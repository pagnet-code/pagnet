package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

const sharingProjectProofDomain = "pagnet/sdk-project/proof/v2"

// SharingProjectStatus is an authenticated enrollment snapshot. Descriptor pins
// trust the server directory on first contact; compare fingerprints separately
// when an independent trust channel is available.
type SharingProjectStatus struct {
	ProjectID        string `json:"projectId"`
	NetworkID        string `json:"networkId"`
	State            string `json:"state"`
	Descriptor       []byte `json:"descriptor"`
	DescriptorHash   []byte `json:"descriptorHash"`
	KeysPinned       int    `json:"keysPinned"`
	PrincipalsProved int    `json:"principalsProved"`
	RosterSize       int    `json:"rosterSize"`
	EndpointProved   bool   `json:"endpointProved"`
}

type SharingProjectEnrollment struct {
	Status                SharingProjectStatus
	Pending               bool
	DescriptorFingerprint string
}

// Field order is part of the server's canonical descriptor encoding.
type sharingProjectDescriptor struct {
	Version           int                       `json:"version"`
	Suite             string                    `json:"suite"`
	ProjectID         string                    `json:"projectId"`
	NetworkID         string                    `json:"networkId"`
	PolicyHash        string                    `json:"policyHash"`
	IssuerTenantID    string                    `json:"issuerTenantId"`
	IssuerUserID      string                    `json:"issuerUserId"`
	RecipientTenantID string                    `json:"recipientTenantId"`
	RecipientUserID   string                    `json:"recipientUserId"`
	Roster            []sharingProjectPrincipal `json:"roster"`
	Permissions       []string                  `json:"permissions"`
	Limits            SharingPairLimits         `json:"limits"`
	ExpiresAt         string                    `json:"expiresAt"`
}
type sharingProjectPrincipal struct {
	PrincipalID string `json:"principalId"`
	PublicKey   string `json:"publicKey"`
}
type sharingProjectChallenge struct {
	ChallengeID    string    `json:"challengeId"`
	DescriptorHash []byte    `json:"descriptorHash"`
	AAD            []byte    `json:"aad"`
	Enc            []byte    `json:"enc"`
	Ciphertext     []byte    `json:"ciphertext"`
	ExpiresAt      time.Time `json:"expiresAt"`
}
type sharingProjectProofAAD struct {
	Domain         string `json:"domain"`
	ProjectID      string `json:"projectId"`
	DescriptorHash []byte `json:"descriptorHash"`
	PrincipalID    string `json:"principalId"`
	EndpointID     string `json:"endpointId"`
	CredentialID   string `json:"credentialId"`
	ChallengeID    string `json:"challengeId"`
}

func (c *Client) projectEnrollmentConnected() error {
	cred, _ := c.credential.Load().(string)
	if !c.connected.Load() || c.endpointID.Load() == "" || c.principalID.Load() == "" || !strings.HasPrefix(cred, "pgn_epd_v1_") {
		return errors.New("sdk: project enrollment requires a connected endpoint credential")
	}
	return nil
}

func (c *Client) ListSharingProjects(ctx context.Context) ([]SharingProjectStatus, error) {
	if err := c.projectEnrollmentConnected(); err != nil {
		return nil, err
	}
	var out []SharingProjectStatus
	query := url.Values{"endpointId": {c.endpointID.Load()}}
	seen := make(map[string]bool)
	for {
		var page []SharingProjectStatus
		var headers http.Header
		if err := c.rest.doWithHeaders(ctx, http.MethodGet, "/sharing-project-transports?"+query.Encode(), nil, &page, &headers); err != nil {
			return nil, err
		}
		out = append(out, page...)
		next := headers.Get("X-Next-Cursor")
		if next == "" {
			return out, nil
		}
		if seen[next] {
			return nil, errors.New("sdk: repeated sharing project cursor")
		}
		seen[next] = true
		query.Set("cursor", next)
	}
}

func (c *Client) SharingProjectStatus(ctx context.Context, projectID string) (SharingProjectStatus, error) {
	var out SharingProjectStatus
	if !validPairPathID(projectID) {
		return out, errors.New("sdk: invalid sharing project ID")
	}
	if err := c.projectEnrollmentConnected(); err != nil {
		return out, err
	}
	err := c.rest.do(ctx, http.MethodGet, "/sharing-project-transports/"+projectID+"/status?"+url.Values{"endpointId": {c.endpointID.Load()}}.Encode(), nil, &out)
	if err == nil && out.ProjectID != projectID {
		err = errors.New("sdk: project status binding mismatch")
	}
	return out, err
}

// EnrollSharingProject advances enrollment once, without background polling.
// Repeating it after reconnect or an uncertain proof response is safe.
func (c *Client) EnrollSharingProject(ctx context.Context, projectID string) (SharingProjectEnrollment, error) {
	return c.EnrollSharingProjectWithPolicyHash(ctx, projectID, "")
}

// EnrollSharingProjectWithPolicyHash additionally requires an independently
// obtained policy hash. A blank hash uses the directory on first contact.
func (c *Client) EnrollSharingProjectWithPolicyHash(ctx context.Context, projectID, policyHash string) (SharingProjectEnrollment, error) {
	var result SharingProjectEnrollment
	if !validPairPathID(projectID) {
		return result, errors.New("sdk: invalid sharing project ID")
	}
	if err := c.projectEnrollmentConnected(); err != nil {
		return result, err
	}
	principal, endpoint, connection := c.principalID.Load(), c.endpointID.Load(), c.connGeneration.Load()
	sameConnection := func() bool {
		return c.connected.Load() && c.principalID.Load() == principal && c.endpointID.Load() == endpoint && c.connGeneration.Load() == connection
	}
	base := "/sharing-project-transports/" + projectID
	request := map[string]string{"endpointId": endpoint}
	var status SharingProjectStatus
	getStatus := func() error {
		return c.rest.do(ctx, http.MethodGet, base+"/status?"+url.Values{"endpointId": {endpoint}}.Encode(), nil, &status)
	}
	if err := getStatus(); err != nil {
		return result, err
	}
	// Legacy projects cannot enroll or authorize message transport.
	if status.State == "accepted_blocked" {
		result.Status, result.Pending = status, true
		return result, nil
	}
	if err := c.rest.do(ctx, http.MethodPost, base+"/pin", request, &status); err != nil {
		return result, err
	}
	if err := getStatus(); err != nil {
		return result, err
	}
	result.Status, result.Pending = status, true
	if len(status.Descriptor) == 0 {
		return result, nil
	} // Waiting for peer pins.
	validate := func() error {
		if !sameConnection() {
			return errors.New("sdk: project endpoint connection changed")
		}
		if err := validateSharingProjectDescriptor(status, projectID, principal, c.identityPub, policyHash, time.Now()); err != nil {
			return err
		}
		return c.kr.pinSharingProjectDescriptor(principal, projectID, status.Descriptor)
	}
	if err := validate(); err != nil {
		return result, err
	}
	result.DescriptorFingerprint = hex.EncodeToString(status.DescriptorHash)
	if !status.EndpointProved {
		var challenge sharingProjectChallenge
		if err := c.rest.do(ctx, http.MethodPost, base+"/challenge", request, &challenge); err != nil {
			return result, err
		}
		var aad sharingProjectProofAAD
		if json.Unmarshal(challenge.AAD, &aad) != nil {
			return result, errors.New("sdk: invalid project challenge AAD")
		}
		canonical, _ := json.Marshal(aad)
		if !bytes.Equal(canonical, challenge.AAD) || aad.Domain != sharingProjectProofDomain || aad.ProjectID != projectID || !bytes.Equal(aad.DescriptorHash, status.DescriptorHash) || !bytes.Equal(challenge.DescriptorHash, status.DescriptorHash) || aad.PrincipalID != principal || aad.EndpointID != endpoint || !validPairPathID(aad.CredentialID) || !validPairPathID(challenge.ChallengeID) || aad.ChallengeID != challenge.ChallengeID || !challenge.ExpiresAt.After(time.Now()) || len(challenge.Enc) != 32 || len(challenge.Ciphertext) != 48 {
			return result, errors.New("sdk: project challenge binding mismatch")
		}
		response, err := e2ee.HPKEUnwrap(c.identityPriv, challenge.Enc, []byte(sharingProjectProofDomain), challenge.AAD, challenge.Ciphertext)
		if err != nil {
			return result, err
		}
		if len(response) != 32 || !sameConnection() {
			return result, errors.New("sdk: invalid project proof response or changed connection")
		}
		err = c.rest.do(ctx, http.MethodPost, base+"/prove", map[string]any{"endpointId": endpoint, "challengeId": challenge.ChallengeID, "response": response}, &status)
		// Recover a committed proof whose response was lost; the next explicit call
		// obtains a fresh challenge if the server did not commit it.
		if err != nil {
			if getStatus() != nil || !status.EndpointProved {
				return result, err
			}
		}
	}
	if err := getStatus(); err != nil {
		return result, err
	}
	if err := validate(); err != nil {
		return result, err
	}
	result.Status, result.Pending = status, status.State != "active" || !status.EndpointProved
	return result, nil
}

func validateSharingProjectDescriptor(s SharingProjectStatus, project, principal string, public []byte, policyHash string, now time.Time) error {
	invalid := errors.New("sdk: invalid sharing project descriptor")
	var d sharingProjectDescriptor
	if len(s.Descriptor) == 0 || len(s.Descriptor) > 65536 || json.Unmarshal(s.Descriptor, &d) != nil {
		return invalid
	}
	canonical, _ := json.Marshal(d)
	hash := sha256.Sum256(s.Descriptor)
	expiry, err := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if !bytes.Equal(canonical, s.Descriptor) || !bytes.Equal(hash[:], s.DescriptorHash) || d.Version != 2 || d.Suite != "X25519-HKDF-SHA256-AES-256-GCM" || s.ProjectID != project || d.ProjectID != project || d.NetworkID != s.NetworkID || !validPairPathID(d.NetworkID) || d.PolicyHash == "" || (policyHash != "" && d.PolicyHash != policyHash) || err != nil || expiry.UTC().Format(time.RFC3339Nano) != d.ExpiresAt || !expiry.After(now) || !d.Limits.valid() || len(d.Permissions) != 2 || d.Permissions[0] != "discover" || d.Permissions[1] != "communicate" || len(d.Roster) < 2 || len(d.Roster) != s.RosterSize {
		return invalid
	}
	for _, id := range []string{d.IssuerTenantID, d.IssuerUserID, d.RecipientTenantID, d.RecipientUserID} {
		if !validPairPathID(id) {
			return invalid
		}
	}
	found := false
	for i, member := range d.Roster {
		key, err := base64.StdEncoding.DecodeString(member.PublicKey)
		if !validPairPathID(member.PrincipalID) || (i > 0 && d.Roster[i-1].PrincipalID >= member.PrincipalID) || err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != member.PublicKey {
			return invalid
		}
		if member.PrincipalID == principal {
			if !bytes.Equal(key, public) {
				return invalid
			}
			found = true
		}
	}
	if !found {
		return invalid
	}
	return nil
}

func (k *keyring) pinSharingProjectDescriptor(principal, project string, descriptor []byte) error {
	if !projectUUID(principal, false) || !projectUUID(project, false) {
		return errors.New("sdk: invalid sharing project pin identity")
	}
	parent := filepath.Join(k.root, principal)
	dir := filepath.Join(parent, "sharing-projects")
	// Persist each directory entry separately, including directories left by a
	// previous interrupted attempt. Refuse symlinks or nonprivate directories.
	for _, directory := range []string{k.root, parent, dir} {
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			return errors.New("sdk: sharing project pin directory is not private")
		}
		if err := k.syncPendingPairDir(filepath.Dir(directory)); err != nil {
			return err
		}
	}
	syncPin := func() error {
		if err := k.syncPendingPairDir(dir); err != nil {
			return err
		}
		return k.syncPendingPairDir(parent)
	}
	path := filepath.Join(dir, project+".json")
	previous, err := readPrivatePairFile(path)
	if err == nil {
		if !bytes.Equal(previous, descriptor) {
			return errors.New("sdk: sharing project descriptor changed")
		}
		return syncPin()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Publish without replacement: a concurrent process must never overwrite a
	// different first-contact pin. The complete file is durable before linking.
	tmp, err := os.CreateTemp(dir, ".descriptor-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(descriptor); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(tmp.Name(), path); errors.Is(err, os.ErrExist) {
		previous, readErr := readPrivatePairFile(path)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(previous, descriptor) {
			return errors.New("sdk: sharing project descriptor changed")
		}
	} else if err != nil {
		return err
	}
	return syncPin()
}
