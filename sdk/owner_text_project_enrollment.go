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

const ownerTextProjectProofDomain = "pagnet/owner-text-project/proof/v1"

// OwnerTextProjectStatus is an authenticated enrollment snapshot. Descriptor pins
// trust the server directory on first contact; compare fingerprints separately
// when an independent trust channel is available. Readiness describes current
// enrollment proofs; it does not authorize message transport.
type OwnerTextProjectStatus struct {
	ProjectID        string                       `json:"projectId"`
	NetworkID        string                       `json:"networkId"`
	State            string                       `json:"state"`
	Descriptor       []byte                       `json:"descriptor"`
	DescriptorHash   []byte                       `json:"descriptorHash"`
	KeysPinned       int                          `json:"keysPinned"`
	PrincipalsProved int                          `json:"principalsProved"`
	RosterSize       int                          `json:"rosterSize"`
	EndpointProved   bool                         `json:"endpointProved"`
	Ready            bool                         `json:"ready"`
	Roles            []OwnerTextProjectRoleStatus `json:"roles"`
	BlockedReason    string                       `json:"blockedReason"`
}

type OwnerTextProjectRoleStatus struct {
	Role           string `json:"role"`
	PrincipalID    string `json:"principalId"`
	InstallationID string `json:"installationId"`
	Ready          bool   `json:"ready"`
}

type OwnerTextProjectEnrollment struct {
	Status                OwnerTextProjectStatus
	Pending               bool
	DescriptorFingerprint string
}

// Field order is part of the server's canonical descriptor encoding.
type ownerTextProjectDescriptor struct {
	Version       int                         `json:"version"`
	Suite         string                      `json:"suite"`
	Domain        string                      `json:"domain"`
	ProjectID     string                      `json:"projectId"`
	NetworkID     string                      `json:"networkId"`
	OwnerTenantID string                      `json:"ownerTenantId"`
	OwnerUserID   string                      `json:"ownerUserId"`
	PolicyHash    string                      `json:"policyHash"`
	Roster        []ownerTextProjectPrincipal `json:"roster"`
	Permissions   []string                    `json:"permissions"`
	Limits        SharingPairLimits           `json:"limits"`
	ExpiresAt     string                      `json:"expiresAt"`
}
type ownerTextProjectPrincipal struct {
	Role           string `json:"role"`
	PrincipalID    string `json:"principalId"`
	InstallationID string `json:"installationId"`
	PublicKey      string `json:"publicKey"`
}
type ownerTextProjectChallenge struct {
	ChallengeID    string    `json:"challengeId"`
	DescriptorHash []byte    `json:"descriptorHash"`
	AAD            []byte    `json:"aad"`
	Enc            []byte    `json:"enc"`
	Ciphertext     []byte    `json:"ciphertext"`
	ExpiresAt      time.Time `json:"expiresAt"`
}
type ownerTextProjectProofAAD struct {
	Domain            string    `json:"domain"`
	ProjectID         string    `json:"projectId"`
	DescriptorHash    []byte    `json:"descriptorHash"`
	PrincipalID       string    `json:"principalId"`
	InstallationID    string    `json:"installationId"`
	ClaimID           string    `json:"claimId"`
	Generation        int64     `json:"generation"`
	EndpointID        string    `json:"endpointId"`
	CredentialID      string    `json:"credentialId"`
	EndpointStartedAt time.Time `json:"endpointStartedAt"`
	ChallengeID       string    `json:"challengeId"`
}

func (c *Client) ownerTextProjectEnrollmentConnected() error {
	cred, _ := c.credential.Load().(string)
	if !c.connected.Load() || c.endpointID.Load() == "" || c.principalID.Load() == "" || !strings.HasPrefix(cred, "pgn_epd_v1_") {
		return errors.New("sdk: project enrollment requires a connected endpoint credential")
	}
	return nil
}

func (c *Client) ListOwnerTextProjects(ctx context.Context) ([]OwnerTextProjectStatus, error) {
	if err := c.ownerTextProjectEnrollmentConnected(); err != nil {
		return nil, err
	}
	var out []OwnerTextProjectStatus
	query := url.Values{"endpointId": {c.endpointID.Load()}}
	seen := make(map[string]bool)
	for {
		var page []OwnerTextProjectStatus
		var headers http.Header
		if err := c.rest.doWithHeaders(ctx, http.MethodGet, "/owner-text-project-transports?"+query.Encode(), nil, &page, &headers); err != nil {
			return nil, err
		}
		out = append(out, page...)
		next := headers.Get("X-Next-Cursor")
		if next == "" {
			return out, nil
		}
		if seen[next] {
			return nil, errors.New("sdk: repeated owner text project cursor")
		}
		seen[next] = true
		query.Set("cursor", next)
	}
}

func (c *Client) OwnerTextProjectStatus(ctx context.Context, projectID string) (OwnerTextProjectStatus, error) {
	var out OwnerTextProjectStatus
	if !projectUUID(projectID, false) {
		return out, errors.New("sdk: invalid owner text project ID")
	}
	if err := c.ownerTextProjectEnrollmentConnected(); err != nil {
		return out, err
	}
	err := c.rest.do(ctx, http.MethodGet, "/owner-text-project-transports/"+projectID+"/status?"+url.Values{"endpointId": {c.endpointID.Load()}}.Encode(), nil, &out)
	if err == nil && out.ProjectID != projectID {
		err = errors.New("sdk: project status binding mismatch")
	}
	return out, err
}

// EnrollOwnerTextProject advances enrollment once, without background polling.
// Repeating it after reconnect or an uncertain proof response is safe.
func (c *Client) EnrollOwnerTextProject(ctx context.Context, projectID, installationID string) (OwnerTextProjectEnrollment, error) {
	return c.EnrollOwnerTextProjectWithPolicyHash(ctx, projectID, installationID, "")
}

// EnrollOwnerTextProjectWithPolicyHash additionally requires an independently
// obtained policy hash. A blank hash uses the directory on first contact.
func (c *Client) EnrollOwnerTextProjectWithPolicyHash(ctx context.Context, projectID, installationID, policyHash string) (OwnerTextProjectEnrollment, error) {
	var result OwnerTextProjectEnrollment
	if !projectUUID(projectID, false) || !projectUUID(installationID, false) {
		return result, errors.New("sdk: invalid owner text project ID")
	}
	if err := c.ownerTextProjectEnrollmentConnected(); err != nil {
		return result, err
	}
	principal, endpoint, connection := c.principalID.Load(), c.endpointID.Load(), c.connGeneration.Load()
	sameConnection := func() bool {
		return c.connected.Load() && c.principalID.Load() == principal && c.endpointID.Load() == endpoint && c.connGeneration.Load() == connection
	}
	base := "/owner-text-project-transports/" + projectID
	request := map[string]string{"endpointId": endpoint}
	var status OwnerTextProjectStatus
	getStatus := func() error {
		if err := c.rest.do(ctx, http.MethodGet, base+"/status?"+url.Values{"endpointId": {endpoint}}.Encode(), nil, &status); err != nil {
			return err
		}
		if !sameConnection() {
			return errors.New("sdk: owner text endpoint connection changed")
		}
		return validateOwnerTextProjectStatus(status, projectID, principal, installationID)
	}
	if err := getStatus(); err != nil {
		return result, err
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
		if err := validateOwnerTextProjectStatus(status, projectID, principal, installationID); err != nil {
			return err
		}
		if err := validateOwnerTextProjectDescriptor(status, projectID, principal, installationID, c.identityPub, policyHash, time.Now()); err != nil {
			return err
		}
		return c.kr.pinOwnerTextProjectDescriptor(principal, projectID, status.Descriptor)
	}
	if err := validate(); err != nil {
		return result, err
	}
	result.DescriptorFingerprint = hex.EncodeToString(status.DescriptorHash)
	if !status.EndpointProved {
		var challenge ownerTextProjectChallenge
		if err := c.rest.do(ctx, http.MethodPost, base+"/challenge", request, &challenge); err != nil {
			return result, err
		}
		var aad ownerTextProjectProofAAD
		if json.Unmarshal(challenge.AAD, &aad) != nil {
			return result, errors.New("sdk: invalid project challenge AAD")
		}
		canonical, _ := json.Marshal(aad)
		if !bytes.Equal(canonical, challenge.AAD) || aad.Domain != ownerTextProjectProofDomain || aad.ProjectID != projectID || !bytes.Equal(aad.DescriptorHash, status.DescriptorHash) || !bytes.Equal(challenge.DescriptorHash, status.DescriptorHash) || aad.PrincipalID != principal || aad.InstallationID != installationID || !projectUUID(aad.ClaimID, false) || aad.Generation < 1 || aad.EndpointStartedAt.IsZero() || aad.EndpointID != endpoint || !projectUUID(aad.CredentialID, false) || !projectUUID(challenge.ChallengeID, false) || aad.ChallengeID != challenge.ChallengeID || !challenge.ExpiresAt.After(time.Now()) || len(challenge.Enc) != 32 || len(challenge.Ciphertext) != 48 {
			return result, errors.New("sdk: project challenge binding mismatch")
		}
		response, err := e2ee.HPKEUnwrap(c.identityPriv, challenge.Enc, []byte(ownerTextProjectProofDomain), challenge.AAD, challenge.Ciphertext)
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
	result.Status, result.Pending = status, !status.Ready || !status.EndpointProved
	return result, nil
}

func validateOwnerTextProjectDescriptor(s OwnerTextProjectStatus, project, principal, installation string, public []byte, policyHash string, now time.Time) error {
	invalid := errors.New("sdk: invalid owner text project descriptor")
	var d ownerTextProjectDescriptor
	if len(s.Descriptor) == 0 || len(s.Descriptor) > 65536 || json.Unmarshal(s.Descriptor, &d) != nil {
		return invalid
	}
	canonical, _ := json.Marshal(d)
	hash := sha256.Sum256(s.Descriptor)
	expiry, err := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if !bytes.Equal(canonical, s.Descriptor) || !bytes.Equal(hash[:], s.DescriptorHash) || d.Version != 1 || d.Domain != ownerTextProjectProofDomain || d.Suite != "X25519-HKDF-SHA256-AES-256-GCM" || s.ProjectID != project || d.ProjectID != project || d.NetworkID != s.NetworkID || !projectUUID(d.NetworkID, false) || !projectUUID(d.OwnerTenantID, false) || !projectUUID(d.OwnerUserID, false) || d.PolicyHash == "" || (policyHash != "" && d.PolicyHash != policyHash) || err != nil || expiry.UTC().Format(time.RFC3339Nano) != d.ExpiresAt || !expiry.After(now) || !d.Limits.valid() || d.Limits.MaxMessagesPerDay < 2 || d.Limits.MaxWireBytesPerDay < 2*d.Limits.MaxMessageWireBytes || d.Limits.MaxTurnsPerThread != 2 || len(d.Permissions) != 2 || d.Permissions[0] != "discover" || d.Permissions[1] != "communicate" || len(d.Roster) != 2 || s.RosterSize != 2 || len(s.Roles) != 2 {
		return invalid
	}
	found := false
	for i, role := range []string{"sender", "responder"} {
		member := d.Roster[i]
		key, err := base64.StdEncoding.DecodeString(member.PublicKey)
		status := s.Roles[i]
		if member.Role != role || !projectUUID(member.PrincipalID, false) || !projectUUID(member.InstallationID, false) || err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != member.PublicKey || status.Role != role || status.PrincipalID != member.PrincipalID || status.InstallationID != member.InstallationID {
			return invalid
		}
		if member.PrincipalID == principal {
			if member.InstallationID != installation || !bytes.Equal(key, public) {
				return invalid
			}
			found = true
		}
	}
	if !found || d.Roster[0].PrincipalID == d.Roster[1].PrincipalID || d.Roster[0].InstallationID == d.Roster[1].InstallationID {
		return invalid
	}
	return nil
}

func (k *keyring) pinOwnerTextProjectDescriptor(principal, project string, descriptor []byte) error {
	if !projectUUID(principal, false) || !projectUUID(project, false) {
		return errors.New("sdk: invalid owner text project pin identity")
	}
	parent := filepath.Join(k.root, principal)
	dir := filepath.Join(parent, "owner-text-projects")
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
			return errors.New("sdk: owner text project pin directory is not private")
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
			return errors.New("sdk: owner text project descriptor changed")
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
			return errors.New("sdk: owner text project descriptor changed")
		}
	} else if err != nil {
		return err
	}
	return syncPin()
}

func validateOwnerTextProjectStatus(s OwnerTextProjectStatus, project, principal, installation string) error {
	invalid := errors.New("sdk: invalid owner text project status")
	if s.ProjectID != project || !projectUUID(s.NetworkID, false) || (s.State != "enrolling" && s.State != "active") || s.RosterSize != 2 || len(s.Roles) != 2 || s.KeysPinned < 0 || s.KeysPinned > 2 || s.PrincipalsProved < 0 || s.PrincipalsProved > 2 {
		return invalid
	}
	found, proved := false, 0
	for i, role := range []string{"sender", "responder"} {
		r := s.Roles[i]
		if r.Role != role || !projectUUID(r.PrincipalID, false) || !projectUUID(r.InstallationID, false) {
			return invalid
		}
		if r.Ready {
			proved++
		}
		if r.PrincipalID == principal {
			if r.InstallationID != installation || s.EndpointProved != r.Ready {
				return invalid
			}
			found = true
		}
	}
	if !found || s.Roles[0].PrincipalID == s.Roles[1].PrincipalID || s.Roles[0].InstallationID == s.Roles[1].InstallationID || proved != s.PrincipalsProved || s.Ready != (s.State == "active" && proved == 2) {
		return invalid
	}
	return nil
}
