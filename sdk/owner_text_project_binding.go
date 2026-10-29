package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// OwnerTextProjectEndpointProof identifies the caller's current server proof.
// It contains public metadata only.
type OwnerTextProjectEndpointProof struct {
	ProofID           string `json:"proofId"`
	PrincipalID       string `json:"principalId"`
	InstallationID    string `json:"installationId"`
	ClaimID           string `json:"claimId"`
	Generation        string `json:"generation"`
	EndpointID        string `json:"endpointId"`
	CredentialID      string `json:"credentialId"`
	EndpointStartedAt string `json:"endpointStartedAt"`
	DescriptorHash    []byte `json:"descriptorHash"`
}

// OwnerTextProjectBindingSnapshot is copied public metadata authenticated for
// one locally proved installation and physical endpoint session.
type OwnerTextProjectBindingSnapshot struct {
	OwnerTextProjectStatus
	InstallationID, ClaimID, ProjectContract, PrincipalID, EndpointID, PolicyHash string
	Generation                                                                    int64
}

type ownerTextInstallationBinding struct {
	installation, claim, contract, endpoint, principal, bearer string
	generation, connection                                     int64
	session                                                    <-chan struct{}
	done                                                       chan struct{}
	aad                                                        map[string]ownerTextProjectProofAAD
	proofs                                                     map[string]OwnerTextProjectEndpointProof
	versions                                                   map[string]string
}

func (c *Client) invalidateOwnerTextBinding() {
	c.ownerTextBindingMu.Lock()
	defer c.ownerTextBindingMu.Unlock()
	c.invalidateOwnerTextBindingLocked()
}
func (c *Client) invalidateOwnerTextBindingLocked() {
	if b := c.ownerTextInstallation; b != nil {
		close(b.done)
		c.ownerTextInstallation = nil
	}
}
func (b *ownerTextInstallationBinding) current(c *Client) bool {
	endpoint, bearer, session, err := c.textServiceEndpointSession()
	return err == nil && endpoint == b.endpoint && bearer == b.bearer && session == b.session && c.principalID.Load() == b.principal && c.connGeneration.Load() == b.connection
}
func (c *Client) retainTextServiceInstallation(p TextServiceInstallationProof, contract, endpoint, bearer, principal string, connection int64, session <-chan struct{}) bool {
	c.ownerTextBindingMu.Lock()
	defer c.ownerTextBindingMu.Unlock()
	if current, credential, done, err := c.textServiceEndpointSession(); err != nil || current != endpoint || credential != bearer || done != session || c.principalID.Load() != principal || c.connGeneration.Load() != connection {
		return false
	}
	if b := c.ownerTextInstallation; b != nil && b.installation == p.InstallationID && b.claim == p.ClaimID && b.generation == p.Generation && b.contract == contract && b.current(c) {
		return true
	}
	c.invalidateOwnerTextBindingLocked()
	b := &ownerTextInstallationBinding{installation: p.InstallationID, claim: p.ClaimID, generation: p.Generation, contract: contract, endpoint: endpoint, bearer: bearer, principal: principal, connection: connection, session: session, done: make(chan struct{}), aad: make(map[string]ownerTextProjectProofAAD), proofs: make(map[string]OwnerTextProjectEndpointProof), versions: make(map[string]string)}
	c.ownerTextInstallation = b
	// Physical disconnects invalidate snapshots even while Client.Done stays open.
	go func() {
		select {
		case <-session:
		case <-b.done:
			return
		}
		c.ownerTextBindingMu.Lock()
		defer c.ownerTextBindingMu.Unlock()
		if c.ownerTextInstallation == b {
			c.invalidateOwnerTextBindingLocked()
		}
	}()
	return true
}
func (c *Client) retainOwnerTextProjectAAD(project string, aad ownerTextProjectProofAAD) {
	c.ownerTextBindingMu.Lock()
	defer c.ownerTextBindingMu.Unlock()
	if b := c.ownerTextInstallation; b != nil && b.current(c) {
		aad.DescriptorHash = append([]byte(nil), aad.DescriptorHash...)
		b.aad[project] = aad
	}
}
func ownerTextCanonicalPositive(s string) bool {
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == s
}

// OwnerTextProjectBinding requires a durable descriptor pin and a successful
// installation proof on this exact endpoint. Ready is deliberately not required:
// a responder may be offline. The returned channel invalidates the snapshot.
func (c *Client) OwnerTextProjectBinding(ctx context.Context, projectID, installationID string) (OwnerTextProjectBindingSnapshot, <-chan struct{}, error) {
	var out OwnerTextProjectBindingSnapshot
	invalid := errors.New("sdk: owner text project binding mismatch")
	if !projectUUID(projectID, false) || !projectUUID(installationID, false) {
		return out, nil, invalid
	}
	c.ownerTextBindingMu.Lock()
	b := c.ownerTextInstallation
	if b == nil || !b.current(c) || b.installation != installationID || b.contract != "owner_text_project_v1" {
		if b != nil && !b.current(c) {
			c.invalidateOwnerTextBindingLocked()
		}
		c.ownerTextBindingMu.Unlock()
		return out, nil, errors.New("sdk: owner text project binding requires a current installation proof")
	}
	c.ownerTextBindingMu.Unlock()
	d, hash, err := c.ownerTextMessageDescriptor(projectID)
	if err != nil {
		c.ownerTextBindingMu.Lock()
		if c.ownerTextInstallation == b {
			c.invalidateOwnerTextBindingLocked()
		}
		c.ownerTextBindingMu.Unlock()
		return out, nil, err
	}
	rest := *c.rest
	rest.cred = func() string { return b.bearer }
	transport := *rest.http
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	rest.http = &transport
	requestCtx, cancel := context.WithCancel(ctx)
	requestDone := make(chan struct{})
	defer func() { close(requestDone); cancel() }()
	go func() {
		select {
		case <-b.session:
			cancel()
		case <-b.done:
			cancel()
		case <-requestDone:
		}
	}()
	var status OwnerTextProjectStatus
	err = rest.do(requestCtx, http.MethodGet, "/owner-text-project-transports/"+projectID+"/status?"+url.Values{"endpointId": {b.endpoint}}.Encode(), nil, &status)
	c.ownerTextBindingMu.Lock()
	defer c.ownerTextBindingMu.Unlock()
	if c.ownerTextInstallation != b || !b.current(c) {
		if c.ownerTextInstallation == b {
			c.invalidateOwnerTextBindingLocked()
		}
		return out, nil, invalid
	}
	valid := false
	defer func() {
		if !valid && c.ownerTextInstallation == b {
			c.invalidateOwnerTextBindingLocked()
		}
	}()
	if err != nil {
		return out, nil, errors.New("sdk: owner text project binding status unavailable")
	}
	if validateOwnerTextProjectStatus(status, projectID, b.principal, installationID) != nil || status.State != "active" || !status.EndpointProved || !ownerTextCanonicalPositive(status.ProjectVersion) || validateOwnerTextProjectDescriptor(status, projectID, b.principal, installationID, c.identityPub, d.PolicyHash, time.Now()) != nil || !bytes.Equal(hash, status.DescriptorHash) {
		return out, nil, invalid
	}
	raw, _ := json.Marshal(d)
	if !bytes.Equal(raw, status.Descriptor) {
		return out, nil, invalid
	}
	p := status.EndpointProof
	if p == nil || !projectUUID(p.ProofID, false) || !projectUUID(p.CredentialID, false) || p.PrincipalID != b.principal || p.InstallationID != installationID || p.ClaimID != b.claim || p.Generation != strconv.FormatInt(b.generation, 10) || p.EndpointID != b.endpoint || !bytes.Equal(p.DescriptorHash, hash) {
		return out, nil, invalid
	}
	started, err := time.Parse("2006-01-02T15:04:05.000000000Z", p.EndpointStartedAt)
	if err != nil || started.IsZero() || started.UTC().Format("2006-01-02T15:04:05.000000000Z") != p.EndpointStartedAt {
		return out, nil, invalid
	}
	if a, ok := b.aad[projectID]; ok && (a.ProjectID != projectID || a.PrincipalID != p.PrincipalID || a.InstallationID != p.InstallationID || a.ClaimID != p.ClaimID || a.Generation != b.generation || a.EndpointID != p.EndpointID || a.CredentialID != p.CredentialID || !a.EndpointStartedAt.Equal(started) || !bytes.Equal(a.DescriptorHash, p.DescriptorHash)) {
		return out, nil, invalid
	}
	if previous, ok := b.proofs[projectID]; ok {
		old, _ := json.Marshal(previous)
		current, _ := json.Marshal(p)
		if !bytes.Equal(old, current) || b.versions[projectID] != status.ProjectVersion {
			return out, nil, invalid
		}
	}
	pinned := *p
	pinned.DescriptorHash = append([]byte(nil), p.DescriptorHash...)
	b.proofs[projectID], b.versions[projectID] = pinned, status.ProjectVersion
	// The JSON round trip gives the caller independent slices and proof pointers.
	copyRaw, _ := json.Marshal(status)
	_ = json.Unmarshal(copyRaw, &out.OwnerTextProjectStatus)
	out.InstallationID, out.ClaimID, out.ProjectContract = b.installation, b.claim, b.contract
	out.PrincipalID, out.EndpointID, out.PolicyHash, out.Generation = b.principal, b.endpoint, d.PolicyHash, b.generation
	valid = true
	return out, b.done, nil
}
