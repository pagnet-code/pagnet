package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

const ownerTextInstallation = "40000000-0000-4000-8000-000000000004"
const ownerTextSecondInstallation = "50000000-0000-4000-8000-000000000005"
const ownerTextClaim = "60000000-0000-4000-8000-000000000006"
const ownerTextChallenge = "70000000-0000-4000-8000-000000000007"
const ownerTextCredential = "80000000-0000-4000-8000-000000000008"

type ownerTextEnrollmentFixture struct {
	mu                                  sync.Mutex
	status                              OwnerTextProjectStatus
	descriptor                          ownerTextProjectDescriptor
	public                              []byte
	response                            []byte
	challenges, proofs, lists, requests int
	lostProof                           bool
	mutateAAD                           func(*ownerTextProjectProofAAD)
	mutateChallenge                     func(*ownerTextProjectChallenge)
}

func newOwnerTextEnrollmentFixture(t *testing.T) (*ownerTextEnrollmentFixture, *Client) {
	t.Helper()
	_, c := newProjectEnrollmentFixture(t)
	f := &ownerTextEnrollmentFixture{public: c.identityPub, response: bytes.Repeat([]byte{9}, 32)}
	f.descriptor = ownerTextProjectDescriptor{Version: 1, Suite: "X25519-HKDF-SHA256-AES-256-GCM", Domain: ownerTextProjectProofDomain, ProjectID: enrollmentProjectID, NetworkID: enrollmentSecondID, OwnerTenantID: ownerTextClaim, OwnerUserID: ownerTextCredential, PolicyHash: "policy", Roster: []ownerTextProjectPrincipal{{"sender", enrollmentPrincipalID, ownerTextInstallation, base64.StdEncoding.EncodeToString(c.identityPub)}, {"responder", enrollmentSecondID, ownerTextSecondInstallation, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))}}, Permissions: []string{"discover", "communicate"}, Limits: SharingPairLimits{1024, 1, 2, 2048, 1, 2}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	f.status = OwnerTextProjectStatus{ProjectID: enrollmentProjectID, NetworkID: enrollmentSecondID, State: "enrolling", KeysPinned: 2, RosterSize: 2, PrincipalsProved: 1, Roles: []OwnerTextProjectRoleStatus{{"sender", enrollmentPrincipalID, ownerTextInstallation, false}, {"responder", enrollmentSecondID, ownerTextSecondInstallation, true}}, BlockedReason: "project_transport_unavailable"}
	f.refresh()
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	c.rest = newRestClient(server.URL, "test", func() string { return "pgn_epd_v1_test" })
	c.closeCh = make(chan struct{})
	return f, c
}
func (f *ownerTextEnrollmentFixture) refresh() {
	f.status.Descriptor, _ = json.Marshal(f.descriptor)
	h := sha256.Sum256(f.status.Descriptor)
	f.status.DescriptorHash = h[:]
}
func (f *ownerTextEnrollmentFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	base := "/api/v1/owner-text-project-transports"
	if !strings.HasPrefix(r.URL.Path, base) {
		http.Error(w, "wrong namespace", 400)
		return
	}
	if r.Method == http.MethodGet && r.URL.Query().Get("endpointId") != "endpoint" {
		http.Error(w, "missing endpoint", 400)
		return
	}
	var req struct {
		EndpointID  string `json:"endpointId"`
		ChallengeID string `json:"challengeId"`
		Response    []byte `json:"response"`
	}
	if r.Method == http.MethodPost && (json.NewDecoder(r.Body).Decode(&req) != nil || req.EndpointID != "endpoint") {
		http.Error(w, "bad endpoint", 400)
		return
	}
	switch {
	case r.URL.Path == base:
		f.lists++
		write([]OwnerTextProjectStatus{f.status})
	case strings.HasSuffix(r.URL.Path, "/status"), strings.HasSuffix(r.URL.Path, "/pin"):
		write(f.status)
	case strings.HasSuffix(r.URL.Path, "/challenge"):
		f.challenges++
		aad := ownerTextProjectProofAAD{ownerTextProjectProofDomain, enrollmentProjectID, f.status.DescriptorHash, enrollmentPrincipalID, ownerTextInstallation, ownerTextClaim, 2, "endpoint", ownerTextCredential, time.Now().Add(-time.Minute).UTC(), ownerTextChallenge}
		if f.mutateAAD != nil {
			f.mutateAAD(&aad)
		}
		raw, _ := json.Marshal(aad)
		enc, ct, err := e2ee.HPKEWrap(f.public, []byte(ownerTextProjectProofDomain), raw, f.response)
		if err != nil {
			panic(err)
		}
		challenge := ownerTextProjectChallenge{ownerTextChallenge, f.status.DescriptorHash, raw, enc, ct, time.Now().Add(time.Minute)}
		if f.mutateChallenge != nil {
			f.mutateChallenge(&challenge)
		}
		write(challenge)
	case strings.HasSuffix(r.URL.Path, "/prove"):
		if req.ChallengeID != ownerTextChallenge || !bytes.Equal(req.Response, f.response) {
			http.Error(w, "bad proof", 400)
			return
		}
		f.proofs++
		f.status.EndpointProved = true
		f.status.PrincipalsProved = 2
		f.status.Roles[0].Ready = true
		f.status.Ready = true
		f.status.State = "active"
		if f.lostProof {
			http.Error(w, "lost response", 503)
			return
		}
		write(f.status)
	default:
		http.NotFound(w, r)
	}
}
func TestOwnerTextProjectEnrollmentReproofAndDurablePin(t *testing.T) {
	f, c := newOwnerTextEnrollmentFixture(t)
	f.lostProof = true
	result, err := c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation)
	if err != nil || result.Pending || result.DescriptorFingerprint == "" {
		t.Fatalf("enroll: %+v %v", result, err)
	}
	path := filepath.Join(c.kr.root, enrollmentPrincipalID, "owner-text-projects", enrollmentProjectID+".json")
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, f.status.Descriptor) {
		t.Fatalf("durable pin: %v", err)
	}
	if _, err = os.Stat(filepath.Join(c.kr.root, enrollmentPrincipalID, "sharing-projects", enrollmentProjectID+".json")); !os.IsNotExist(err) {
		t.Fatal("cross-domain pin")
	}
	f.mu.Lock()
	f.status.EndpointProved = false
	f.status.PrincipalsProved = 1
	f.status.Roles[0].Ready = false
	f.status.Ready = false
	f.mu.Unlock()
	c.connGeneration.Add(1)
	result, err = c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation)
	if err != nil || result.Pending || f.proofs != 2 {
		t.Fatalf("reproof: %+v %v proofs=%d", result, err, f.proofs)
	}
	restarted, err := newKeyring(filepath.Dir(c.kr.root))
	if err != nil {
		t.Fatal(err)
	}
	c.kr = restarted
	f.mu.Lock()
	f.descriptor.PolicyHash = "changed"
	f.refresh()
	f.mu.Unlock()
	if _, err = c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation); err == nil {
		t.Fatal("changed descriptor accepted after restart")
	}
}
func TestOwnerTextProjectRejectsDescriptorAndInstallationChanges(t *testing.T) {
	for _, kind := range []string{"domain", "roles", "installation", "key", "duplicate", "canonical", "hash", "policy", "wrong installation"} {
		t.Run(kind, func(t *testing.T) {
			f, c := newOwnerTextEnrollmentFixture(t)
			installation := ownerTextInstallation
			switch kind {
			case "domain":
				f.descriptor.Domain = sharingProjectProofDomain
			case "roles":
				f.descriptor.Roster[0].Role = "responder"
			case "installation":
				f.descriptor.Roster[0].InstallationID = ownerTextSecondInstallation
			case "key":
				f.descriptor.Roster[0].PublicKey = f.descriptor.Roster[1].PublicKey
			case "duplicate":
				f.descriptor.Roster[1].PrincipalID = enrollmentPrincipalID
			case "policy":
				f.descriptor.PolicyHash = "other"
			case "wrong installation":
				installation = ownerTextSecondInstallation
			}
			f.refresh()
			if kind == "canonical" {
				f.status.Descriptor = append(f.status.Descriptor, ' ')
				h := sha256.Sum256(f.status.Descriptor)
				f.status.DescriptorHash = h[:]
			}
			if kind == "hash" {
				f.status.DescriptorHash = make([]byte, 32)
			}
			if _, err := c.EnrollOwnerTextProjectWithPolicyHash(context.Background(), enrollmentProjectID, installation, "policy"); err == nil {
				t.Fatal("accepted invalid descriptor")
			}
			if f.proofs != 0 {
				t.Fatal("proved rejected descriptor")
			}
		})
	}
}
func TestOwnerTextProjectChallengeBindings(t *testing.T) {
	cases := map[string]func(*ownerTextProjectProofAAD){"domain": func(a *ownerTextProjectProofAAD) { a.Domain = sharingProjectProofDomain }, "installation": func(a *ownerTextProjectProofAAD) { a.InstallationID = ownerTextSecondInstallation }, "generation": func(a *ownerTextProjectProofAAD) { a.Generation = 0 }, "claim": func(a *ownerTextProjectProofAAD) { a.ClaimID = "" }, "session": func(a *ownerTextProjectProofAAD) { a.EndpointStartedAt = time.Time{} }, "principal": func(a *ownerTextProjectProofAAD) { a.PrincipalID = enrollmentSecondID }, "endpoint": func(a *ownerTextProjectProofAAD) { a.EndpointID = "other" }, "hash": func(a *ownerTextProjectProofAAD) { a.DescriptorHash = nil }, "challenge": func(a *ownerTextProjectProofAAD) { a.ChallengeID = ownerTextClaim }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f, c := newOwnerTextEnrollmentFixture(t)
			f.mutateAAD = mutate
			if _, err := c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation); err == nil {
				t.Fatal("bad challenge accepted")
			}
			if f.proofs != 0 {
				t.Fatal("sent bad proof")
			}
		})
	}
	for _, kind := range []string{"expired", "ciphertext", "noncanonical", "connection"} {
		t.Run(kind, func(t *testing.T) {
			f, c := newOwnerTextEnrollmentFixture(t)
			f.mutateChallenge = func(ch *ownerTextProjectChallenge) {
				switch kind {
				case "expired":
					ch.ExpiresAt = time.Now().Add(-time.Second)
				case "ciphertext":
					ch.Ciphertext[0] ^= 1
				case "noncanonical":
					ch.AAD = append(ch.AAD, ' ')
				case "connection":
					c.connGeneration.Add(1)
				}
			}
			if _, err := c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation); err == nil {
				t.Fatal("bad challenge accepted")
			}
			if f.proofs != 0 {
				t.Fatal("sent bad proof")
			}
		})
	}
}

func TestOwnerTextProjectCoordinatorReconnectWakeAndIdle(t *testing.T) {
	f, c := newOwnerTextEnrollmentFixture(t)
	defer func() { c.stopSharingCoordinator(); close(c.closeCh); c.wg.Wait() }()
	ready := make(chan string, 8)
	c.OnOwnerTextProjectReady(func(project string) { ready <- project })
	if err := c.EnableOwnerTextProjects(ownerTextInstallation); err != nil {
		t.Fatal(err)
	}
	waitReady := func() {
		t.Helper()
		select {
		case project := <-ready:
			if project != enrollmentProjectID {
				t.Fatal(project)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("missing ready")
		}
	}
	waitReady()
	// Allow registration's coalesced kick to complete before measuring idle.
	c.sharingMu.Lock()
	s := c.sharingCoordinator
	c.sharingMu.Unlock()
	deadline := time.Now().Add(time.Second)
	for {
		c.sharingMu.Lock()
		full := s.full
		c.sharingMu.Unlock()
		if !full {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pending full scan")
		}
		time.Sleep(time.Millisecond)
	}
	f.mu.Lock()
	requests := f.requests
	f.mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	f.mu.Lock()
	if f.requests != requests {
		t.Errorf("idle requests: %d -> %d", requests, f.requests)
	}
	f.mu.Unlock()
	c.sharingPairDisconnected(c.connGeneration.Load())
	f.mu.Lock()
	f.status.EndpointProved = false
	f.status.PrincipalsProved = 1
	f.status.Roles[0].Ready = false
	f.status.Ready = false
	f.mu.Unlock()
	c.connGeneration.Add(1)
	c.sharingPairLive()
	waitReady()
	// A claim restart on the same endpoint also needs a fresh proof.
	f.mu.Lock()
	f.status.EndpointProved = false
	f.status.PrincipalsProved = 1
	f.status.Roles[0].Ready = false
	f.status.Ready = false
	f.mu.Unlock()
	c.WakeOwnerTextProjects()
	waitReady()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.proofs != 3 || f.lists < 3 {
		t.Fatalf("proofs=%d lists=%d", f.proofs, f.lists)
	}
}

func TestOwnerTextProjectListPaginationAndPending(t *testing.T) {
	f, c := newOwnerTextEnrollmentFixture(t)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/owner-text-project-transports" || r.URL.Query().Get("endpointId") != "endpoint" {
			t.Error("wrong list binding")
		}
		calls++
		if calls == 1 {
			w.Header().Set("X-Next-Cursor", "opaque")
		} else if r.URL.Query().Get("cursor") != "opaque" {
			t.Error("missing cursor")
		}
		_ = json.NewEncoder(w).Encode([]OwnerTextProjectStatus{f.status})
	}))
	defer server.Close()
	rest := c.rest
	c.rest = newRestClient(server.URL, "test", func() string { return "pgn_epd_v1_test" })
	statuses, err := c.ListOwnerTextProjects(context.Background())
	if err != nil || len(statuses) != 2 || calls != 2 {
		t.Fatalf("pagination: %d %d %v", len(statuses), calls, err)
	}
	c.rest = rest
	f.status.Descriptor = nil
	f.status.DescriptorHash = nil
	f.status.KeysPinned = 1
	result, err := c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation)
	if err != nil || !result.Pending || f.challenges != 0 {
		t.Fatalf("peer pending: %+v %v", result, err)
	}
	if _, err = c.OwnerTextProjectStatus(context.Background(), enrollmentProjectID); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerTextProjectPinRejectsSymlinkAndInsecureDirectory(t *testing.T) {
	for _, kind := range []string{"symlink", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			f, c := newOwnerTextEnrollmentFixture(t)
			parent := filepath.Join(c.kr.root, enrollmentPrincipalID)
			dir := filepath.Join(parent, "owner-text-projects")
			if kind == "symlink" {
				if err := os.Symlink(t.TempDir(), dir); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation); err == nil {
				t.Fatal("unsafe pin directory accepted")
			}
			if f.proofs != 0 {
				t.Fatal("proved without durable pin")
			}
		})
	}
}
