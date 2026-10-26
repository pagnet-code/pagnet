package sdk

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

const enrollmentProjectID = "10000000-0000-4000-8000-000000000001"
const enrollmentPrincipalID = "20000000-0000-4000-8000-000000000002"
const enrollmentSecondID = "30000000-0000-4000-8000-000000000003"

type projectEnrollmentFixture struct {
	status             SharingProjectStatus
	descriptor         sharingProjectDescriptor
	public             []byte
	response           []byte
	corrupt, lostProof bool
	proofs, challenges int
}

func newProjectEnrollmentFixture(t *testing.T) (*projectEnrollmentFixture, *Client) {
	t.Helper()
	private, err := newIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdh.X25519().NewPrivateKey(private)
	pub := key.PublicKey().Bytes()
	f := &projectEnrollmentFixture{public: pub, response: bytes.Repeat([]byte{7}, 32)}
	f.descriptor = sharingProjectDescriptor{Version: 2, Suite: "X25519-HKDF-SHA256-AES-256-GCM", ProjectID: enrollmentProjectID, NetworkID: "network", PolicyHash: "policy", IssuerTenantID: "issuer-tenant", IssuerUserID: "issuer-user", RecipientTenantID: "recipient-tenant", RecipientUserID: "recipient-user", Roster: []sharingProjectPrincipal{{enrollmentPrincipalID, base64.StdEncoding.EncodeToString(pub)}, {enrollmentSecondID, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))}}, Permissions: []string{"discover", "communicate"}, Limits: SharingPairLimits{1024, 1, 1, 1024, 1, 1}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	f.status = SharingProjectStatus{ProjectID: enrollmentProjectID, NetworkID: "network", State: "enrolling", RosterSize: 2, KeysPinned: 2}
	f.refresh()
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	kr, err := newKeyring(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.PersistIdentity(enrollmentPrincipalID, "pgn_epd_v1_test", private); err != nil {
		t.Fatal(err)
	}
	c := &Client{kr: kr, identityPriv: private, identityPub: pub}
	c.principalID.Store(enrollmentPrincipalID)
	c.endpointID.Store("endpoint")
	c.credential.Store("pgn_epd_v1_test")
	c.connected.Store(true)
	c.connGeneration.Store(1)
	c.rest = newRestClient(server.URL, "test", func() string { return "pgn_epd_v1_test" })
	return f, c
}
func (f *projectEnrollmentFixture) refresh() {
	f.status.Descriptor, _ = json.Marshal(f.descriptor)
	hash := sha256.Sum256(f.status.Descriptor)
	f.status.DescriptorHash = hash[:]
}
func (f *projectEnrollmentFixture) serve(w http.ResponseWriter, r *http.Request) {
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case r.URL.Path == "/api/v1/sharing-project-transports":
		write([]SharingProjectStatus{f.status})
	case strings.HasSuffix(r.URL.Path, "/status"), strings.HasSuffix(r.URL.Path, "/pin"):
		write(f.status)
	case strings.HasSuffix(r.URL.Path, "/challenge"):
		f.challenges++
		aad, _ := json.Marshal(sharingProjectProofAAD{sharingProjectProofDomain, enrollmentProjectID, f.status.DescriptorHash, enrollmentPrincipalID, "endpoint", "credential", "challenge"})
		enc, ct, _ := e2ee.HPKEWrap(f.public, []byte(sharingProjectProofDomain), aad, f.response)
		if f.corrupt {
			ct[0] ^= 1
		}
		write(sharingProjectChallenge{"challenge", f.status.DescriptorHash, aad, enc, ct, time.Now().Add(time.Minute)})
	case strings.HasSuffix(r.URL.Path, "/prove"):
		var req struct {
			EndpointID  string `json:"endpointId"`
			ChallengeID string `json:"challengeId"`
			Response    []byte `json:"response"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.EndpointID != "endpoint" || req.ChallengeID != "challenge" || !bytes.Equal(req.Response, f.response) {
			http.Error(w, "bad proof", 400)
			return
		}
		f.proofs++
		f.status.EndpointProved = true
		f.status.PrincipalsProved = 2
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

func TestSharingProjectEnrollmentReconnectRepeat(t *testing.T) {
	f, c := newProjectEnrollmentFixture(t)
	f.lostProof = true
	result, err := c.EnrollSharingProject(context.Background(), enrollmentProjectID)
	if err != nil || result.Pending || result.DescriptorFingerprint == "" {
		t.Fatalf("enrollment: %+v %v", result, err)
	}
	// Reconstruct the client as a process reconnect using only its persisted keyring.
	reopened, err := newKeyring(filepath.Dir(c.kr.root))
	if err != nil {
		t.Fatal(err)
	}
	private, err := reopened.identityKey(enrollmentPrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	c2 := &Client{kr: reopened, rest: c.rest, identityPriv: private, identityPub: c.identityPub}
	c2.principalID.Store(enrollmentPrincipalID)
	c2.endpointID.Store("endpoint")
	c2.credential.Store("pgn_epd_v1_test")
	c2.connected.Store(true)
	c2.connGeneration.Store(2)
	result, err = c2.EnrollSharingProject(context.Background(), enrollmentProjectID)
	if err != nil || result.Pending || f.proofs != 1 || f.challenges != 1 {
		t.Fatalf("repeat: %+v %v, proofs %d challenges %d", result, err, f.proofs, f.challenges)
	}
	f.descriptor.PolicyHash = "substituted"
	f.refresh()
	if _, err := c2.EnrollSharingProject(context.Background(), enrollmentProjectID); err == nil {
		t.Fatal("accepted descriptor substitution after reconnect")
	}
}

func TestSharingProjectEnrollmentRejectsInvalidInputs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*projectEnrollmentFixture)
	}{
		{"wrong own key", func(f *projectEnrollmentFixture) {
			f.descriptor.Roster[0].PublicKey = f.descriptor.Roster[1].PublicKey
			f.refresh()
		}},
		{"wrong network", func(f *projectEnrollmentFixture) { f.descriptor.NetworkID = "other"; f.refresh() }},
		{"wrong permissions", func(f *projectEnrollmentFixture) { f.descriptor.Permissions = []string{"communicate"}; f.refresh() }},
		{"wrong hash", func(f *projectEnrollmentFixture) { f.status.DescriptorHash = make([]byte, 32) }},
		{"noncanonical", func(f *projectEnrollmentFixture) {
			f.status.Descriptor = append(f.status.Descriptor, ' ')
			hash := sha256.Sum256(f.status.Descriptor)
			f.status.DescriptorHash = hash[:]
		}},
		{"corrupt challenge", func(f *projectEnrollmentFixture) { f.corrupt = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, c := newProjectEnrollmentFixture(t)
			tc.mutate(f)
			if _, err := c.EnrollSharingProject(context.Background(), enrollmentProjectID); err == nil {
				t.Fatal("accepted invalid enrollment")
			}
			if f.proofs != 0 {
				t.Fatal("submitted invalid proof")
			}
		})
	}
}

func TestSharingProjectEnrollmentExpectedPolicyAndLegacy(t *testing.T) {
	f, c := newProjectEnrollmentFixture(t)
	if _, err := c.EnrollSharingProjectWithPolicyHash(context.Background(), enrollmentProjectID, "other"); err == nil {
		t.Fatal("accepted wrong expected policy")
	}
	f.status.State = "accepted_blocked"
	result, err := c.EnrollSharingProject(context.Background(), enrollmentProjectID)
	if err != nil || !result.Pending || f.challenges != 0 {
		t.Fatalf("legacy project advanced: %+v %v", result, err)
	}
}

func TestSharingProjectPinDirectorySyncFailures(t *testing.T) {
	for _, stage := range []string{"new parent", "existing directory", "existing parent"} {
		t.Run(stage, func(t *testing.T) {
			kr, err := newKeyring(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(kr.root, enrollmentPrincipalID)
			dir := filepath.Join(parent, "sharing-projects")
			path := filepath.Join(dir, enrollmentProjectID+".json")
			descriptor := []byte("immutable descriptor")
			if stage != "new parent" {
				if err = kr.pinSharingProjectDescriptor(enrollmentPrincipalID, enrollmentProjectID, descriptor); err != nil {
					t.Fatal(err)
				}
			}
			injected := errors.New("injected directory sync failure")
			parentSyncs := 0
			failed := false
			kr.pendingPairSyncDir = func(path string) error {
				if path == parent {
					parentSyncs++
				}
				if (stage == "new parent" && path == parent) || (stage == "existing directory" && path == dir) || (stage == "existing parent" && path == parent && parentSyncs == 2) {
					failed = true
					return injected
				}
				return syncPairDir(path)
			}
			if err = kr.pinSharingProjectDescriptor(enrollmentPrincipalID, enrollmentProjectID, descriptor); !errors.Is(err, injected) || !failed {
				t.Fatalf("sync failure ignored: %v, injected %v", err, failed)
			}
			if stage == "new parent" {
				if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("published pin before parent sync: %v", err)
				}
			} else {
				raw, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(raw, descriptor) {
					t.Fatalf("existing pin changed: %v", err)
				}
			}
			kr.pendingPairSyncDir = nil
			if err = kr.pinSharingProjectDescriptor(enrollmentPrincipalID, enrollmentProjectID, descriptor); err != nil {
				t.Fatalf("retry did not recover durability: %v", err)
			}
		})
	}
}

func TestSharingProjectPinRejectsUnsafePaths(t *testing.T) {
	for _, kind := range []string{"invalid UUID", "directory mode", "directory symlink", "file mode", "file symlink"} {
		t.Run(kind, func(t *testing.T) {
			kr, err := newKeyring(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			descriptor := []byte("descriptor")
			if kind == "invalid UUID" {
				if err = kr.pinSharingProjectDescriptor("../outside", enrollmentProjectID, descriptor); err == nil {
					t.Fatal("accepted unsafe identity")
				}
				return
			}
			if err = kr.pinSharingProjectDescriptor(enrollmentPrincipalID, enrollmentProjectID, descriptor); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(kr.root, enrollmentPrincipalID, "sharing-projects")
			path := filepath.Join(dir, enrollmentProjectID+".json")
			switch kind {
			case "directory mode":
				err = os.Chmod(dir, 0o755)
			case "directory symlink":
				moved := dir + "-moved"
				if err = os.Rename(dir, moved); err == nil {
					err = os.Symlink(moved, dir)
				}
			case "file mode":
				err = os.Chmod(path, 0o644)
			case "file symlink":
				moved := path + "-moved"
				if err = os.Rename(path, moved); err == nil {
					err = os.Symlink(moved, path)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = kr.pinSharingProjectDescriptor(enrollmentPrincipalID, enrollmentProjectID, descriptor); err == nil {
				t.Fatal("accepted unsafe pin store")
			}
		})
	}
}
