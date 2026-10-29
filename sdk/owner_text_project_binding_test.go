package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ownerTextBindingFixture(t *testing.T, lost bool) (*ownerTextEnrollmentFixture, *Client) {
	t.Helper()
	f, c := newOwnerTextEnrollmentFixture(t)
	c.endpointID.Store(textEndpointID)
	c.cur = &conn{dead: make(chan struct{})}
	t.Cleanup(func() { c.invalidateOwnerTextBinding() })
	f.status.ProjectVersion = "1"
	f.lostProof = lost
	f.mutateAAD = func(a *ownerTextProjectProofAAD) {
		a.EndpointID = textEndpointID
		f.status.EndpointProof = &OwnerTextProjectEndpointProof{ProofID: ownerTextChallenge, PrincipalID: a.PrincipalID, InstallationID: a.InstallationID, ClaimID: a.ClaimID, Generation: "2", EndpointID: a.EndpointID, CredentialID: a.CredentialID, EndpointStartedAt: a.EndpointStartedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"), DescriptorHash: append([]byte(nil), a.DescriptorHash...)}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/installations/") {
			claim := ownerTextClaim
			_ = json.NewEncoder(w).Encode(TextServiceReadiness{InstallationID: ownerTextInstallation, ClaimID: &claim, Generation: 2, ProjectContract: "owner_text_project_v1"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer pgn_epd_v1_test" {
			t.Error("wrong captured bearer")
		}
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(bytes.ReplaceAll(raw, []byte(textEndpointID), []byte("endpoint"))))
		}
		q := r.URL.Query()
		if q.Get("endpointId") == textEndpointID {
			q.Set("endpointId", "endpoint")
			r.URL.RawQuery = q.Encode()
		}
		f.serve(w, r)
	}))
	t.Cleanup(server.Close)
	c.rest = newRestClient(server.URL, "test", func() string { return c.credential.Load().(string) })
	proof := TextServiceInstallationProof{InstallationID: ownerTextInstallation, ClaimID: ownerTextClaim, Generation: 2, ProjectContract: "owner_text_project_v1", Nonce: bytes.Repeat([]byte{1}, 32)}
	if _, err := c.ProveTextServiceInstallation(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	return f, c
}

func TestOwnerTextProjectBindingEnrollmentAndRecovery(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "ambiguous recovery"}[lost], func(t *testing.T) {
			f, c := ownerTextBindingFixture(t, lost)
			if _, err := c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation); err != nil {
				t.Fatal(err)
			}
			// A caller's proof remains authoritative while its responder is offline.
			f.mu.Lock()
			f.status.Ready = false
			f.status.Roles[1].Ready = false
			f.status.PrincipalsProved = 1
			f.mu.Unlock()
			first, done, err := c.OwnerTextProjectBinding(context.Background(), enrollmentProjectID, ownerTextInstallation)
			if err != nil || first.Ready || first.ProjectVersion != "1" {
				t.Fatalf("binding: %v", err)
			}
			first.Descriptor[0] ^= 1
			first.DescriptorHash[0] ^= 1
			first.EndpointProof.DescriptorHash[0] ^= 1
			first.Roles[0].InstallationID = "changed"
			if _, _, err = c.OwnerTextProjectBinding(context.Background(), enrollmentProjectID, ownerTextInstallation); err != nil {
				t.Fatal("copy mutated internal pin", err)
			}
			// Already-proved recovery has no locally retained challenge.
			c.ownerTextBindingMu.Lock()
			clear(c.ownerTextInstallation.aad)
			clear(c.ownerTextInstallation.proofs)
			c.ownerTextBindingMu.Unlock()
			if _, _, err = c.OwnerTextProjectBinding(context.Background(), enrollmentProjectID, ownerTextInstallation); err != nil {
				t.Fatal(err)
			}
			c.connMu.Lock()
			close(c.cur.dead)
			c.connMu.Unlock()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("binding did not invalidate")
			}
		})
	}
}

func TestOwnerTextProjectBindingRejectsMismatch(t *testing.T) {
	for _, kind := range []string{"claim", "generation", "credential", "start", "proof", "version", "descriptor", "missing pin", "bearer", "connection", "replacement"} {
		t.Run(kind, func(t *testing.T) {
			f, c := ownerTextBindingFixture(t, false)
			if _, err := c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation); err != nil {
				t.Fatal(err)
			}
			_, done, err := c.OwnerTextProjectBinding(context.Background(), enrollmentProjectID, ownerTextInstallation)
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			switch kind {
			case "claim":
				f.status.EndpointProof.ClaimID = textClaimID
			case "generation":
				f.status.EndpointProof.Generation = "02"
			case "credential":
				f.status.EndpointProof.CredentialID = ownerTextClaim
			case "start":
				f.status.EndpointProof.EndpointStartedAt = "2026-01-01T01:01:01.000000000Z"
			case "proof":
				f.status.EndpointProof.ProofID = ownerTextClaim
			case "version":
				f.status.ProjectVersion = "01"
			case "descriptor":
				f.status.DescriptorHash[0] ^= 1
			case "missing pin":
				c.kr = nil
			case "bearer":
				c.credential.Store("pgn_epd_v1_changed")
			case "connection":
				c.connGeneration.Add(1)
			case "replacement":
				c.retainTextServiceInstallation(TextServiceInstallationProof{InstallationID: ownerTextInstallation, ClaimID: textClaimID, Generation: 3}, "owner_text_project_v1", textEndpointID, "pgn_epd_v1_test", enrollmentPrincipalID, c.connGeneration.Load(), c.cur.dead)
			}
			f.mu.Unlock()
			if _, _, err = c.OwnerTextProjectBinding(context.Background(), enrollmentProjectID, ownerTextInstallation); err == nil {
				t.Fatal("accepted mismatch")
			}
			if kind == "bearer" || kind == "connection" || kind == "replacement" {
				select {
				case <-done:
				default:
					t.Fatal("old snapshot remains live")
				}
			}
		})
	}
}

func TestOwnerTextProjectBindingReconnectDuringStatus(t *testing.T) {
	f, c := ownerTextBindingFixture(t, false)
	if _, err := c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pgn_epd_v1_test" || r.URL.Query().Get("endpointId") != textEndpointID {
			t.Error("status not pinned")
		}
		close(entered)
		<-release
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(f.status)
	}))
	defer server.Close()
	c.rest = newRestClient(server.URL, "test", func() string { return c.credential.Load().(string) })
	result := make(chan error, 1)
	go func() {
		_, _, err := c.OwnerTextProjectBinding(context.Background(), enrollmentProjectID, ownerTextInstallation)
		result <- err
	}()
	<-entered
	c.connMu.Lock()
	old := c.cur
	c.cur = &conn{dead: make(chan struct{})}
	close(old.dead)
	c.connMu.Unlock()
	close(release)
	if err := <-result; err == nil {
		t.Fatal("reconnected status accepted")
	}
}

func TestOwnerTextProjectBindingReplacementProofFailureInvalidates(t *testing.T) {
	_, c := ownerTextBindingFixture(t, false)
	if _, err := c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation); err != nil {
		t.Fatal(err)
	}
	_, done, err := c.OwnerTextProjectBinding(context.Background(), enrollmentProjectID, ownerTextInstallation)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "ambiguous", 503) }))
	defer server.Close()
	c.rest = newRestClient(server.URL, "test", func() string { return c.credential.Load().(string) })
	_, err = c.ProveTextServiceInstallation(context.Background(), TextServiceInstallationProof{InstallationID: ownerTextInstallation, ClaimID: textClaimID, Generation: 3, ProjectContract: "owner_text_project_v1", Nonce: bytes.Repeat([]byte{1}, 32)})
	if err == nil {
		t.Fatal("expected ambiguous proof failure")
	}
	select {
	case <-done:
	default:
		t.Fatal("replacement left prior binding live")
	}
}

func TestOwnerTextProjectBindingLostDurablePinInvalidates(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "expired"} {
		t.Run(kind, func(t *testing.T) {
			f, c := ownerTextBindingFixture(t, false)
			if _, err := c.EnrollOwnerTextProject(context.Background(), enrollmentProjectID, ownerTextInstallation); err != nil {
				t.Fatal(err)
			}
			_, done, err := c.OwnerTextProjectBinding(context.Background(), enrollmentProjectID, ownerTextInstallation)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(c.kr.root, enrollmentPrincipalID, "owner-text-projects", enrollmentProjectID+".json")
			switch kind {
			case "missing":
				err = os.Remove(path)
			case "corrupt":
				err = os.WriteFile(path, []byte("invalid"), 0600)
			case "expired":
				f.descriptor.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
				raw, _ := json.Marshal(f.descriptor)
				err = os.WriteFile(path, raw, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = c.OwnerTextProjectBinding(context.Background(), enrollmentProjectID, ownerTextInstallation); err == nil {
				t.Fatal("accepted invalid durable pin")
			}
			select {
			case <-done:
			default:
				t.Fatal("prior binding remained live after pin validation failed")
			}
		})
	}
}
