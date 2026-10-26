package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

type projectTransportFixture struct {
	t                                 *testing.T
	project                           string
	clients                           []*Client
	status                            SharingProjectStatus
	endpoint                          string
	wire                              []byte
	posts, receipts, acks, proofs     int
	loseSend, missingReceipt, failACK bool
	badDigest                         bool
	quota                             int
	requests                          [][]byte
	cursors                           []string
}

func newProjectTransportFixture(t *testing.T) *projectTransportFixture {
	t.Helper()
	project, clients := projectMessageFixture(t)
	d, hash, err := clients[0].projectMessageDescriptor(project)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(d)
	f := &projectTransportFixture{t: t, project: project, clients: clients, endpoint: "endpoint-1", status: SharingProjectStatus{ProjectID: project, NetworkID: d.NetworkID, State: "active", Descriptor: raw, DescriptorHash: hash, RosterSize: len(d.Roster), EndpointProved: true}}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	for _, c := range clients {
		c.endpointID.Store(f.endpoint)
		c.credential.Store("pgn_epd_v1_test")
		c.connected.Store(true)
		c.connGeneration.Store(1)
		c.rest = newRestClient(server.URL, "test", func() string { return c.credential.Load().(string) })
	}
	return f
}
func (f *projectTransportFixture) receipt() SharingProjectMessageReceipt {
	var wire sharingProjectMessageWire
	_ = json.Unmarshal(f.wire, &wire)
	digest := sha256.Sum256(f.wire)
	if f.badDigest {
		digest[0] ^= 1
	}
	return SharingProjectMessageReceipt{MessageID: wire.ID, AdmissionSeq: 7, RequestDigest: digest[:], Status: "pending", CreatedAt: time.Now().UTC()}
}
func (f *projectTransportFixture) serve(w http.ResponseWriter, r *http.Request) {
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	if r.Header.Get("Authorization") != "Bearer pgn_epd_v1_test" {
		f.t.Error("wrong endpoint credential")
		http.Error(w, "auth", 401)
		return
	}
	var req struct {
		EndpointID string          `json:"endpointId"`
		Wire       json.RawMessage `json:"wire"`
		Response   []byte          `json:"response"`
	}
	endpoint := r.URL.Query().Get("endpointId")
	if r.Method == http.MethodPost {
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "body", 400)
			return
		}
		endpoint = req.EndpointID
	}
	if endpoint != f.endpoint {
		f.t.Errorf("stale endpoint: %q, want %q", endpoint, f.endpoint)
		http.Error(w, "endpoint", 403)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/status"), strings.HasSuffix(r.URL.Path, "/pin"):
		write(f.status)
	case strings.HasSuffix(r.URL.Path, "/challenge"):
		aad, _ := json.Marshal(sharingProjectProofAAD{sharingProjectProofDomain, f.project, f.status.DescriptorHash, f.clients[0].PrincipalID(), f.endpoint, "credential", "challenge"})
		enc, ct, _ := e2ee.HPKEWrap(f.clients[0].identityPub, []byte(sharingProjectProofDomain), aad, bytes.Repeat([]byte{9}, 32))
		write(sharingProjectChallenge{"challenge", f.status.DescriptorHash, aad, enc, ct, time.Now().Add(time.Minute)})
	case strings.HasSuffix(r.URL.Path, "/prove"):
		if !bytes.Equal(req.Response, bytes.Repeat([]byte{9}, 32)) {
			http.Error(w, "proof", 400)
			return
		}
		f.proofs++
		f.status.EndpointProved = true
		write(f.status)
	case strings.HasSuffix(r.URL.Path, "/receipt"):
		f.receipts++
		if f.missingReceipt {
			http.NotFound(w, r)
			return
		}
		write(f.receipt())
	case strings.HasSuffix(r.URL.Path, "/ack"):
		f.acks++
		if f.failACK {
			http.Error(w, "retry ack", 503)
			return
		}
		w.WriteHeader(204)
	case strings.HasSuffix(r.URL.Path, "/messages") && r.Method == http.MethodPost:
		f.posts++
		f.requests = append(f.requests, append([]byte(nil), req.Wire...))
		if f.quota != 0 {
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(f.quota)
			write(map[string]any{"error": "sharing_project_quota_exceeded", "limit": "maxInFlight", "max": 2, "resetAt": time.Now().Add(time.Minute)})
			return
		}
		f.wire = append([]byte(nil), req.Wire...)
		if f.loseSend {
			w.WriteHeader(201)
			_, _ = w.Write([]byte("{"))
			return
		}
		write(f.receipt())
	case strings.HasSuffix(r.URL.Path, "/messages"):
		f.cursors = append(f.cursors, r.URL.Query().Get("cursor"))
		if r.URL.Query().Get("limit") != "1" {
			f.t.Error("missing inbox limit")
		}
		if r.URL.Query().Get("cursor") == "7" {
			write([]json.RawMessage{})
			return
		}
		w.Header().Set("X-Next-Cursor", "7")
		write([]json.RawMessage{f.wire})
	default:
		http.NotFound(w, r)
	}
}
func TestSharingProjectTransportUncertainSendReceiptAndRetry(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "receipt", true: "retry"}[missing], func(t *testing.T) {
			f := newProjectTransportFixture(t)
			c := f.clients[0]
			prepared, err := c.PrepareSharingProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", []byte("exact wire"), nil)
			if err != nil {
				t.Fatal(err)
			}
			f.loseSend, f.missingReceipt = true, missing
			receipt, err := c.SendPreparedSharingProjectMessage(context.Background(), f.project, prepared.ID)
			if missing {
				if err == nil {
					t.Fatal("uncertain send succeeded without receipt")
				}
				f.loseSend, f.missingReceipt = false, false
				receipt, err = c.SendPreparedSharingProjectMessage(context.Background(), f.project, prepared.ID)
			}
			if err != nil || receipt.MessageID != prepared.ID || f.receipts != 1 {
				t.Fatalf("send: %+v, %v, receipts %d", receipt, err, f.receipts)
			}
			for _, raw := range f.requests {
				if !bytes.Equal(raw, prepared.Wire) {
					t.Fatal("retry changed durable wire")
				}
			}
			if _, err := c.SharingProjectMessageReceipt(context.Background(), f.project, prepared.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := c.LoadPreparedSharingProjectMessage(f.project, prepared.ID); !errors.Is(err, ErrSharingProjectMessageAdmitted) {
				t.Fatalf("admission did not retire wire: %v", err)
			}
		})
	}
}
func TestSharingProjectTransportInboxPaginationDuplicatesAndACK(t *testing.T) {
	f := newProjectTransportFixture(t)
	prepared, err := f.clients[0].PrepareSharingProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", []byte("deliver"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.wire = prepared.Wire
	bob := f.clients[1]
	for i := 0; i < 2; i++ {
		page, err := bob.SharingProjectInbox(context.Background(), f.project, "", 1)
		if err != nil || len(page.Messages) != 1 || page.NextCursor != "7" {
			t.Fatalf("page: %+v %v", page, err)
		}
		opened, err := bob.DecryptSharingProjectMessage(f.project, page.Messages[0], nil)
		if err != nil || string(opened.Plaintext) != "deliver" {
			t.Fatalf("decrypt: %v", err)
		}
	}
	if f.acks != 0 {
		t.Fatal("read automatically acknowledged")
	}
	page, err := bob.SharingProjectInbox(context.Background(), f.project, "7", 1)
	if err != nil || len(page.Messages) != 0 || len(f.cursors) != 3 || f.cursors[2] != "7" {
		t.Fatalf("cursor: %+v %v", page, err)
	}
	f.failACK = true
	if err := bob.AckSharingProjectMessage(context.Background(), f.project, prepared.ID); err == nil {
		t.Fatal("ACK failure hidden")
	}
	f.failACK = false
	if err := bob.AckSharingProjectMessage(context.Background(), f.project, prepared.ID); err != nil {
		t.Fatal(err)
	}
	if f.acks != 2 {
		t.Fatal("ACK not explicitly retried")
	}
}
func TestSharingProjectTransportCurrentEndpointAndDescriptor(t *testing.T) {
	f := newProjectTransportFixture(t)
	c := f.clients[0]
	prepared, err := c.PrepareSharingProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.endpoint = "endpoint-reconnected"
	c.endpointID.Store(f.endpoint)
	c.connGeneration.Add(1)
	f.status.EndpointProved = false
	if _, err := c.SendPreparedSharingProjectMessage(context.Background(), f.project, prepared.ID); err != nil || f.proofs != 1 {
		t.Fatalf("reprove: %v, proofs %d", err, f.proofs)
	}
	var d sharingProjectDescriptor
	_ = json.Unmarshal(f.status.Descriptor, &d)
	d.PolicyHash = strings.Repeat("1", 64)
	f.status.Descriptor, _ = json.Marshal(d)
	hash := sha256.Sum256(f.status.Descriptor)
	f.status.DescriptorHash = hash[:]
	if _, err := c.SendPreparedSharingProjectMessage(context.Background(), f.project, prepared.ID); err == nil || f.posts != 1 {
		t.Fatal("descriptor mismatch permitted send")
	}
	c.connected.Store(false)
	if _, err := c.SendPreparedSharingProjectMessage(context.Background(), f.project, prepared.ID); err == nil {
		t.Fatal("disconnected send allowed")
	}
}
func TestSharingProjectTransportQuota(t *testing.T) {
	for _, code := range []int{413, 409, 429} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			f := newProjectTransportFixture(t)
			prepared, err := f.clients[0].PrepareSharingProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.quota = code
			_, err = f.clients[0].SendPreparedSharingProjectMessage(context.Background(), f.project, prepared.ID)
			var quota *SharingProjectMessageQuotaError
			if !errors.As(err, &quota) || quota.StatusCode != code || quota.Maximum != 2 || quota.RetryAfter != "5" || quota.ResetAt == nil {
				t.Fatalf("quota detail: %v", err)
			}
			if f.receipts != 0 {
				t.Fatal("quota treated as ambiguous send")
			}
			if _, err = f.clients[0].LoadPreparedSharingProjectMessage(f.project, prepared.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
