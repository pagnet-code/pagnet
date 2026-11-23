package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
)

type ownerTextTransportFixture struct {
	t                                       *testing.T
	project                                 string
	clients                                 []*Client
	status                                  OwnerTextProjectStatus
	wire                                    []byte
	posts, receipts, acks, proofs, statuses int
	requests                                [][]byte
	cursors                                 []string
	loseSend, missingReceipt, failACK       bool
	sendStatus, quota                       int
	mutateReceipt                           func(*OwnerTextProjectMessageReceipt)
	mutateStatus                            func(*OwnerTextProjectStatus)
	beforeResponse                          func(string)
	inbox                                   []json.RawMessage
	nextCursor                              string
}

func newOwnerTextTransportFixture(t *testing.T) *ownerTextTransportFixture {
	t.Helper()
	project, clients := ownerTextMessageFixture(t)
	d, hash, err := clients[0].ownerTextMessageDescriptor(project)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(d)
	f := &ownerTextTransportFixture{t: t, project: project, clients: clients[:2], status: OwnerTextProjectStatus{ProjectID: project, NetworkID: d.NetworkID, State: "active", Descriptor: raw, DescriptorHash: hash, KeysPinned: 2, PrincipalsProved: 2, RosterSize: 2, EndpointProved: true, Ready: true}}
	for _, member := range d.Roster {
		f.status.Roles = append(f.status.Roles, OwnerTextProjectRoleStatus{Role: member.Role, PrincipalID: member.PrincipalID, InstallationID: member.InstallationID, Ready: true})
	}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	for i, c := range f.clients {
		c.endpointID.Store([]string{ownerTextClaim, ownerTextChallenge}[i])
		c.credential.Store("pgn_epd_v1_test")
		c.connected.Store(true)
		c.connGeneration.Store(1)
		c.rest = newRestClient(server.URL, "test", func() string { return "pgn_epd_v1_test" })
	}
	return f
}
func (f *ownerTextTransportFixture) receipt() OwnerTextProjectMessageReceipt {
	var wire ownerTextProjectMessageWire
	_ = json.Unmarshal(f.wire, &wire)
	digest := sha256.Sum256(f.wire)
	receipt := OwnerTextProjectMessageReceipt{MessageID: wire.ID, AdmissionSeq: 7, RequestDigest: digest[:], Status: "pending", CreatedAt: time.Now().UTC()}
	if f.mutateReceipt != nil {
		f.mutateReceipt(&receipt)
	}
	return receipt
}
func (f *ownerTextTransportFixture) serve(w http.ResponseWriter, r *http.Request) {
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	base := "/api/v1/owner-text-project-transports/" + f.project
	if !strings.HasPrefix(r.URL.Path, base+"/") {
		f.t.Errorf("wrong owner namespace: %s", r.URL.Path)
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer pgn_epd_v1_test" {
		f.t.Error("wrong credential")
		http.Error(w, "auth", 401)
		return
	}
	endpoint := r.URL.Query().Get("endpointId")
	var req struct {
		EndpointID string `json:"endpointId"`
		Response   []byte `json:"response"`
	}
	if r.Method == http.MethodPost && !strings.Contains(r.URL.Path, "/messages") {
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "body", 400)
			return
		}
		endpoint = req.EndpointID
	}
	index := -1
	for i, c := range f.clients {
		if endpoint == c.endpointID.Load() {
			index = i
		}
	}
	if index < 0 {
		f.t.Errorf("wrong endpoint query: %s", r.URL.RawQuery)
		http.Error(w, "endpoint", 403)
		return
	}
	response := func(kind string) {
		if f.beforeResponse != nil {
			f.beforeResponse(kind)
		}
	}
	switch {
	case r.URL.Path == base+"/status" || r.URL.Path == base+"/pin":
		f.statuses++
		status := f.status
		status.Roles = append([]OwnerTextProjectRoleStatus(nil), f.status.Roles...)
		status.EndpointProved = status.Roles[index].Ready
		if f.mutateStatus != nil {
			f.mutateStatus(&status)
		}
		response("status")
		write(status)
	case r.URL.Path == base+"/challenge":
		principal := f.status.Roles[index]
		aad, _ := json.Marshal(ownerTextProjectProofAAD{ownerTextProjectProofDomain, f.project, f.status.DescriptorHash, principal.PrincipalID, principal.InstallationID, ownerTextClaim, 1, endpoint, ownerTextCredential, time.Now().Add(-time.Minute).UTC(), ownerTextChallenge})
		enc, ct, err := e2ee.HPKEWrap(f.clients[index].identityPub, []byte(ownerTextProjectProofDomain), aad, bytes.Repeat([]byte{9}, 32))
		if err != nil {
			f.t.Error(err)
			http.Error(w, "crypto", 500)
			return
		}
		write(ownerTextProjectChallenge{ownerTextChallenge, f.status.DescriptorHash, aad, enc, ct, time.Now().Add(time.Minute)})
	case r.URL.Path == base+"/prove":
		if !bytes.Equal(req.Response, bytes.Repeat([]byte{9}, 32)) {
			f.t.Error("wrong proof response")
			http.Error(w, "proof", 400)
			return
		}
		f.proofs++
		f.status.Roles[index].Ready = true
		f.status.PrincipalsProved = 2
		f.status.Ready = true
		f.status.EndpointProved = true
		write(f.status)
	case strings.HasSuffix(r.URL.Path, "/receipt"):
		f.receipts++
		var wire ownerTextProjectMessageWire
		_ = json.Unmarshal(f.wire, &wire)
		if r.URL.Path != base+"/messages/"+wire.ID+"/receipt" {
			f.t.Errorf("wrong receipt URL: %s", r.URL.Path)
		}
		if f.missingReceipt {
			http.NotFound(w, r)
			return
		}
		response("receipt")
		write(f.receipt())
	case strings.HasSuffix(r.URL.Path, "/ack"):
		f.acks++
		if r.Method != http.MethodPost {
			f.t.Error("ACK method must be POST")
		}
		message := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, base+"/messages/"), "/ack")
		if !projectUUID(message, true) {
			f.t.Errorf("wrong ACK URL: %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		if len(raw) != 0 {
			f.t.Error("ACK must have empty body")
		}
		response("ack")
		if f.failACK {
			http.Error(w, "retry ack", 503)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == base+"/messages" && r.Method == http.MethodPost:
		f.posts++
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			f.t.Error(err)
		}
		f.requests = append(f.requests, bytes.Clone(raw))
		if r.Header.Get("Content-Type") != "application/json" {
			f.t.Error("wrong content type")
		}
		if f.quota != 0 {
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(f.quota)
			write(map[string]any{"error": "sharing_project_quota_exceeded", "limit": "maxInFlight", "max": 2, "resetAt": time.Now().Add(time.Minute)})
			return
		}
		f.wire = bytes.Clone(raw)
		response("send")
		if f.sendStatus != 0 {
			http.Error(w, "ambiguous server error", f.sendStatus)
			return
		}
		if f.loseSend {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("{"))
			return
		}
		w.WriteHeader(http.StatusCreated)
		write(f.receipt())
	case r.URL.Path == base+"/messages" && r.Method == http.MethodGet:
		f.cursors = append(f.cursors, r.URL.Query().Get("cursor"))
		if r.URL.Query().Get("limit") != "1" {
			f.t.Error("missing exact inbox limit query")
		}
		response("inbox")
		if f.nextCursor != "" {
			w.Header().Set("X-Next-Cursor", f.nextCursor)
		}
		if f.inbox != nil {
			write(f.inbox)
		} else {
			write([]json.RawMessage{})
		}
	default:
		http.NotFound(w, r)
	}
}
func TestOwnerTextTransportExactWireAmbiguousSendAndRetry(t *testing.T) {
	for _, kind := range []string{"decode receipt", "retry", "server error"} {
		t.Run(kind, func(t *testing.T) {
			f := newOwnerTextTransportFixture(t)
			c := f.clients[0]
			prepared, err := c.PrepareOwnerTextProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", []byte("exact wire"), nil)
			if err != nil {
				t.Fatal(err)
			}
			f.loseSend = true
			f.missingReceipt = kind == "retry"
			if kind == "server error" {
				f.sendStatus = 503
			}
			receipt, err := c.SendPreparedOwnerTextProjectMessage(context.Background(), f.project, prepared.ID)
			if kind == "retry" {
				if err == nil {
					t.Fatal("missing receipt accepted")
				}
				loaded, loadErr := c.LoadPreparedOwnerTextProjectMessage(f.project, prepared.ID)
				if loadErr != nil || !bytes.Equal(loaded.Wire, prepared.Wire) {
					t.Fatal("ambiguous failure lost retry bytes")
				}
				f.loseSend = false
				f.missingReceipt = false
				receipt, err = c.SendPreparedOwnerTextProjectMessage(context.Background(), f.project, prepared.ID)
			}
			if err != nil || receipt.MessageID != prepared.ID || f.receipts != 1 {
				t.Fatalf("send: %+v %v receipts=%d", receipt, err, f.receipts)
			}
			for _, raw := range f.requests {
				if !bytes.Equal(raw, prepared.Wire) {
					t.Fatal("POST changed exact canonical bytes")
				}
			}
			if _, err = c.LoadPreparedOwnerTextProjectMessage(f.project, prepared.ID); !errors.Is(err, ErrOwnerTextProjectMessageAdmitted) {
				t.Fatal(err)
			}
			if _, err = c.OwnerTextProjectMessageReceipt(context.Background(), f.project, prepared.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestOwnerTextTransportRejectsReceiptMismatch(t *testing.T) {
	cases := map[string]func(*OwnerTextProjectMessageReceipt){
		"id":               func(r *OwnerTextProjectMessageReceipt) { r.MessageID = ownerTextID(t) },
		"sequence":         func(r *OwnerTextProjectMessageReceipt) { r.AdmissionSeq = 0 },
		"digest":           func(r *OwnerTextProjectMessageReceipt) { r.RequestDigest = make([]byte, 32) },
		"status":           func(r *OwnerTextProjectMessageReceipt) { r.Status = "unknown" },
		"createdAt":        func(r *OwnerTextProjectMessageReceipt) { r.CreatedAt = time.Time{} },
		"created timezone": func(r *OwnerTextProjectMessageReceipt) { r.CreatedAt = r.CreatedAt.In(time.FixedZone("offset", 3600)) },
		"pending ack":      func(r *OwnerTextProjectMessageReceipt) { stamp := r.CreatedAt; r.AcknowledgedAt = &stamp },
		"missing ack":      func(r *OwnerTextProjectMessageReceipt) { r.Status = "acknowledged" },
		"earlier ack": func(r *OwnerTextProjectMessageReceipt) {
			r.Status = "acknowledged"
			stamp := r.CreatedAt.Add(-time.Second)
			r.AcknowledgedAt = &stamp
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newOwnerTextTransportFixture(t)
			c := f.clients[0]
			prepared, err := c.PrepareOwnerTextProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.mutateReceipt = mutate
			if _, err = c.SendPreparedOwnerTextProjectMessage(context.Background(), f.project, prepared.ID); err == nil {
				t.Fatal("wrong receipt accepted")
			}
			if _, err = c.LoadPreparedOwnerTextProjectMessage(f.project, prepared.ID); err != nil {
				t.Fatal("receipt failure lost retry wire")
			}
			if _, err = c.OwnerTextProjectMessageReceipt(context.Background(), f.project, prepared.ID); err == nil {
				t.Fatal("wrong reconciliation receipt accepted")
			}
		})
	}
}
func TestOwnerTextTransportReproofAndLiveAuthority(t *testing.T) {
	f := newOwnerTextTransportFixture(t)
	c := f.clients[0]
	prepared, err := c.PrepareOwnerTextProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.status.Roles[0].Ready = false
	f.status.PrincipalsProved = 1
	f.status.EndpointProved = false
	f.status.Ready = false
	if _, err = c.SendPreparedOwnerTextProjectMessage(context.Background(), f.project, prepared.ID); err != nil || f.proofs != 1 {
		t.Fatalf("reproof: %v proofs=%d", err, f.proofs)
	}
	f.mutateStatus = func(s *OwnerTextProjectStatus) { s.State = "revoked" }
	if _, err = c.OwnerTextProjectMessageReceipt(context.Background(), f.project, prepared.ID); err == nil {
		t.Fatal("receipt permitted after revoked authority")
	}
	if f.receipts != 0 {
		t.Fatal("revoked authority reached receipt endpoint")
	}
}
func TestOwnerTextTransportRejectsConnectionOrPinChange(t *testing.T) {
	for _, kind := range []string{"status generation", "send generation", "receipt generation", "credential", "descriptor", "proof installation"} {
		t.Run(kind, func(t *testing.T) {
			f := newOwnerTextTransportFixture(t)
			c := f.clients[0]
			prepared, err := c.PrepareOwnerTextProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "descriptor" {
				f.mutateStatus = func(s *OwnerTextProjectStatus) { s.DescriptorHash = make([]byte, 32) }
			}
			if kind == "proof installation" {
				f.mutateStatus = func(s *OwnerTextProjectStatus) { s.Roles[0].InstallationID = uuid.NewString() }
			}
			f.beforeResponse = func(stage string) {
				if (kind == "status generation" && stage == "status") || (kind == "send generation" && stage == "send") || (kind == "receipt generation" && stage == "receipt") {
					c.connGeneration.Add(1)
				}
				if kind == "credential" && stage == "status" {
					c.credential.Store("pgn_epd_v1_rotated")
				}
			}
			if kind == "receipt generation" {
				f.loseSend = true
			}
			if _, err = c.SendPreparedOwnerTextProjectMessage(context.Background(), f.project, prepared.ID); err == nil {
				t.Fatal("changed session or pin accepted")
			}
			if _, err = c.LoadPreparedOwnerTextProjectMessage(f.project, prepared.ID); err != nil {
				t.Fatal("changed session retired retry wire")
			}
			if (kind == "status generation" || kind == "credential" || kind == "descriptor" || kind == "proof installation") && f.posts != 0 {
				t.Fatal("invalid authority reached POST")
			}
		})
	}
}
func TestOwnerTextTransportInboxCursorAndExplicitACK(t *testing.T) {
	f := newOwnerTextTransportFixture(t)
	sender, responder := f.clients[0], f.clients[1]
	prepared, err := sender.PrepareOwnerTextProjectMessage(f.project, responder.PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.inbox = []json.RawMessage{prepared.Wire}
	f.nextCursor = "7"
	page, err := responder.OwnerTextProjectInbox(context.Background(), f.project, "", 1)
	if err != nil || len(page.Messages) != 1 || !bytes.Equal(page.Messages[0], prepared.Wire) || page.NextCursor != "7" || f.acks != 0 {
		t.Fatalf("inbox: %+v %v", page, err)
	}
	f.inbox = []json.RawMessage{}
	f.nextCursor = ""
	if _, err = responder.OwnerTextProjectInbox(context.Background(), f.project, "7", 1); err != nil {
		t.Fatal(err)
	}
	if len(f.cursors) != 2 || f.cursors[1] != "7" {
		t.Fatal("cursor query missing")
	}
	f.failACK = true
	if err = responder.AckOwnerTextProjectMessage(context.Background(), f.project, prepared.ID); err == nil {
		t.Fatal("failed ACK accepted")
	}
	f.failACK = false
	if err = responder.AckOwnerTextProjectMessage(context.Background(), f.project, prepared.ID); err != nil || f.acks != 2 {
		t.Fatal(err)
	}
	for _, cursor := range []string{"0", "01", "-1", "+1", "9223372036854775808"} {
		if _, err = responder.OwnerTextProjectInbox(context.Background(), f.project, cursor, 1); err == nil {
			t.Fatalf("invalid cursor accepted: %s", cursor)
		}
	}
	for _, limit := range []int{-1, 101} {
		if _, err = responder.OwnerTextProjectInbox(context.Background(), f.project, "", limit); err == nil {
			t.Fatal("invalid limit accepted")
		}
	}
	for _, next := range []string{"0", "01", "-1", "7"} {
		f.inbox = []json.RawMessage{prepared.Wire}
		f.nextCursor = next
		if _, err = responder.OwnerTextProjectInbox(context.Background(), f.project, "7", 1); err == nil {
			t.Fatalf("invalid next cursor accepted: %s", next)
		}
	}
	f.inbox = []json.RawMessage{prepared.Wire, prepared.Wire}
	f.nextCursor = ""
	if _, err = responder.OwnerTextProjectInbox(context.Background(), f.project, "", 1); err == nil {
		t.Fatal("oversized page accepted")
	}
	f.inbox = []json.RawMessage{prepared.Wire}
	if _, err = sender.OwnerTextProjectInbox(context.Background(), f.project, "", 1); err == nil {
		t.Fatal("wrong recipient inbox accepted")
	}
}
func TestOwnerTextTransportQuotaPreservesPreparedBytes(t *testing.T) {
	for _, code := range []int{413, 409, 429} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			f := newOwnerTextTransportFixture(t)
			c := f.clients[0]
			prepared, err := c.PrepareOwnerTextProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.quota = code
			_, err = c.SendPreparedOwnerTextProjectMessage(context.Background(), f.project, prepared.ID)
			var quota *OwnerTextProjectMessageQuotaError
			if !errors.As(err, &quota) || quota.StatusCode != code || quota.RetryAfter != "5" || quota.Limit != "maxInFlight" || quota.Maximum != 2 {
				t.Fatalf("quota: %v", err)
			}
			loaded, err := c.LoadPreparedOwnerTextProjectMessage(f.project, prepared.ID)
			if err != nil || !bytes.Equal(loaded.Wire, prepared.Wire) || f.receipts != 0 {
				t.Fatal("quota changed retry bytes or reconciled definitive failure")
			}
		})
	}
}

func TestOwnerTextTransportAcknowledgedReceipt(t *testing.T) {
	f := newOwnerTextTransportFixture(t)
	c := f.clients[0]
	prepared, err := c.PrepareOwnerTextProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.mutateReceipt = func(r *OwnerTextProjectMessageReceipt) {
		r.Status = "acknowledged"
		stamp := r.CreatedAt.Add(time.Second)
		r.AcknowledgedAt = &stamp
	}
	receipt, err := c.SendPreparedOwnerTextProjectMessage(context.Background(), f.project, prepared.ID)
	if err != nil || receipt.Status != "acknowledged" {
		t.Fatalf("acknowledged receipt: %v", err)
	}
}

func TestOwnerTextTransportAllowsOfflinePeer(t *testing.T) {
	for _, operation := range []string{"send", "receipt", "inbox", "ack"} {
		t.Run(operation, func(t *testing.T) {
			f := newOwnerTextTransportFixture(t)
			caller := f.clients[0]
			prepared, err := caller.PrepareOwnerTextProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.wire = prepared.Wire
			f.status.Roles[1].Ready = false
			f.status.PrincipalsProved = 1
			f.status.Ready = false
			switch operation {
			case "send":
				_, err = caller.SendPreparedOwnerTextProjectMessage(context.Background(), f.project, prepared.ID)
			case "receipt":
				_, err = caller.OwnerTextProjectMessageReceipt(context.Background(), f.project, prepared.ID)
			case "inbox":
				_, err = caller.OwnerTextProjectInbox(context.Background(), f.project, "", 1)
			case "ack":
				err = caller.AckOwnerTextProjectMessage(context.Background(), f.project, prepared.ID)
			}
			if err != nil {
				t.Fatalf("offline peer blocked caller's %s: %v", operation, err)
			}
		})
	}
}
