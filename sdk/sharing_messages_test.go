package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

type sharingMessageFixture struct {
	pair              *pairRESTFixture
	messages          map[string]pairMessageWire
	canonical         map[string][]byte
	acked             map[string]bool
	loseSend          bool
	wrongReceipt      bool
	quota             bool
	quotaCode         int
	quotaLimit        string
	receiptHTTPStatus int
	revokeOnReceipt   bool
	pageSize          int
	tamperInbox       bool
	sends             int
	acks              int
}

func sharingMessageClients(t *testing.T) (*sharingMessageFixture, *Client, *Client) {
	t.Helper()
	f, i, r := pairRESTClients(t)
	f.status.Limits.MaxMessageWireBytes = 4096
	ctx := context.Background()
	for _, c := range []*Client{i, r, i, r, i} {
		if _, err := c.EnrollSharingPair(ctx, "grant"); err != nil {
			t.Fatal(err)
		}
	}
	f.server.Close()
	m := &sharingMessageFixture{pair: f, messages: map[string]pairMessageWire{}, canonical: map[string][]byte{}, acked: map[string]bool{}}
	server := httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(server.Close)
	i.rest.base = server.URL + "/api/v1"
	r.rest.base = i.rest.base
	return m, i, r
}
func (f *sharingMessageFixture) serve(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.URL.Path, "/messages") {
		f.pair.serve(w, r)
		return
	}
	principal := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer pgn_epd_v1_")
	write := func(value any) {
		if err := json.NewEncoder(w).Encode(value); err != nil {
			f.pair.t.Error(err)
		}
	}
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/messages") {
		var body struct {
			pairMessageWire
			EndpointID string `json:"endpointId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.pair.t.Error(err)
			w.WriteHeader(400)
			return
		}
		if body.EndpointID == "" {
			f.pair.t.Error("missing endpoint")
		}
		if f.quota {
			w.Header().Set("Retry-After", "5")
			code, limit := f.quotaCode, f.quotaLimit
			if code == 0 {
				code = 429
			}
			if limit == "" {
				limit = "maxInFlight"
			}
			w.WriteHeader(code)
			body := map[string]any{"error": "sharing_pair_quota_exceeded", "limit": limit, "max": 2}
			if limit == "ownerBudget" {
				delete(body, "max")
				body["scope"] = "owner"
				body["resetAt"] = time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
			}
			write(body)
			return
		}
		wire := body.pairMessageWire
		wire.Version = 1
		wire.GrantID = f.pair.status.GrantID
		wire.NetworkID = f.pair.status.NetworkID
		wire.SenderPrincipalID = principal
		raw, _ := json.Marshal(wire)
		if old, exists := f.canonical[wire.ID]; exists && !bytes.Equal(old, raw) {
			f.pair.t.Error("retry changed canonical wire")
			w.WriteHeader(409)
			return
		}
		f.messages[wire.ID] = wire
		f.canonical[wire.ID] = raw
		f.sends++
		if f.loseSend {
			f.loseSend = false
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(201)
		write(map[string]string{"ID": wire.ID})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/inbox") {
		page := []pairMessageWire{}
		for _, wire := range f.messages {
			if wire.RecipientPrincipalID == principal && !f.acked[wire.ID] && wire.ID > r.URL.Query().Get("cursor") {
				if f.tamperInbox {
					wire.AAD.TenantID = "wrong"
				}
				page = append(page, wire)
			}
		}
		sort.Slice(page, func(i, j int) bool { return page[i].ID < page[j].ID })
		if f.pageSize > 0 && len(page) > f.pageSize {
			page = page[:f.pageSize]
			w.Header().Set("X-Next-Cursor", page[len(page)-1].ID)
		}
		write(page)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/receipt") && f.receiptHTTPStatus != 0 {
		if f.revokeOnReceipt {
			f.pair.status.State = "revoked"
		}
		w.WriteHeader(f.receiptHTTPStatus)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-2]
	wire, exists := f.messages[id]
	if !exists {
		w.WriteHeader(404)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/receipt") {
		if wire.SenderPrincipalID != principal {
			w.WriteHeader(404)
			return
		}
		digest := sha256.Sum256(f.canonical[id])
		if f.wrongReceipt {
			digest[0]++
		}
		status := "pending"
		if f.acked[id] {
			status = "acknowledged"
		}
		write(SharingMessageReceipt{MessageID: id, RequestDigest: digest[:], Status: status})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/ack") {
		if wire.RecipientPrincipalID != principal {
			w.WriteHeader(404)
			return
		}
		f.acked[id] = true
		f.acks++
		w.WriteHeader(204)
		return
	}
	http.NotFound(w, r)
}

func TestSharingMessagesTwoPrincipalsAndAck(t *testing.T) {
	f, i, r := sharingMessageClients(t)
	ctx := context.Background()
	prepared, err := i.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("private question")}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := i.SendPreparedSharingMessage(ctx, prepared)
	if err != nil || receipt.Status != "pending" {
		t.Fatalf("send: %v", err)
	}
	if bytes.Contains(f.canonical[prepared.MessageID], []byte("private question")) {
		t.Fatal("plaintext crossed wire")
	}
	if _, err := i.SendPreparedSharingMessage(ctx, prepared); err != nil {
		t.Fatal("repeat admitted send", err)
	}
	if f.sends != 1 {
		t.Fatal("retired handle resent ciphertext")
	}
	var incoming SharingMessage
	if err := r.ReceiveSharingMessages(ctx, "grant", func(_ context.Context, m SharingMessage) error { incoming = m; return errors.New("handler failed") }); err == nil {
		t.Fatal("handler failure lost")
	}
	if f.acks != 0 {
		t.Fatal("ACK before handler success")
	}
	if err := r.ReceiveSharingMessages(ctx, "grant", func(_ context.Context, m SharingMessage) error { panic("failure") }); err == nil {
		t.Fatal("handler panic lost")
	}
	if f.acks != 0 {
		t.Fatal("ACK after panic")
	}
	f.tamperInbox = true
	if err := r.ReceiveSharingMessages(ctx, "grant", func(context.Context, SharingMessage) error { t.Fatal("tampered AAD reached handler"); return nil }); err == nil {
		t.Fatal("tampered AAD accepted")
	}
	f.tamperInbox = false
	if err := r.ReceiveSharingMessages(ctx, "grant", func(_ context.Context, m SharingMessage) error {
		incoming = m
		if m.TextBody() != "private question" {
			t.Fatal("wrong plaintext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if f.acks != 1 {
		t.Fatal("missing dedicated ACK")
	}
	reply, err := r.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("private reply")}, ReplyTo: &incoming})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.SendPreparedSharingMessage(ctx, reply); err != nil {
		t.Fatal(err)
	}
	if err := i.ReceiveSharingMessages(ctx, "grant", func(_ context.Context, m SharingMessage) error {
		if m.Kind != "REPLY" || m.ThreadID != incoming.ThreadID || m.CorrelationID == nil || *m.CorrelationID != incoming.ID || m.TextBody() != "private reply" {
			t.Fatal("reply binding")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if f.acks != 2 {
		t.Fatal("reply not ACKed")
	}
	forged := SharingMessage{GrantID: "grant", Message: Message{ID: incoming.ID, ThreadID: incoming.ThreadID}}
	if _, err := r.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("reply")}, ReplyTo: &forged}); err == nil {
		t.Fatal("forged predecessor accepted")
	}
}

func TestSharingMessagesExactRetryReconnectAndReceipt(t *testing.T) {
	f, i, _ := sharingMessageClients(t)
	ctx := context.Background()
	request := SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("retry input")}}
	p, err := i.PrepareSharingMessage(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	request.MessageID = p.MessageID
	f.loseSend = true
	if _, err := i.SendPreparedSharingMessage(ctx, p); err == nil {
		t.Fatal("lost response hidden")
	}
	original := append([]byte(nil), f.canonical[p.MessageID]...)
	handles, err := i.UnresolvedSharingMessages()
	if err != nil || len(handles) != 1 {
		t.Fatalf("lost unresolved state %v", err)
	}
	i.connGeneration.Add(1)
	i.endpointID.Store("issuer-reconnected")
	if _, err := i.SendPreparedSharingMessage(ctx, handles[0]); err == nil {
		t.Fatal("sent without reconnect proof")
	}
	if _, err := i.EnrollSharingPair(ctx, "grant"); err != nil {
		t.Fatal(err)
	}
	// A generic network epoch with a higher name must not replace activation.
	if err := i.kr.StoreEpoch("network", "zzzz-newer-epoch", [32]byte{99}); err != nil {
		t.Fatal(err)
	}
	repeated, err := i.PrepareSharingMessage(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.state.WireDigest != p.state.WireDigest {
		t.Fatal("retry reencrypted")
	}
	f.wrongReceipt = true
	if _, err := i.SendPreparedSharingMessage(ctx, repeated); err == nil {
		t.Fatal("wrong receipt accepted")
	}
	if !bytes.Equal(original, f.canonical[p.MessageID]) {
		t.Fatal("reconnect changed exact wire")
	}
	handles, err = i.UnresolvedSharingMessages()
	if err != nil || len(handles) != 1 {
		t.Fatalf("wrong receipt deleted record %v", err)
	}
	f.wrongReceipt = false
	if _, err := i.GetSharingMessageReceipt(ctx, handles[0]); err != nil {
		t.Fatal(err)
	}
	handles, err = i.UnresolvedSharingMessages()
	if err != nil || len(handles) != 0 {
		t.Fatalf("confirmed admission retained wire %v", err)
	}
	request.Parts = []MessagePart{TextPart("changed input")}
	if _, err := i.PrepareSharingMessage(ctx, request); err == nil {
		t.Fatal("retired ID rebound")
	}
}

func TestSharingMessagesQuotaAndReservationFailClosed(t *testing.T) {
	f, i, _ := sharingMessageClients(t)
	ctx := context.Background()
	p, err := i.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("quota")}})
	if err != nil {
		t.Fatal(err)
	}
	f.quota = true
	_, err = i.SendPreparedSharingMessage(ctx, p)
	var quota *SharingMessageQuotaError
	if !errors.As(err, &quota) || quota.Limit != "maxInFlight" || quota.Maximum != 2 || quota.RetryAfter != "5" || quota.Error() != "sdk: sharing message quota maxInFlight exceeded (maximum 2)" {
		t.Fatalf("quota not surfaced: %v", err)
	}
	handles, err := i.UnresolvedSharingMessages()
	if err != nil || len(handles) != 1 {
		t.Fatalf("quota deleted record: %v", err)
	}
	f.pair.status.State = "revoked"
	if _, err := i.SendPreparedSharingMessage(ctx, p); err == nil {
		t.Fatal("revoked pair sent")
	}
	handles, err = i.UnresolvedSharingMessages()
	if err != nil || len(handles) != 1 {
		t.Fatalf("revocation deleted record: %v", err)
	}
}

func TestSharingMessagesOwnerBudget(t *testing.T) {
	f, c, _ := sharingMessageClients(t)
	ctx := context.Background()
	prepared, err := c.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("owner budget")}})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := c.kr.loadPairMessage(prepared.state.Binding)
	if err != nil {
		t.Fatal(err)
	}
	f.quota, f.quotaLimit = true, "ownerBudget"
	_, err = c.SendPreparedSharingMessage(ctx, prepared)
	var quota *SharingMessageQuotaError
	reset := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	if !errors.As(err, &quota) || quota.Limit != "ownerBudget" || quota.StatusCode != 429 || quota.Maximum != 0 || quota.RetryAfter != "5" || quota.ResetAt == nil || !quota.ResetAt.Equal(reset) {
		t.Fatalf("owner budget detail: %v", err)
	}
	if quota.Error() != "Sharing owner budget exhausted" {
		t.Fatalf("owner budget presentation: %q", quota.Error())
	}
	handles, err := c.UnresolvedSharingMessages()
	if err != nil || len(handles) != 1 || !handles[0].CanRetry() {
		t.Fatalf("owner budget lost retryable reservation: %v", err)
	}
	retained, err := c.kr.loadPairMessage(prepared.state.Binding)
	if err != nil || !bytes.Equal(retained, wire) {
		t.Fatalf("owner budget changed durable wire: %v", err)
	}
	f.quota = false
	if _, err := c.SendPreparedSharingMessage(ctx, handles[0]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.canonical[prepared.MessageID], wire) {
		t.Fatal("owner budget retry changed wire")
	}
}

func TestSharingMessagesPermanentRejectionAndAmbiguousAuthority(t *testing.T) {
	for _, tc := range []struct {
		name         string
		code         int
		limit        string
		receipt      int
		revoke       bool
		wantRetained bool
	}{
		{"wire", 413, "maxMessageWireBytes", 404, false, false},
		{"turns", 409, "maxTurnsPerThread", 404, false, false},
		{"revoked-hidden", 413, "maxMessageWireBytes", 404, true, true},
		{"receipt-unavailable", 413, "maxMessageWireBytes", 503, false, true},
		{"unknown-conflict", 409, "other", 404, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, i, _ := sharingMessageClients(t)
			ctx := context.Background()
			p, err := i.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("rejection")}})
			if err != nil {
				t.Fatal(err)
			}
			f.quota = true
			f.quotaCode = tc.code
			f.quotaLimit = tc.limit
			f.receiptHTTPStatus = tc.receipt
			f.revokeOnReceipt = tc.revoke
			if _, err := i.SendPreparedSharingMessage(ctx, p); err == nil {
				t.Fatal("rejection hidden")
			}
			unresolved, err := i.UnresolvedSharingMessages()
			if err != nil {
				t.Fatal(err)
			}
			if (len(unresolved) == 1) != tc.wantRetained {
				t.Fatalf("retained %d want retained=%v", len(unresolved), tc.wantRetained)
			}
			if !tc.wantRetained {
				f.quota = false
				if _, err := i.SendPreparedSharingMessage(ctx, p); err == nil {
					t.Fatal("rejected handle resent")
				}
				b := p.state.Binding
				b.InputDigest[0]++
				if _, _, err := i.kr.reservePairMessage(b); err == nil {
					t.Fatal("rejected ID rebound")
				}
			}
		})
	}
	// A permanent rejection on a retry must still recover an earlier admission.
	f, i, _ := sharingMessageClients(t)
	ctx := context.Background()
	p, err := i.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("admitted before lost response")}})
	if err != nil {
		t.Fatal(err)
	}
	f.loseSend = true
	if _, err := i.SendPreparedSharingMessage(ctx, p); err == nil {
		t.Fatal("lost send hidden")
	}
	f.quota = true
	f.quotaCode = 413
	f.quotaLimit = "maxMessageWireBytes"
	if receipt, err := i.SendPreparedSharingMessage(ctx, p); err != nil || receipt.Status != "pending" {
		t.Fatalf("earlier admission lost: %v", err)
	}
}

func TestSharingMessagesOversizeAndExplicitIncompleteAbort(t *testing.T) {
	f, i, _ := sharingMessageClients(t)
	ctx := context.Background()
	// Plaintext alone exceeds the wire limit: reject before reserving.
	huge := strings.Repeat("x", f.pair.status.Limits.MaxMessageWireBytes+1)
	if _, err := i.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart(huge)}}); err == nil {
		t.Fatal("oversized plaintext prepared")
	}
	// Encryption/base64/metadata expansion exceeds the limit: reject the reserved
	// ID with a durable tombstone instead of consuming outstanding capacity.
	expanded := strings.Repeat("x", f.pair.status.Limits.MaxMessageWireBytes*3/4)
	p, err := i.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart(expanded)}})
	if err == nil || p.MessageID == "" {
		t.Fatal("wire expansion was not rejected after reservation")
	}
	unresolved, err := i.UnresolvedSharingMessages()
	if err != nil || len(unresolved) != 0 {
		t.Fatalf("oversize consumed spool capacity: %v", err)
	}
	if _, err := i.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", MessageID: p.MessageID, Parts: []MessagePart{TextPart("different")}}); err == nil {
		t.Fatal("oversize ID rebound")
	}
	b, abortWire := spoolInput(t)
	b.PrincipalID = i.PrincipalID()
	var abortRequest pairMessageWire
	json.Unmarshal(abortWire, &abortRequest)
	abortRequest.SenderPrincipalID = b.PrincipalID
	abortWire, _ = json.Marshal(abortRequest)
	state, _, err := i.kr.reservePairMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	incomplete := PreparedSharingMessage{MessageID: b.MessageID, state: state}
	if incomplete.CanRetry() {
		t.Fatal("incomplete handle permits retry")
	}
	if err := i.AbortPreparedSharingMessage(incomplete); err != nil {
		t.Fatal(err)
	}
	if err := i.AbortPreparedSharingMessage(incomplete); err != nil {
		t.Fatal("abort not idempotent", err)
	}
	if _, err := i.kr.storePairMessage(b, abortWire, sha256.Sum256(abortWire)); err == nil {
		t.Fatal("aborted reservation recreated")
	}
	unresolved, err = i.UnresolvedSharingMessages()
	if err != nil || len(unresolved) != 0 {
		t.Fatalf("abort consumed spool capacity: %v", err)
	}
	ready, err := i.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("ready")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := i.AbortPreparedSharingMessage(ready); err == nil {
		t.Fatal("finalized possibly sent ciphertext aborted without receipt")
	}
}

func TestSharingMessagesInboxPagination(t *testing.T) {
	f, i, r := sharingMessageClients(t)
	ctx := context.Background()
	f.pageSize = 1
	for n := 0; n < 2; n++ {
		p, err := i.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("page")}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := i.SendPreparedSharingMessage(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	handled := 0
	if err := r.ReceiveSharingMessages(ctx, "grant", func(context.Context, SharingMessage) error { handled++; return nil }); err != nil {
		t.Fatal(err)
	}
	if handled != 2 || f.acks != 2 {
		t.Fatalf("pagination handled=%d acked=%d", handled, f.acks)
	}
}

func TestSharingMessagesAuthenticatedCausality(t *testing.T) {
	f, i, r := sharingMessageClients(t)
	ctx := context.Background()
	ask, err := i.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("ask")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.SendPreparedSharingMessage(ctx, ask); err != nil {
		t.Fatal(err)
	}
	var incoming SharingMessage
	if err := r.ReceiveSharingMessages(ctx, "grant", func(_ context.Context, m SharingMessage) error { incoming = m; return nil }); err != nil {
		t.Fatal(err)
	}
	reply, err := r.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("reply")}, ReplyTo: &incoming})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.SendPreparedSharingMessage(ctx, reply); err != nil {
		t.Fatal(err)
	}
	original := f.messages[reply.MessageID]
	for _, field := range []string{"kind", "thread", "correlation"} {
		t.Run(field, func(t *testing.T) {
			wire := original
			other, _ := spoolInput(t)
			switch field {
			case "kind":
				wire.Kind = "ASK"
				wire.ThreadID = wire.ID
				wire.CorrelationID = nil
			case "thread":
				wire.ThreadID = other.MessageID
			case "correlation":
				wire.CorrelationID = &other.MessageID
			}
			// These altered outer requests remain structurally valid. The ciphertext
			// must reject their causality independently of outer-field validation.
			session, err := i.sharingMessageSession(ctx, "grant")
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSharingWire(wire, session, true); err != nil {
				t.Fatal("tamper test not structurally valid", err)
			}
			f.messages[reply.MessageID] = wire
			if err := i.ReceiveSharingMessages(ctx, "grant", func(context.Context, SharingMessage) error { t.Fatal("tampered causality reached handler"); return nil }); err == nil {
				t.Fatal("tampered causality decrypted")
			}
			if f.acks != 1 {
				t.Fatal("tampered causality ACKed")
			}
		})
	}
	f.messages[reply.MessageID] = original
	if err := i.ReceiveSharingMessages(ctx, "grant", func(context.Context, SharingMessage) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
