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
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func TestPreparedMessageAmbiguousTimeoutRestart(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("prepared", true)
	principal, credential := fs.createPrincipal("service", "sender", network)
	target, _ := fs.createPrincipal("agent", "target", network)
	state := t.TempDir()
	c := mustConnect(t, fs, credential, state)
	waitForCryptoReady(t, fs, principal)
	var mu sync.Mutex
	var requests [][]byte
	received := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, raw)
		first := len(requests) == 1
		mu.Unlock()
		if first {
			close(received)
			<-r.Context().Done()
			return
		}
		var req restMessageRequest
		_ = json.Unmarshal(raw, &req)
		_ = json.NewEncoder(w).Encode(map[string]string{"ID": req.ID})
	}))
	defer server.Close()
	c.rest.base = server.URL
	id := domain.NewID().String()
	m := OutgoingMessage{ID: id, NetworkID: network, RecipientPrincipalID: target, Parts: []MessagePart{TextPart("private durable question")}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-received; cancel() }()
	got, err := c.Send(ctx, m)
	if err == nil || got != id {
		t.Fatalf("ambiguous send = %q, %v", got, err)
	}
	path, _ := c.preparedMessagePath(network, id)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("private durable question")) {
		t.Fatal("plaintext persisted")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("file permissions", info.Mode())
	}
	info, _ = os.Stat(filepath.Dir(path))
	if info.Mode().Perm() != 0700 {
		t.Fatal("directory permissions", info.Mode())
	}
	// Reconnect from disk, including a new keyring and restored identity.
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := mustConnect(t, fs, credential, state)
	restarted.rest.base = server.URL
	// Replay does not depend on a current enrollment, tenant lookup, or encryption.
	restarted.networkTenants = sync.Map{}
	if got, err := restarted.SendPrepared(context.Background(), network, id); err != nil || got != id {
		t.Fatalf("replay = %q, %v", got, err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("saved ciphertext changed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) {
		t.Fatal("replay request bytes differ")
	}
	var req restMessageRequest
	_ = json.Unmarshal(requests[1], &req)
	if req.ID != id || req.ThreadID != id || req.AAD.ObjectID != id || req.AAD.Sender != principal || req.AAD.Recipient != target {
		t.Fatal("incorrect request identity")
	}
}

func TestPreparedMessageConflictTamperAndBindings(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("prepared", true)
	principal, credential := fs.createPrincipal("service", "sender", network)
	target, _ := fs.createPrincipal("agent", "target", network)
	c := mustConnect(t, fs, credential, t.TempDir())
	waitForCryptoReady(t, fs, principal)
	ctx := context.Background()
	m := OutgoingMessage{ID: domain.NewID().String(), NetworkID: network, RecipientPrincipalID: target, Parts: []MessagePart{TextPart("original")}}
	first, err := c.PrepareMessage(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.PrepareMessage(ctx, m)
	if err != nil || again != first {
		t.Fatalf("identical preparation = %#v %v", again, err)
	}
	changed := m
	changed.Parts = []MessagePart{TextPart("changed")}
	if _, err := c.PrepareMessage(ctx, changed); err == nil {
		t.Fatal("conflicting content accepted")
	}
	changed = m
	changed.ThreadID = domain.NewID().String()
	if _, err := c.PrepareMessage(ctx, changed); err == nil {
		t.Fatal("conflicting thread accepted")
	}
	changed = m
	changed.RecipientPrincipalID = domain.NewID().String()
	if _, err := c.PrepareMessage(ctx, changed); err == nil {
		t.Fatal("conflicting recipient accepted")
	}
	changed = m
	changed.NetworkID = domain.NewID().String()
	if _, err := c.PrepareMessage(ctx, changed); err == nil {
		t.Fatal("cross network reuse accepted")
	}
	if _, err := c.SendPrepared(ctx, changed.NetworkID, m.ID); err == nil {
		t.Fatal("cross network replay accepted")
	}
	path, _ := c.preparedMessagePath(network, m.ID)
	original, _ := os.ReadFile(path)
	var saved savedMessage
	_ = json.Unmarshal(original, &saved)
	saved.Request.ThreadID = domain.NewID().String()
	tampered, _ := json.Marshal(saved)
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SendPrepared(ctx, network, m.ID); err == nil {
		t.Fatal("tampered routing replayed")
	}
	if _, err := c.PrepareMessage(ctx, m); err == nil {
		t.Fatal("tampered cache overwritten")
	}
	_ = json.Unmarshal(original, &saved)
	saved.Request.Envelope.Ciphertext = "tampered"
	tampered, _ = json.Marshal(saved)
	_ = os.WriteFile(path, tampered, 0600)
	if _, err := c.SendPrepared(ctx, network, m.ID); err == nil {
		t.Fatal("tampered ciphertext replayed")
	}
	_ = os.WriteFile(path, original, 0600)
	foreign := &Client{kr: c.kr, identityPriv: c.identityPriv}
	foreign.principalID.Store(domain.NewID().String())
	foreignPath, _ := foreign.preparedMessagePath(network, m.ID)
	if err := os.MkdirAll(filepath.Dir(foreignPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreignPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.SendPrepared(ctx, network, m.ID); err == nil {
		t.Fatal("cross principal replay accepted")
	}
}

func TestPreparedMessageReplyAndValidation(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("prepared", true)
	principal, credential := fs.createPrincipal("service", "sender", network)
	target, _ := fs.createPrincipal("agent", "target", network)
	c := mustConnect(t, fs, credential, t.TempDir())
	waitForCryptoReady(t, fs, principal)
	ctx := context.Background()
	thread, correlation := domain.NewID().String(), domain.NewID().String()
	m := OutgoingMessage{NetworkID: network, RecipientPrincipalID: target, Kind: "REPLY", ThreadID: thread, CorrelationID: correlation, Parts: []MessagePart{TextPart("reply")}}
	p, err := c.PrepareMessage(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || p.ThreadID != thread || p.CorrelationID != correlation {
		t.Fatal("reply identity lost", p)
	}
	path, _ := c.preparedMessagePath(network, p.ID)
	saved, err := c.loadPreparedMessage(path, network, p.ID)
	if err != nil || saved.Request.ThreadID != thread || saved.Request.CorrelationID != correlation {
		t.Fatal("saved reply identity lost", err)
	}
	cases := []struct {
		name   string
		change func(*OutgoingMessage)
	}{
		{"network", func(m *OutgoingMessage) { m.NetworkID = "../escape" }},
		{"id", func(m *OutgoingMessage) { m.ID = "bad" }},
		{"recipient", func(m *OutgoingMessage) { m.RecipientPrincipalID = "" }},
		{"group", func(m *OutgoingMessage) { m.RecipientGroupID = target }},
		{"kind", func(m *OutgoingMessage) { m.Kind = "NOTICE" }},
		{"thread", func(m *OutgoingMessage) { m.ThreadID = "" }},
		{"correlation", func(m *OutgoingMessage) { m.CorrelationID = "" }},
		{"bad correlation", func(m *OutgoingMessage) { m.CorrelationID = "bad" }},
		{"parts", func(m *OutgoingMessage) { m.Parts = nil }},
		{"oversize", func(m *OutgoingMessage) { m.Parts = []MessagePart{TextPart(string(bytes.Repeat([]byte("x"), 65<<10)))} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := m
			tc.change(&bad)
			if _, err := c.PrepareMessage(ctx, bad); err == nil {
				t.Fatal("invalid preparation accepted")
			}
		})
	}
}
