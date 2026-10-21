package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	replay := &Client{kr: restarted.kr, identityPriv: restarted.identityPriv, rest: restarted.rest}
	replay.principalID.Store(restarted.PrincipalID())
	if got, err := replay.SendPrepared(context.Background(), network, id); err != nil || got != id {
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

func TestPreparedMessageDirectorySyncFailure(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("prepared", true)
	principal, credential := fs.createPrincipal("service", "sender", network)
	target, _ := fs.createPrincipal("agent", "target", network)
	c := mustConnect(t, fs, credential, t.TempDir())
	waitForCryptoReady(t, fs, principal)
	ctx := context.Background()
	fault := errors.New("directory sync failed")
	for _, mode := range []string{"publish", "cached", "link loser", "send"} {
		for failAt := 0; failAt < 4; failAt++ {
			t.Run(fmt.Sprintf("%s/directory%d", mode, failAt), func(t *testing.T) {
				m := OutgoingMessage{ID: domain.NewID().String(), NetworkID: network, RecipientPrincipalID: target, Parts: []MessagePart{TextPart("durable")}}
				path, _ := c.preparedMessagePath(network, m.ID)
				if mode == "cached" || mode == "send" {
					if _, err := c.PrepareMessage(ctx, m); err != nil {
						t.Fatal(err)
					}
				}
				oldSync, oldLink := preparedMessageSyncDir, preparedMessageLink
				defer func() { preparedMessageSyncDir, preparedMessageLink = oldSync, oldLink }()
				if mode == "link loser" {
					preparedMessageLink = func(from, to string) error {
						// Another process publishes this exact entry but has not
						// synced its directories when our link loses the race.
						if err := os.Link(from, to); err != nil {
							return err
						}
						return &os.LinkError{Op: "link", Old: from, New: to, Err: os.ErrExist}
					}
				}
				wantDirs := []string{filepath.Dir(path), filepath.Dir(filepath.Dir(path)), c.kr.root, filepath.Dir(c.kr.root)}
				calls := 0
				preparedMessageSyncDir = func(dir string) error {
					if dir != wantDirs[calls] {
						t.Fatalf("sync directory = %q, want %q", dir, wantDirs[calls])
					}
					calls++
					if calls == failAt+1 {
						return fault
					}
					return oldSync(dir)
				}
				if mode == "send" {
					// No REST client: reaching the network before syncing would panic.
					replay := &Client{kr: c.kr, identityPriv: c.identityPriv}
					replay.principalID.Store(principal)
					if _, err := replay.SendPrepared(ctx, network, m.ID); !errors.Is(err, fault) {
						t.Fatalf("send error = %v", err)
					}
				} else if p, err := c.PrepareMessage(ctx, m); !errors.Is(err, fault) || p.ID != "" {
					t.Fatalf("prepare = %#v, %v", p, err)
				}
				if calls != failAt+1 {
					t.Fatalf("sync calls = %d, want %d", calls, failAt+1)
				}
				// A failed publisher left an observable entry. Retrying must
				// finish syncing it before it can return success.
				preparedMessageSyncDir, preparedMessageLink = oldSync, oldLink
				if p, err := c.PrepareMessage(ctx, m); err != nil || p.ID != m.ID {
					t.Fatalf("recovery = %#v, %v", p, err)
				}
			})
		}
	}
}

func TestSendWithoutIDDoesNotConsumePreparedHistory(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("prepared", true)
	principal, credential := fs.createPrincipal("service", "sender", network)
	target, _ := fs.createPrincipal("agent", "target", network)
	c := mustConnect(t, fs, credential, t.TempDir())
	waitForCryptoReady(t, fs, principal)
	m := OutgoingMessage{NetworkID: network, RecipientPrincipalID: target, Parts: []MessagePart{TextPart("ordinary send")}}
	path, _ := c.preparedMessagePath(network, domain.NewID().String())
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < preparedMessageHistoryLimit; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("entry-%d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.PrepareMessage(context.Background(), m); err == nil {
		t.Fatal("full prepared history accepted a new entry")
	}
	var mu sync.Mutex
	var requests []restMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req restMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		mu.Lock()
		requests = append(requests, req)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"ID": req.ID})
	}))
	defer server.Close()
	c.rest.base = server.URL
	for _, kind := range []string{"ASK", "REPLY"} {
		m.Kind = kind
		m.ThreadID, m.CorrelationID = domain.NewID().String(), domain.NewID().String()
		if id, err := c.Send(context.Background(), m); err != nil || id == "" {
			t.Fatalf("ordinary %s = %q, %v", kind, id, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != preparedMessageHistoryLimit {
		t.Fatalf("history changed: count=%d, error=%v", len(entries), err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 || requests[0].ID == requests[1].ID || requests[1].CorrelationID != m.CorrelationID {
		t.Fatal("ordinary send identity or routing lost")
	}
}
