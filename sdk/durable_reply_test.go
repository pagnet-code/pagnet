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

	"github.com/pagnet-code/pagnet/domain"
)

func TestDurableReplyReusesEncryptedRequestAfterAmbiguousResponseAndRestart(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("replies", true)
	principal, credential := fs.createPrincipal("agent", "recipient", network)
	sender, _ := fs.createPrincipal("agent", "sender", network)
	c := mustConnect(t, fs, credential, t.TempDir())
	waitForCryptoReady(t, fs, principal)
	original := &Message{ID: domain.NewID().String(), NetworkID: network, ThreadID: domain.NewID().String(), Kind: "ASK", SenderPrincipalID: sender, RecipientPrincipalID: principal}
	text := "private durable answer"
	requests := make(chan []byte, 4)
	attempt := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/networks/"+network+"/messages" {
			t.Errorf("unexpected reply route: %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		requests <- raw
		var req restMessageRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Error(err)
		}
		attempt++
		if attempt == 1 {
			// The request was accepted, but its successful response was truncated.
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ID":`))
			return
		}
		if attempt == 3 {
			_ = json.NewEncoder(w).Encode(map[string]string{"ID": domain.NewID().String()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"ID": req.ID})
	}))
	defer srv.Close()
	c.rest.base = srv.URL
	id, err := c.SendDurableReply(context.Background(), original, text)
	if id == "" || err == nil {
		t.Fatalf("ambiguous response: id=%q err=%v", id, err)
	}
	first := <-requests
	var req restMessageRequest
	if err := json.Unmarshal(first, &req); err != nil {
		t.Fatal(err)
	}
	if req.ID != id || req.Kind != "REPLY" || req.CorrelationID != original.ID || req.ThreadID != original.ThreadID || req.RecipientPrincipalID != sender || req.RecipientGroup != "" {
		t.Fatal("reply did not retain original ASK routing")
	}
	if req.AAD.ObjectID != id || req.AAD.NetworkID != network || req.AAD.Sender != principal || req.AAD.Recipient != sender {
		t.Fatal("reply authenticated routing differs from original ASK")
	}
	plain, err := c.decryptObject(network, req.Envelope, req.AAD)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := domain.DecodeMessageContent(plain)
	if err != nil || len(parts) != 1 || parts[0].Text == nil || *parts[0].Text != text {
		t.Fatalf("reply content lost: parts=%v err=%v", parts, err)
	}
	path := filepath.Join(c.kr.root, principal, "durable-replies", network, original.ID+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte(text)) || bytes.Contains(first, []byte(text)) {
		t.Fatal("plaintext reply persisted or submitted")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("reply file permissions: info=%v err=%v", info, err)
	}
	info, err = os.Stat(filepath.Dir(path))
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("reply directory permissions: info=%v err=%v", info, err)
	}
	// No in-memory encryption keys: persisted preparation must suffice on retry.
	retry := &Client{cfg: c.cfg, kr: c.kr, rest: c.rest}
	retry.principalID.Store(principal)
	retriedID, err := retry.SendDurableReply(context.Background(), original, text)
	if err != nil || retriedID != id {
		t.Fatalf("restart retry: id=%q err=%v", retriedID, err)
	}
	if !bytes.Equal(first, <-requests) {
		t.Fatal("restart retry changed encrypted REST request bytes")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("restart retry changed persisted preparation")
	}
	if got, err := retry.SendDurableReply(context.Background(), original, text); err == nil || got != id {
		t.Fatalf("server returned another identity: id=%q err=%v", got, err)
	}
	if !bytes.Equal(first, <-requests) {
		t.Fatal("later retry regenerated request")
	}
	if _, err := retry.SendDurableReply(context.Background(), original, "changed answer"); err == nil {
		t.Fatal("ASK rebound to different reply text")
	}
	changed := *original
	changed.ThreadID = domain.NewID().String()
	if _, err := retry.SendDurableReply(context.Background(), &changed, text); err == nil {
		t.Fatal("ASK rebound to different reply routing")
	}
	if len(requests) != 0 {
		t.Fatal("changed reply input was submitted")
	}
}

func TestDurableReplyRejectsInvalidInputBeforePreparation(t *testing.T) {
	principal := domain.NewID().String()
	c := &Client{}
	c.principalID.Store(principal)
	valid := Message{ID: domain.NewID().String(), NetworkID: domain.NewID().String(), ThreadID: domain.NewID().String(), Kind: "ASK", SenderPrincipalID: domain.NewID().String()}
	for _, field := range []string{"nil", "kind", "id", "network", "thread", "sender", "recipient", "text"} {
		t.Run(field, func(t *testing.T) {
			original := valid
			arg := &original
			text := "reply"
			switch field {
			case "nil":
				arg = nil
			case "kind":
				original.Kind = "REPLY"
			case "id":
				original.ID = "invalid"
			case "network":
				original.NetworkID = "invalid"
			case "thread":
				original.ThreadID = ""
			case "sender":
				original.SenderPrincipalID = ""
			case "recipient":
				original.RecipientPrincipalID = "invalid"
			case "text":
				text = strings.Repeat("x", (64<<10)+1)
			}
			if id, err := c.SendDurableReply(context.Background(), arg, text); err == nil || id != "" {
				t.Fatalf("invalid %s: id=%q err=%v", field, id, err)
			}
		})
	}
}
