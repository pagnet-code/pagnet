package sdk

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestBrowserAskEncryptedRetryPersistenceAndReadIsolation(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("browser", true)
	principal, credential := fs.createPrincipal("service", "browser", network)
	target, _ := fs.createPrincipal("agent", "target", network)
	c := mustConnect(t, fs, credential, t.TempDir())
	waitForCryptoReady(t, fs, principal)
	ctx := context.Background()
	id := domain.NewID().String()
	text := "private customer question"
	if _, err := c.SendBrowserAsk(ctx, network, target, id, text); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.kr.root, principal, "browser-asks", network, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte(text)) {
		t.Fatal("plaintext persisted in retry cache")
	}
	var prepared preparedBrowserAsk
	if err := json.Unmarshal(before, &prepared); err != nil {
		t.Fatal(err)
	}
	// A new SDK object models retry after process restart using the same durable keyring.
	retry := &Client{cfg: c.cfg, kr: c.kr, rest: c.rest, identityPriv: c.identityPriv, identityPub: c.identityPub}
	retry.principalID.Store(principal)
	retry.tenantID.Store(c.tenantID.Load())
	if _, err := retry.SendBrowserAsk(ctx, network, target, id, text); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("retry regenerated encrypted request")
	}
	if _, err := c.SendBrowserAsk(ctx, network, target, id, "changed input"); err == nil {
		t.Fatal("UUID rebound to different input")
	}
	pid, tid := domain.ID(principal), domain.ID(target)
	ask := domain.Message{ID: domain.ID(id), NetworkID: domain.ID(network), ThreadID: domain.ID(id), Kind: domain.MessageKindAsk, SenderPrincipalID: &pid, RecipientPrincipalID: &tid, Metadata: map[string]any{"e2ee_envelope": prepared.Request.Envelope, "e2ee_aad": prepared.Request.AAD}}
	replyID := domain.NewID()
	correlation := domain.ID(id)
	aad := fs.buildAAD(network, e2ee.ObjectTypeMessage, replyID.String(), target, principal)
	plain, _ := domain.EncodeMessageContent([]domain.MessagePart{domain.TextPart("private reply"), domain.DataPart(json.RawMessage(`{"ok":true}`))})
	envelope, err := e2ee.Encrypt(plain, fs.epochKey, aad)
	if err != nil {
		t.Fatal(err)
	}
	reply := domain.Message{ID: replyID, NetworkID: domain.ID(network), ThreadID: domain.ID(id), Kind: domain.MessageKindReply, SenderPrincipalID: &tid, RecipientPrincipalID: &pid, CorrelationID: &correlation, Metadata: map[string]any{"e2ee_envelope": envelope, "e2ee_aad": aad}}
	tamper := false
	foreign := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := BrowserAskResult{MessageID: id, ThreadID: id, TargetPrincipalID: target, Messages: []domain.Message{ask, reply}}
		if tamper {
			wrong := aad
			wrong.ObjectID = "foreign"
			result.Messages[1].Metadata = map[string]any{"e2ee_envelope": envelope, "e2ee_aad": wrong}
		}
		if foreign {
			result.Messages[1].RecipientPrincipalID = &tid
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	c.rest.base = server.URL
	out, err := c.GetBrowserAsk(ctx, network, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Messages[1].Parts) != 2 || out.Messages[1].TextBody() != "private reply" {
		t.Fatal("typed reply lost")
	}
	if _, exists := out.Messages[0].Metadata["e2ee_envelope"]; exists {
		t.Fatal("ciphertext leaked as result metadata")
	}
	tamper = true
	if out, err := c.GetBrowserAsk(ctx, network, id); err == nil || out != nil {
		t.Fatal("tampered result partially disclosed")
	}
	tamper = false
	foreign = true
	if out, err := c.GetBrowserAsk(ctx, network, id); err == nil || out != nil {
		t.Fatal("foreign recipient exposed")
	}
}
