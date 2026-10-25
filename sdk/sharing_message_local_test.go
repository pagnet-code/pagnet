package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSharingMessageExpectedGeneration(t *testing.T) {
	ctx := context.Background()
	var disconnected Client
	if _, err := disconnected.PrepareSharingMessage(ctx, SharingMessageRequest{ExpectedGeneration: -1}); err == nil {
		t.Fatal("negative generation accepted")
	}
	newer, issuer, recipient := pairRESTClients(t)
	newer.status.Generation++
	newer.status.Limits.MaxMessageWireBytes = 4096
	for _, client := range []*Client{issuer, recipient, issuer, recipient, issuer} {
		if _, err := client.EnrollSharingPair(ctx, "grant"); err != nil {
			t.Fatal(err)
		}
	}
	staleID := uuid.Must(uuid.NewV7()).String()
	if _, err := issuer.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", MessageID: staleID, ExpectedGeneration: 1, Parts: []MessagePart{TextPart("stale input")}}); err == nil {
		t.Fatal("old generation accepted after reenrollment")
	}
	if _, found, err := issuer.LookupSharingMessage(staleID); err != nil || found {
		t.Fatalf("old generation reserved ID: found=%v err=%v", found, err)
	}
	f, c, _ := sharingMessageClients(t)
	id := uuid.Must(uuid.NewV7()).String()
	req := SharingMessageRequest{GrantID: "grant", MessageID: id, ExpectedGeneration: f.pair.status.Generation + 1, Parts: []MessagePart{TextPart("generation-bound input")}}
	if _, err := c.PrepareSharingMessage(ctx, req); err == nil {
		t.Fatal("stale generation accepted")
	}
	if _, found, err := c.LookupSharingMessage(id); err != nil || found {
		t.Fatalf("stale generation reserved ID: found=%v err=%v", found, err)
	}
	req.ExpectedGeneration = f.pair.status.Generation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			status := f.pair.status
			status.Generation++
			_ = json.NewEncoder(w).Encode(status)
			return
		}
		f.serve(w, r)
	}))
	defer server.Close()
	originalBase := c.rest.base
	c.rest.base = server.URL + "/api/v1"
	if _, err := c.PrepareSharingMessage(ctx, req); err == nil {
		t.Fatal("generation changed between list and status accepted")
	}
	if _, found, err := c.LookupSharingMessage(id); err != nil || found {
		t.Fatalf("generation race reserved ID: found=%v err=%v", found, err)
	}
	c.rest.base = originalBase
	p, err := c.PrepareSharingMessage(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if p.Generation() != req.ExpectedGeneration {
		t.Fatal("wrong prepared generation")
	}
	original, err := c.kr.loadPairMessage(p.state.Binding)
	if err != nil {
		t.Fatal(err)
	}
	// Zero preserves current-generation behavior and retries the same ciphertext.
	req.ExpectedGeneration = 0
	repeated, err := c.PrepareSharingMessage(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := c.kr.loadPairMessage(repeated.state.Binding)
	if err != nil || !bytes.Equal(original, wire) {
		t.Fatalf("retry reencrypted: %v", err)
	}
}

func TestSharingMessageLookupRestartAndRevocation(t *testing.T) {
	f, c, peer := sharingMessageClients(t)
	ctx := context.Background()
	prepare := func() PreparedSharingMessage {
		t.Helper()
		p, err := c.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("local state")}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	prepared, admitted := prepare(), prepare()
	if _, err := c.SendPreparedSharingMessage(ctx, admitted); err != nil {
		t.Fatal(err)
	}
	tombstone, found, err := c.LookupSharingMessage(admitted.MessageID)
	if err != nil || !found {
		t.Fatalf("admitted lookup: %v %v", found, err)
	}
	if _, err := c.SendPreparedSharingMessage(ctx, tombstone.Prepared); err == nil {
		t.Fatal("admitted lookup used as send handle")
	}
	if _, err := c.GetSharingMessageReceipt(ctx, tombstone.Prepared); err == nil {
		t.Fatal("admitted lookup used as receipt handle")
	}
	b := prepared.state.Binding
	b.MessageID = uuid.Must(uuid.NewV7()).String()
	incomplete, _, err := c.kr.reservePairMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	b.MessageID = uuid.Must(uuid.NewV7()).String()
	rejected, _, err := c.kr.reservePairMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AbortPreparedSharingMessage(PreparedSharingMessage{b.MessageID, rejected}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := peer.LookupSharingMessage(prepared.MessageID); err != nil || found {
		t.Fatalf("other principal saw reservation: %v %v", found, err)
	}
	f.pair.status.State = "revoked"
	// Reopen only local storage, disconnected and without a transport client.
	restarted := &Client{}
	restarted.kr, err = newKeyring(filepath.Dir(c.kr.root))
	if err != nil {
		t.Fatal(err)
	}
	restarted.principalID.Store(c.principalID.Load())
	for _, tc := range []struct {
		id          string
		disposition SharingMessageDisposition
	}{
		{prepared.MessageID, SharingMessagePrepared}, {admitted.MessageID, SharingMessageAdmitted},
		{incomplete.Binding.MessageID, SharingMessageIncomplete}, {rejected.Binding.MessageID, SharingMessageRejected},
	} {
		state, found, err := restarted.LookupSharingMessage(tc.id)
		if err != nil || !found || state.Disposition != tc.disposition {
			t.Fatalf("lookup %s: %+v %v %v", tc.disposition, state, found, err)
		}
		if state.Prepared.MessageID != tc.id || state.Prepared.GrantID() != "grant" || state.Prepared.Generation() != prepared.Generation() {
			t.Fatal("lookup lost identity")
		}
		if state.Prepared.CanRetry() != (tc.disposition == SharingMessagePrepared) {
			t.Fatal("wrong retry disposition")
		}
		if _, err := restarted.SendPreparedSharingMessage(ctx, state.Prepared); err == nil {
			t.Fatal("local lookup granted send authority")
		}
		if _, err := restarted.GetSharingMessageReceipt(ctx, state.Prepared); err == nil {
			t.Fatal("local lookup granted receipt authority")
		}
	}
	if _, found, err := restarted.LookupSharingMessage(uuid.Must(uuid.NewV7()).String()); err != nil || found {
		t.Fatalf("missing lookup: %v %v", found, err)
	}
	if _, _, err := restarted.LookupSharingMessage("../invalid"); err == nil {
		t.Fatal("invalid ID accepted")
	}
}

func TestSharingMessageLookupAuthentication(t *testing.T) {
	for _, kind := range []string{"wire", "index", "principal-binding"} {
		t.Run(kind, func(t *testing.T) {
			k, err := newKeyring(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			b, wire := spoolInput(t)
			storeSpool(t, k, b, wire)
			c := &Client{kr: k}
			c.principalID.Store(b.PrincipalID)
			switch kind {
			case "wire":
				if err := os.WriteFile(k.pairMessagePath(b), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "index":
				if err := os.WriteFile(filepath.Join(k.pairMessageDir(b.PrincipalID), "index.json"), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "principal-binding":
				records, key, err := k.readPairMessageIndex(b.PrincipalID)
				if err != nil {
					t.Fatal(err)
				}
				state := records[b.MessageID]
				state.Binding.PrincipalID = "other"
				records[b.MessageID] = state
				if err := k.writePairMessageIndex(b.PrincipalID, records, key); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := c.LookupSharingMessage(b.MessageID); err == nil {
				t.Fatal("corrupt local state accepted")
			}
		})
	}
}
