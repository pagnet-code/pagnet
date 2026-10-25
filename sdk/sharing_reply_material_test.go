package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func receivedReplyMaterial(t *testing.T) (*sharingMessageFixture, *Client, *Client, SharingMessage, []byte) {
	t.Helper()
	f, issuer, recipient := sharingMessageClients(t)
	ctx := context.Background()
	p, err := issuer.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("persisted question")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.SendPreparedSharingMessage(ctx, p); err != nil {
		t.Fatal(err)
	}
	var received SharingMessage
	var material []byte
	if err := recipient.ReceiveSharingMessages(ctx, "grant", func(_ context.Context, m SharingMessage) error {
		received = m
		material, err = m.ExportReplyMaterial()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return f, issuer, recipient, received, material
}

func TestSharingReplyMaterialRestart(t *testing.T) {
	f, issuer, recipient, received, material := receivedReplyMaterial(t)
	ctx := context.Background()
	if bytes.Contains(material, []byte("persisted question")) {
		t.Fatal("reply material contains plaintext")
	}
	if _, err := (SharingMessage{GrantID: "grant", Message: received.Message}).ExportReplyMaterial(); err == nil {
		t.Fatal("public message exported reply material")
	}
	// Reopen persisted keys with a new client and connection; import must require
	// a new proof before it can restore a predecessor, even after the inbox ACK.
	kr, err := newKeyring(filepath.Dir(recipient.kr.root))
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Client{kr: kr, identityPriv: recipient.identityPriv, identityPub: recipient.identityPub}
	restarted.principalID.Store(recipient.principalID.Load())
	restarted.endpointID.Store("recipient-restarted")
	restarted.credential.Store(recipient.credential.Load())
	restarted.connected.Store(true)
	restarted.connGeneration.Store(2)
	restarted.rest = newRestClient(strings.TrimSuffix(recipient.rest.base, "/api/v1"), "test", func() string { return restarted.credential.Load().(string) })
	if _, err := restarted.ImportReceivedSharingMessage(ctx, "grant", material); err == nil {
		t.Fatal("import accepted without restart proof")
	}
	if _, err := restarted.EnrollSharingPair(ctx, "grant"); err != nil {
		t.Fatal(err)
	}
	restored, err := restarted.ImportReceivedSharingMessage(ctx, "grant", material)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored, received) {
		t.Fatal("restored message differs from callback")
	}
	if f.acks != 1 || f.sends != 1 {
		t.Fatal("import changed server message state")
	}
	p, err := restarted.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("reply after restart")}, ReplyTo: &restored})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.SendPreparedSharingMessage(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := issuer.ReceiveSharingMessages(ctx, "grant", func(_ context.Context, reply SharingMessage) error {
		if reply.ThreadID != received.ThreadID || reply.CorrelationID == nil || *reply.CorrelationID != received.ID || reply.TextBody() != "reply after restart" {
			t.Fatal("restored predecessor lost reply binding")
		}
		original, err := reply.ExportReplyMaterial()
		if err != nil {
			return err
		}
		// Public fields, including the pointer-valued correlation, must never
		// mutate the authenticated private wire used for persistence/replies.
		reply.ID = "edited"
		reply.Parts = []MessagePart{TextPart("edited")}
		*reply.CorrelationID = "edited"
		edited, err := reply.ExportReplyMaterial()
		if err != nil {
			return err
		}
		if !bytes.Equal(original, edited) {
			t.Fatal("public edit changed reply material")
		}
		_, err = issuer.ImportReceivedSharingMessage(ctx, "grant", edited)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSharingReplyMaterialRejectsTampering(t *testing.T) {
	f, issuer, recipient, _, material := receivedReplyMaterial(t)
	ctx := context.Background()
	mutate := func(change func(*pairMessageWire)) []byte {
		var wire pairMessageWire
		if err := json.Unmarshal(material, &wire); err != nil {
			t.Fatal(err)
		}
		change(&wire)
		raw, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for name, raw := range map[string][]byte{
		"empty":           nil,
		"absolute size":   bytes.Repeat([]byte("x"), maxSharingReplyMaterialBytes+1),
		"pair size":       bytes.Repeat([]byte("x"), f.pair.status.Limits.MaxMessageWireBytes+1),
		"whitespace":      append(append([]byte(nil), material...), ' '),
		"trailing object": append(append([]byte(nil), material...), []byte("{}")...),
		"unknown field":   append([]byte(`{"unknown":1,`), material[1:]...),
		"duplicate field": append([]byte(`{"version":1,`), material[1:]...),
		"grant":           mutate(func(w *pairMessageWire) { w.GrantID = "other" }),
		"generation":      mutate(func(w *pairMessageWire) { w.Generation++ }),
		"principal":       mutate(func(w *pairMessageWire) { w.RecipientPrincipalID = "other" }),
		"aad":             mutate(func(w *pairMessageWire) { w.AAD.CreatedAt = "2026-01-01T00:00:00Z" }),
		"ciphertext":      mutate(func(w *pairMessageWire) { w.Envelope.Ciphertext = "AAAA" }),
		"protected binding": mutate(func(w *pairMessageWire) {
			w.Kind = "REPLY"
			id := w.ID
			w.CorrelationID = &id
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := recipient.ImportReceivedSharingMessage(ctx, "grant", raw); err == nil {
				t.Fatal("invalid reply material accepted")
			}
		})
	}
	if _, err := issuer.ImportReceivedSharingMessage(ctx, "grant", material); err == nil {
		t.Fatal("sender imported incoming predecessor")
	}
	if _, err := recipient.ImportReceivedSharingMessage(ctx, "other", material); err == nil {
		t.Fatal("wrong grant accepted")
	}
	f.pair.status.State = "revoked"
	if _, err := recipient.ImportReceivedSharingMessage(ctx, "grant", material); err == nil {
		t.Fatal("revoked authorization accepted")
	}
	f.pair.status.State = "active"
	f.pair.status.Generation++
	if _, err := recipient.ImportReceivedSharingMessage(ctx, "grant", material); err == nil {
		t.Fatal("obsolete generation accepted")
	}
	if f.acks != 1 || f.sends != 1 {
		t.Fatal("rejected imports changed server message state")
	}
}
