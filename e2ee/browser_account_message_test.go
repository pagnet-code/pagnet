package e2ee

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBrowserAccountMessageAAD(t *testing.T) {
	aad := AAD{ProtocolVersion: 2, TenantID: "tenant", NetworkID: "network", ObjectType: ObjectTypeMessage, ObjectID: "message", Sender: "logical-delegate", Recipient: "target-principal", CreatedAt: "2026-11-10T12:00:00Z", KeyEpochID: "frozen-epoch", BrowserAccountMessage: &BrowserAccountMessageBinding{BindingDigest: strings.Repeat("a", 64), SenderKind: BrowserAccountDelegateSenderKind}}
	key := [32]byte{1}
	env, err := Encrypt([]byte("private text"), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"digest", "sender", "target", "epoch", "senderKind", "native"} {
		t.Run(kind, func(t *testing.T) {
			changed := aad
			b := *aad.BrowserAccountMessage
			changed.BrowserAccountMessage = &b
			switch kind {
			case "digest":
				b.BindingDigest = strings.Repeat("b", 64)
			case "sender":
				changed.Sender = "principal"
			case "target":
				changed.Recipient = "other"
			case "epoch":
				changed.KeyEpochID = "other"
			case "senderKind":
				b.SenderKind = "principal"
			case "native":
				changed.NativeContent = &NativeContentBinding{}
			}
			if _, e := Decrypt(env, key, changed); e == nil {
				t.Fatal("authenticated tampered account binding")
			}
		})
	}
	var b BrowserAccountMessageBinding
	if json.Unmarshal([]byte(`{"binding_digest":"x","sender_kind":"browser_account_delegate","unknown":true}`), &b) == nil {
		t.Fatal("unknown authenticated field accepted")
	}
}
