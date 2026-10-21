package sdk

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func spoolInput(t *testing.T) (pairMessageBinding, []byte) {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	b := pairMessageBinding{PrincipalID: "sender", GrantID: "grant", Generation: 1, NetworkID: "network", MessageID: id.String(), InputDigest: sha256.Sum256([]byte("plaintext"))}
	w := pairMessageWire{Version: 1, GrantID: b.GrantID, Generation: 1, NetworkID: b.NetworkID, ID: b.MessageID, ThreadID: b.MessageID, Kind: "ASK", SenderPrincipalID: b.PrincipalID, RecipientPrincipalID: "recipient"}
	raw, _ := json.Marshal(w)
	return b, raw
}
