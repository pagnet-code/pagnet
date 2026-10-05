package fabricagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func TestHostedPromptSameGrammarExactBytesNoOwnershipTransplant(t *testing.T) {
	p := HostedProfile{DefinitionID: domain.NewID().String(), PrincipalID: domain.NewID().String(), NetworkID: domain.NewID().String(), OwnershipID: domain.NewID().String(), NativeProfile: sha256.Sum256([]byte("genuine original immutable profile")), WorkerDirectory: filepath.Join(t.TempDir(), "original"), Scope: sessionworker.Scope{ServerURL: "https://app.pagnet.dev", TenantID: domain.NewID().String(), AccountID: domain.NewID().String(), HostID: domain.NewID().String(), InstanceID: domain.NewID().String(), Generation: "original-generation"}}
	before, _ := json.Marshal(p)
	for _, text := range []string{"Sales questions\n<literal> & café", strings.Repeat("é", 64<<10), strings.Repeat("a", 128<<10)} {
		raw, _ := json.Marshal(map[string]string{"input": text})
		got, err := BindHostedPrompt(fabric.Envelope{Operation: fabric.OperationInvoke, Payload: raw}, p)
		if err != nil || got != text {
			t.Fatal("exact native prompt bytes changed", err)
		}
	}
	for _, raw := range []json.RawMessage{[]byte(`{"input":"hello","inputKind":"local-native"}`), []byte(`{"prompt":"hello"}`), []byte(`{"input":""}`), []byte(`{"input":1}`), []byte(`{"input":"hello","runtime":"different"}`)} {
		if _, err := BindHostedPrompt(fabric.Envelope{Operation: fabric.OperationInvoke, Payload: raw}, p); err == nil {
			t.Fatal("invented alternate prompt grammar", string(raw))
		}
	}
	raw, _ := json.Marshal(map[string]string{"input": strings.Repeat("é", 65537)})
	if _, err := BindHostedPrompt(fabric.Envelope{Operation: fabric.OperationInvoke, Payload: raw}, p); err == nil {
		t.Fatal("UTF-8 byte limit exceeded")
	}
	if _, err := BindHostedPrompt(fabric.Envelope{Operation: fabric.OperationDiscover, Payload: []byte(`{"input":"hello"}`)}, p); err == nil {
		t.Fatal("discovery became native input")
	}
	after, _ := json.Marshal(p)
	if !bytes.Equal(before, after) {
		t.Fatal("original cloud profile or ownership changed")
	}
}
