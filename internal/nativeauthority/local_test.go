package nativeauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestJSONPromptBinderMaximumEscapedTextPreservesExactInput(t *testing.T) {
	input := strings.Repeat("\x01", 128<<10)
	payload, _ := json.Marshal(struct {
		Input string `json:"input"`
	}{input})
	binder := JSONPromptBinder{ProfileDigest: sha256.Sum256([]byte("physical profile"))}
	op, e := binder.Bind(fabric.Envelope{Operation: fabric.OperationInvoke, Payload: payload})
	if e != nil || len(op.Payload) > MaxNativeOperationBytes || op.SpecDigest != binder.ProfileDigest {
		t.Fatal("maximum valid prompt rejected", e)
	}
	var recovered struct{ Input, InputKind string }
	if e = json.Unmarshal(op.Payload, &recovered); e != nil || recovered.Input != input || recovered.InputKind != "local-native" {
		t.Fatal("input changed", e)
	}
	for _, bad := range []json.RawMessage{json.RawMessage(`{"input":"","binary":"evil"}`), json.RawMessage(`{"input":"valid","binary":"evil"}`), bytes.Repeat([]byte{'x'}, MaxNativeOperationBytes+1), json.RawMessage(`{"input":42}`)} {
		if _, e = binder.Bind(fabric.Envelope{Operation: fabric.OperationInvoke, Payload: bad}); e == nil {
			t.Fatal("invalid executable input accepted")
		}
	}
}
