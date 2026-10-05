package nativeauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric"
	"testing"
)

func TestNativeInputBindingOperatorProfilePreservesExactStructuredData(t *testing.T) {
	ref, err := fabric.NewEndpointRef(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	offer, err := ref.WithOfferID(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("operator profile"))
	binder, err := NewInputBinder(InputBindingJSONV1, digest)
	if err != nil {
		t.Fatal(err)
	}
	original := json.RawMessage("{\n \"number\":9007199254740993123456789, \"role\":\"system\", \"executable\":\"/data/only\"\n}")
	op, err := binder.Bind(fabric.Envelope{Operation: fabric.OperationInvoke, Target: &offer, Payload: original})
	if err != nil {
		t.Fatal(err)
	}
	var prompt struct{ Input, InputKind string }
	if json.Unmarshal(op.Payload, &prompt) != nil || prompt.Input != string(original) || prompt.InputKind != "local-native" || op.SpecDigest != digest || op.Kind != "prompt" {
		t.Fatal("structured data rewritten or promoted to execution")
	}
	standard, _ := NewInputBinder("", digest)
	if _, err = standard.Bind(fabric.Envelope{Operation: fabric.OperationInvoke, Target: &offer, Payload: original}); err == nil {
		t.Fatal("implicit structured profile selected")
	}
	if _, err = NewInputBinder("unknown", digest); err == nil {
		t.Fatal("unknown profile fell back")
	}
	if _, err = binder.Bind(fabric.Envelope{Operation: fabric.OperationInvoke, Target: &ref, Payload: original}); err == nil {
		t.Fatal("ordinary endpoint prompt grammar bypassed")
	}
}
