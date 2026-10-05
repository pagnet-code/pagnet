package fabricagent

import (
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

func TestAdvertisedPromptSchemaMatchesActualEndpointBinder(t *testing.T) {
	metadata := NativePromptMetadata()
	var schema struct {
		Type                 string
		Required             []string
		AdditionalProperties bool
		Properties           map[string]struct {
			Type                 string
			MinLength, MaxLength int
		}
	}
	if err := json.Unmarshal(metadata["extensions.pagnet.agent.input_schema"], &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Type != "object" || len(schema.Required) != 1 || schema.Required[0] != "input" || schema.AdditionalProperties || schema.Properties["input"].Type != "string" || schema.Properties["input"].MinLength != 1 || schema.Properties["input"].MaxLength != 128<<10 {
		t.Fatal("schema differs from actual binder")
	}
	binder := nativeauthority.JSONPromptBinder{}
	for _, input := range []json.RawMessage{json.RawMessage(`{"input":"exact user instructions"}`), json.RawMessage(`{"input":"Unicode 🦉"}`)} {
		if _, err := binder.Bind(fabric.Envelope{Operation: fabric.OperationInvoke, Payload: input}); err != nil {
			t.Fatal("advertised input rejected", err)
		}
	}
	for _, input := range []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{"input":""}`), json.RawMessage(`{"prompt":"wrong protocol"}`), json.RawMessage(`{"input":"valid","binary":"injected"}`)} {
		if _, err := binder.Bind(fabric.Envelope{Operation: fabric.OperationInvoke, Payload: input}); err == nil {
			t.Fatal("unsupported input accepted", string(input))
		}
	}
	metadata["extensions.pagnet.agent.input_schema"][0] = 'x'
	if !json.Valid(NativePromptMetadata()["extensions.pagnet.agent.input_schema"]) {
		t.Fatal("descriptor caller mutated shared schema")
	}
}
