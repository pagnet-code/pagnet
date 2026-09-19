package sdk

import (
	"encoding/json"
	"testing"
)

var helloSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "text": { "type": "string" }
  },
  "required": ["text"]
}`)

func TestSchemaValidateValid(t *testing.T) {
	c := newSchemaCache()
	if err := c.validate(helloSchema, json.RawMessage(`{"text":"hi"}`)); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
}

func TestSchemaValidateInvalid(t *testing.T) {
	c := newSchemaCache()
	// Missing required field.
	if err := c.validate(helloSchema, json.RawMessage(`{}`)); err == nil {
		t.Fatal("missing required field should fail validation")
	}
	// Wrong type.
	if err := c.validate(helloSchema, json.RawMessage(`{"text":42}`)); err == nil {
		t.Fatal("wrong type should fail validation")
	}
}

func TestSchemaEmptyValidatesEverything(t *testing.T) {
	c := newSchemaCache()
	if err := c.validate(nil, json.RawMessage(`{"anything":true}`)); err != nil {
		t.Fatalf("empty schema should validate anything: %v", err)
	}
	if err := c.validate(json.RawMessage(``), json.RawMessage(`[1,2,3]`)); err != nil {
		t.Fatalf("empty schema bytes should validate anything: %v", err)
	}
}

func TestSchemaRejectsInvalidJSONData(t *testing.T) {
	c := newSchemaCache()
	if err := c.validate(helloSchema, json.RawMessage(`{not json`)); err == nil {
		t.Fatal("invalid JSON data should fail")
	}
}

func TestSchemaRejectsMalformedSchema(t *testing.T) {
	c := newSchemaCache()
	if err := c.validate(json.RawMessage(`{not a schema`), json.RawMessage(`{}`)); err == nil {
		t.Fatal("malformed schema should fail to compile")
	}
}

func TestSchemaCacheReusesCompiledSchema(t *testing.T) {
	c := newSchemaCache()
	// Validate the same schema many times; the cache should hold one entry.
	for i := 0; i < 5; i++ {
		if err := c.validate(helloSchema, json.RawMessage(`{"text":"x"}`)); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("schema cache holds %d entries, want 1 (compiled once)", n)
	}
}
