package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Schema validation (north-star §76, plan D9): the server cannot validate
// protected content (zero-knowledge), so the SDKs validate:
//
//   - the CALLER validates the invocation input BEFORE encryption (when a
//     schema is known — the local capability registry or the caller's
//     Invocation.InputSchema);
//   - the TARGET validates the decrypted input against its registered
//     InputSchema;
//   - the TARGET validates the handler output against its registered
//     OutputSchema BEFORE encryption (a validation failure becomes an
//     invocation_error result — never a malformed ciphertext);
//   - the CALLER validates the decrypted output (when a schema is known).
//
// Full JSON Schema (draft 2020-12 by default, the draft declared in the
// schema's $schema wins) is supported via the maintained
// github.com/santhosh-tekuri/jsonschema/v6 validator — no hand-rolled
// subset.

// schemaCache is a bounded cache of compiled schemas keyed by the schema
// bytes' hash (capabilities re-validate on every invocation; compiling each
// time would burn CPU for no reason).
type schemaCache struct {
	mu      sync.Mutex
	entries map[string]*jsonschema.Schema
	order   []string // insertion order for eviction
	cap     int
}

func newSchemaCache() *schemaCache {
	return &schemaCache{entries: map[string]*jsonschema.Schema{}, cap: 128}
}

func (c *schemaCache) get(key string) (*jsonschema.Schema, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.entries[key]
	return s, ok
}

func (c *schemaCache) put(key string, s *jsonschema.Schema) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; ok {
		c.entries[key] = s
		return
	}
	c.entries[key] = s
	c.order = append(c.order, key)
	if len(c.order) > c.cap {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, old)
	}
}

// compileSchema compiles a JSON Schema document (its raw bytes). An empty
// schema is the "no schema" case and compiles to nil (validation is a
// no-op).
func (c *schemaCache) compile(schema json.RawMessage) (*jsonschema.Schema, error) {
	if len(schema) == 0 {
		return nil, nil
	}
	sum := sha256.Sum256(schema)
	key := hex.EncodeToString(sum[:])
	if s, ok := c.get(key); ok {
		return s, nil
	}
	var doc any
	if err := json.Unmarshal(schema, &doc); err != nil {
		return nil, fmt.Errorf("sdk: capability schema is not valid JSON: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("urn:pagnet:capability-schema", doc); err != nil {
		return nil, fmt.Errorf("sdk: add capability schema: %w", err)
	}
	s, err := compiler.Compile("urn:pagnet:capability-schema")
	if err != nil {
		return nil, fmt.Errorf("sdk: compile capability schema: %w", err)
	}
	c.put(key, s)
	return s, nil
}

// validateAgainstSchema validates raw JSON data against a JSON Schema.
// data must be valid JSON (it is decoded once for the validator). A nil
// schema validates everything.
func (c *schemaCache) validate(schema, data json.RawMessage) error {
	if len(schema) == 0 {
		return nil
	}
	s, err := c.compile(schema)
	if err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("sdk: value is not valid JSON: %w", err)
	}
	if err := s.Validate(v); err != nil {
		return fmt.Errorf("sdk: schema validation failed: %w", err)
	}
	return nil
}
