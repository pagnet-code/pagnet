package domain

import "encoding/json"

// Capability is a versioned descriptor of one thing a principal can do —
// a verb with an optional JSON-Schema contract. It is discovery and routing
// metadata, NOT a permission: advertising a capability never grants the
// right to call it, and a network permission never implies a capability.
//
// IDs are dot-separated and stable across versions (e.g.
// "documents.extract", "memory.search", "code.review"). Bumping Version
// signals a contract change; callers pin CapabilityVersion at invocation.
//
// Schemas may be omitted for trivial capabilities.
type Capability struct {
	ID string `json:"id"`
	// Version is the contract version (1 for first publication).
	Version     int    `json:"version"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// InputSchema is the JSON Schema of the invocation input (may be nil).
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	// OutputSchema is the JSON Schema of the invocation output (may be nil).
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Tags         []string        `json:"tags,omitempty"`
	Metadata     map[string]any  `json:"metadata,omitempty"`
}

// CapabilityNames extracts the names from a capability list.
func CapabilityNames(caps []Capability) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		out = append(out, c.Name)
	}
	return out
}
