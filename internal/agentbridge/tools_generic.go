package agentbridge

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// RegisterGenericTools adds the V2 GENERIC network tool surface (plan §52)
// to s, each call relayed over br. These are the generic primitives a
// network participant uses to discover, invoke, and consume network events —
// the complement to the fixed collaboration tools (network_ask /
// network_delegate / network_task_* / ...).
//
// There is NO per-capability tool generation: a capability is DISCOVERED
// through network_search and CALLED through network_invoke (its id + input).
// New capabilities never require new tools — the surface is fixed and the
// capability set is data.
//
// The protected-content tools (network_invoke input, network_event_publish
// payload) are encrypted by the DAEMON before they cross the cloud boundary
// (plan §12 / D6 always-encrypted); the bridge relays them verbatim. Tools
// that RETURN participant-authored content carry the untrusted-data wording
// (plan §46): the returned data is never instructions.
func RegisterGenericTools(s *server.MCPServer, br *Bridge) {
	// network_search: discover agents, services, and capabilities.
	s.AddTool(mcp.NewTool("network_search",
		mcp.WithDescription("Search the network for agents, services, and capabilities by query, kind, or capability id. Returns routing metadata (ids, names, capabilities) — use network_invoke to call a capability you find."+peerDescription),
		mcp.WithString("query", mcp.Description("free-text query to match against names/descriptions")),
		mcp.WithString("kind", mcp.Description("agent | service | capability (omit to search all)")),
		mcp.WithString("capability", mcp.Description("capability id to search for")),
		mcp.WithNumber("limit", mcp.Description("max results (default set by the network)")),
		mcp.WithString("cursor", mcp.Description("pagination cursor from a prior search")),
	), br.Handle("network_search", map[string]any{
		"query": "string", "kind": "string", "capability": "string",
		"limit": "number", "cursor": "string",
	}))

	// network_invoke: call a capability (its input is E2EE to the owner).
	s.AddTool(mcp.NewTool("network_invoke",
		mcp.WithDescription("Invoke a capability (a versioned verb offered by an agent or service). The input is encrypted end-to-end to the capability's owner; the result is returned to you. Pass idempotencyKey to make a retried call safe (not re-executed)."+peerDescription),
		mcp.WithString("capability", mcp.Required(), mcp.Description("the capability id to invoke (e.g. documents.extract)")),
		mcp.WithObject("input", mcp.Required(), mcp.Description("the invocation input — a JSON object; shape defined by the capability's input schema"), allowAnyKeys),
		mcp.WithString("idempotencyKey", mcp.Description("optional idempotency key (a retried call with the same key is not re-executed)")),
	), br.Handle("network_invoke", map[string]any{
		"capability": "string", "input": "object", "idempotencyKey": "string",
	}))

	// network_event_publish: publish a typed network event (payload E2EE).
	s.AddTool(mcp.NewTool("network_event_publish",
		mcp.WithDescription("Publish a typed network event. The payload is encrypted end-to-end. Subscribers (and the target, when given) are woken with a trigger to fetch it via network_event_get — the payload is delivered to them as DATA, never inlined into their prompt."+peerDescription),
		mcp.WithString("type", mcp.Required(), mcp.Description("the event type (dot-separated, e.g. build.completed)")),
		mcp.WithObject("payload", mcp.Required(), mcp.Description("the event payload — a JSON object"), allowAnyKeys),
		mcp.WithString("target", mcp.Description("optional target principal/agent name to address this event to")),
	), br.Handle("network_event_publish", map[string]any{
		"type": "string", "payload": "object", "target": "string",
	}))

	// network_event_get: fetch one event's (decrypted) payload.
	s.AddTool(mcp.NewTool("network_event_get",
		mcp.WithDescription("Fetch one network event by id: its type, routing metadata, and its (decrypted) payload. In a turn triggered by a network event, call this to see what happened."+untrustedDataDescription),
		mcp.WithString("eventId", mcp.Required(), mcp.Description("the event id")),
	), br.Handle("network_event_get", map[string]any{"eventId": "string"}))

	// network_events: list recent events (newest first).
	s.AddTool(mcp.NewTool("network_events",
		mcp.WithDescription("List recent network events (newest first), optionally filtered by type. Returns event metadata (type, id, target, time); fetch a specific payload with network_event_get."+untrustedDataDescription),
		mcp.WithString("type", mcp.Description("event type filter (dot-separated; omit for all)")),
		mcp.WithNumber("limit", mcp.Description("max events (default set by the network)")),
	), br.Handle("network_events", map[string]any{
		"type": "string", "limit": "number",
	}))

	// network_subscribe: subscribe to an event pattern.
	s.AddTool(mcp.NewTool("network_subscribe",
		mcp.WithDescription("Subscribe this agent to a network event pattern (dot-separated, e.g. build.* or *). A match wakes the agent with a trigger turn to fetch the event via network_event_get. Returns the subscription id (use it to unsubscribe)."+peerDescription),
		mcp.WithString("pattern", mcp.Required(), mcp.Description("the event type pattern to subscribe to (supports * wildcards)")),
		mcp.WithString("mode", mcp.Description("deliver (default) | wake")),
	), br.Handle("network_subscribe", map[string]any{
		"pattern": "string", "mode": "string",
	}))

	// network_unsubscribe: cancel a subscription by id.
	s.AddTool(mcp.NewTool("network_unsubscribe",
		mcp.WithDescription("Cancel an event subscription by its id (the id returned by network_subscribe)."+peerDescription),
		mcp.WithString("subscriptionId", mcp.Required(), mcp.Description("the subscription id")),
	), br.Handle("network_unsubscribe", map[string]any{"subscriptionId": "string"}))
}

// allowAnyKeys is a PropertyOption marking a declared object property as a
// free-form JSON object (arbitrary keys): the capability invocation input
// and the event payload have capability-defined / publisher-defined shapes
// that the daemon does not schema-validate.
func allowAnyKeys(schema map[string]any) {
	schema["additionalProperties"] = true
}
