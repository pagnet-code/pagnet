package e2ee

// AAD object types (plan §12). The AAD's ObjectType field binds a protected
// object to the class of content it protects. These are the object types
// for the Pagnet-native protected content paths:
//
//   - ObjectTypeMessage: a durable message body (ASK/REPLY/NOTICE/STATUS).
//   - ObjectTypeTask: a task's objective / instructions / acceptance criteria
//     and its blocked-reason / generated textual results.
//   - ObjectTypeRuntimeInteraction: a native runtime interaction's detail
//     (the question / options / answer); kind + state + ids stay plaintext.
//   - ObjectTypeRuntimeOutput: a non-PTY turn output chunk (the PTY byte
//     stream is a separate, later path).
//   - ObjectTypeArtifact: an artifact's free-form label / description /
//     detailed result text (canonical URLs / commit SHAs / paths are
//     operational metadata and stay plaintext).
//   - ObjectTypeAgentDefinition: an agent definition's free-form mission /
//     instruction text.
//   - ObjectTypeAgentTemplate: a network template's combined mission +
//     instruction document (the template's protected content).
//
// Protocol v2 (the V2 cutover) adds the event + invocation object types:
//
//   - ObjectTypeEventPayload: an event's payload (the routing metadata —
//     type, producer, target, resource, capability — stays plaintext).
//   - ObjectTypeInvocationInput: a capability invocation's input.
//   - ObjectTypeInvocationOutput: a capability invocation's output.
//   - ObjectTypeInvocationError: a failed invocation's error detail.
//
// The values are part of the AAD wire contract: the sender and the recipient
// must agree on them, and the server relays them verbatim (it never derives
// or alters them).
const (
	ObjectTypeMessage            = "message"
	ObjectTypeTask               = "task"
	ObjectTypeRuntimeInteraction = "runtime_interaction"
	ObjectTypeRuntimeOutput      = "runtime_output"
	ObjectTypeArtifact           = "artifact"
	ObjectTypeAgentDefinition    = "agent_definition"
	ObjectTypeAgentTemplate      = "agent_template"

	ObjectTypeEventPayload     = "event_payload"
	ObjectTypeInvocationInput  = "invocation_input"
	ObjectTypeInvocationOutput = "invocation_output"
	ObjectTypeInvocationError  = "invocation_error"
)
