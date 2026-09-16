package e2ee

// AAD object types (plan §12). The AAD's ObjectType field binds a protected
// object to the class of content it protects. These are the v1 object types
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
)
