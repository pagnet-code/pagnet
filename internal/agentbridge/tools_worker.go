// The fixed network_* tools (PROTOCOL §6) — the worker agent's network
// surface, registered by `pagnet mcp worker` (the daemon's own
// executable, spawned as <self> mcp worker): one registration, one
// entrypoint.
//
// The tool names are FIXED protocol names; they must never drift:
// network_whoami, network_discover, network_ask, network_delegate,
// network_inbox, network_reply, network_task_get, network_task_update,
// network_claim, network_release, network_publish_artifact,
// network_register_capabilities.

package agentbridge

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// §16: every tool description MUST carry this wording — it is the
// mechanism that keeps agents off runtime-native subagent messaging for
// pagnet peers.
const peerDescription = " Use this tool for communication with persistent pagnet peers, including agents using another runtime, repository, process or host. Do not use runtime-native subagent communication for pagnet peers. Runtime-native tools are only for workers owned by this runtime session."

// RegisterWorkerTools adds the fixed network_* tool surface (PROTOCOL
// §6) to s, each call relayed over br.
func RegisterWorkerTools(s *server.MCPServer, br *Bridge) {
	s.AddTool(mcp.NewTool("network_whoami",
		mcp.WithDescription("My pagnet identity: this agent instance, its definition (name, profile, capabilities), and my network."+peerDescription),
	), br.Handle("network_whoami", map[string]any{}))

	s.AddTool(mcp.NewTool("network_discover",
		mcp.WithDescription("Who/what exists in my network: agents (with capabilities and live instances), resources, and recent tasks. Optionally narrow with resourceKey/action for candidate discovery."+peerDescription),
		mcp.WithString("resourceKey", mcp.Description("canonical resource key to discover agents for (e.g. github.com/org/repo)")),
		mcp.WithString("action", mcp.Description("the action to discover agents for (e.g. implement, review)")),
	), br.Handle("network_discover", map[string]any{"resourceKey": "string", "action": "string"}))

	s.AddTool(mcp.NewTool("network_ask",
		mcp.WithDescription("Send a durable ask message to another agent (by name) or instance. The recipient is woken if hibernated. Without a recipient the message is stored in the thread."+peerDescription),
		mcp.WithString("body", mcp.Required(), mcp.Description("the message text")),
		mcp.WithString("toAgent", mcp.Description("recipient agent name")),
		mcp.WithString("toInstance", mcp.Description("recipient instance id (takes precedence over toAgent)")),
		mcp.WithString("threadId", mcp.Description("existing thread to post in (otherwise a new thread is started)")),
		mcp.WithString("subject", mcp.Description("thread subject for a new thread")),
		mcp.WithString("taskId", mcp.Description("related task id")),
		mcp.WithString("resource", mcp.Description("resource key this ask is about")),
	), br.Handle("network_ask", map[string]any{
		"body": "string", "toAgent": "string", "toInstance": "string",
		"threadId": "string", "subject": "string", "taskId": "string", "resource": "string",
	}))

	s.AddTool(mcp.NewTool("network_delegate",
		mcp.WithDescription("Create and delegate a durable task (delegated work is a Task, never a chat message). With a resolvable target the task is delivered to that instance immediately; otherwise it stays pending for routing."+peerDescription),
		mcp.WithString("objective", mcp.Required(), mcp.Description("what to achieve")),
		mcp.WithString("title", mcp.Description("short title (defaults to the objective)")),
		mcp.WithArray("acceptanceCriteria", mcp.Description("how done is verified"), mcp.WithStringItems()),
		mcp.WithString("toAgent", mcp.Description("target agent name")),
		mcp.WithString("toInstance", mcp.Description("target instance id")),
		mcp.WithString("resource", mcp.Description("resource key the task is about")),
	), br.Handle("network_delegate", map[string]any{
		"objective": "string", "title": "string", "acceptanceCriteria": "array",
		"toAgent": "string", "toInstance": "string", "resource": "string",
	}))

	s.AddTool(mcp.NewTool("network_inbox",
		mcp.WithDescription("My undelivered inbound messages (asks, replies, notices addressed to me or my group)."+peerDescription),
	), br.Handle("network_inbox", map[string]any{}))

	s.AddTool(mcp.NewTool("network_reply",
		mcp.WithDescription("Reply within an existing thread. The thread's most recent other participant is woken with the reply."+peerDescription),
		mcp.WithString("threadId", mcp.Required(), mcp.Description("the thread to reply in")),
		mcp.WithString("body", mcp.Required(), mcp.Description("the reply text")),
	), br.Handle("network_reply", map[string]any{"threadId": "string", "body": "string"}))

	s.AddTool(mcp.NewTool("network_task_get",
		mcp.WithDescription("Read a task: state, objective, acceptance criteria, status history, dependencies, and artifacts."+peerDescription),
		mcp.WithString("taskId", mcp.Required(), mcp.Description("the task id")),
	), br.Handle("network_task_get", map[string]any{"taskId": "string"}))

	s.AddTool(mcp.NewTool("network_task_update",
		mcp.WithDescription("Update a task's state (accept, start, block with a reason, complete with evidence, fail, cancel). State transitions are validated by the control plane; a reason is REQUIRED for blocked, completed, and failed."+peerDescription),
		mcp.WithString("taskId", mcp.Required(), mcp.Description("the task id")),
		mcp.WithString("status", mcp.Required(), mcp.Description("accepted | working | blocked | completed | failed | cancelled")),
		mcp.WithString("reason", mcp.Description("why (REQUIRED for blocked/completed/failed: evidence for completion, the blocker for blocked, what failed)")),
	), br.Handle("network_task_update", map[string]any{"taskId": "string", "status": "string", "reason": "string"}))

	s.AddTool(mcp.NewTool("network_claim",
		mcp.WithDescription("Acquire a scoped claim (TTL, glob-aware overlap check). Overlapping claims on the same scope are rejected — never work on a scope someone else holds."+peerDescription),
		mcp.WithString("scope", mcp.Required(), mcp.Description("e.g. a path glob like src/compiler/**, a task id, or a resource key")),
		mcp.WithString("scopeType", mcp.Description("path (default) | task | resource")),
		mcp.WithString("resourceId", mcp.Description("resource id to scope against")),
		mcp.WithString("taskId", mcp.Description("task id this claim is for")),
		mcp.WithNumber("ttlSeconds", mcp.Description("claim lifetime in seconds (default 3600)")),
	), br.Handle("network_claim", map[string]any{
		"scope": "string", "scopeType": "string", "resourceId": "string",
		"taskId": "string", "ttlSeconds": "number",
	}))

	s.AddTool(mcp.NewTool("network_release",
		mcp.WithDescription("Release a claim I hold, early."+peerDescription),
		mcp.WithString("claimId", mcp.Required(), mcp.Description("the claim id")),
	), br.Handle("network_release", map[string]any{"claimId": "string"}))

	s.AddTool(mcp.NewTool("network_publish_artifact",
		mcp.WithDescription("Publish a produced artifact (file/report) as a first-class object and get its reference."+peerDescription),
		mcp.WithString("uri", mcp.Required(), mcp.Description("storage reference of the artifact (path or URL)")),
		mcp.WithString("label", mcp.Description("human-readable label (defaults to the uri)")),
		mcp.WithString("type", mcp.Description("artifact type (default other)")),
		mcp.WithString("taskId", mcp.Description("task this artifact belongs to")),
	), br.Handle("network_publish_artifact", map[string]any{
		"uri": "string", "label": "string", "type": "string", "taskId": "string",
	}))

	s.AddTool(mcp.NewTool("network_register_capabilities",
		mcp.WithDescription("Declare the capabilities THIS instance can actually perform for its current mission (id, name, description). Merged with your definition's user-set capabilities in discovery — it never replaces or removes them, and it applies to this instance only. Call it once when you understand your mission, and again if your effective capabilities change."+peerDescription),
		mcp.WithArray("capabilities",
			mcp.Required(),
			mcp.Description("the capabilities to declare (replaces your previous declaration for this instance)"),
			mcp.Items(map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":          map[string]any{"type": "string", "description": "short verb id, e.g. review-auth"},
					"name":        map[string]any{"type": "string", "description": "human-readable name, e.g. Review authentication code"},
					"description": map[string]any{"type": "string", "description": "what this capability covers"},
				},
				"required": []string{"id", "name"},
			}),
		),
	), br.Handle("network_register_capabilities", map[string]any{"capabilities": "array"}))
}
