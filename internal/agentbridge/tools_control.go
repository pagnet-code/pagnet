// The fixed control_* tools (spec §8–9) — the representative's control
// surface. Shared by the pagnet-control binary and `pagnet mcp control`
// (packaging migration): one registration, two entrypoints.
//
// The tool names are FIXED protocol names; they must never drift:
// control_whoami, control_list_networks, control_use_network,
// control_network_status, control_list_agents, control_find_agents,
// control_list_tasks, control_task_status, control_list_blocked,
// control_ask, control_reply, control_delegate, control_wake_agent,
// control_launch_agent, control_stop_agent, control_restart_agent,
// control_get_history, control_get_thread, control_get_graph,
// control_channel_send, control_channel_history.

package agentbridge

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// RegisterControlTools adds the fixed control_* tool surface (spec
// §8–9) to s, each call relayed over br.
func RegisterControlTools(s *server.MCPServer, br *Bridge) {
	s.AddTool(mcp.NewTool("control_whoami",
		mcp.WithDescription("My pagnet identity: this representative instance, its definition, the current turn context, and my network grants."),
	), br.Handle("control_whoami", map[string]any{}))

	s.AddTool(mcp.NewTool("control_list_networks",
		mcp.WithDescription("The networks I have grants on, with the permissions each grant allows (observe/communicate/delegate/operate)."),
	), br.Handle("control_list_networks", map[string]any{}))

	s.AddTool(mcp.NewTool("control_use_network",
		mcp.WithDescription("Switch the current conversation's active network to one I am granted. Only from channel/web turns; a network-triggered turn is pinned to its network."),
		mcp.WithString("networkId", mcp.Required(), mcp.Description("the network to activate for this conversation")),
	), br.Handle("control_use_network", map[string]any{"networkId": "string"}))

	s.AddTool(mcp.NewTool("control_network_status",
		mcp.WithDescription("A compact overview of one network: agent count, instance statuses, and task counts by status."),
		mcp.WithString("networkId", mcp.Description("defaults to the current conversation's active network")),
	), br.Handle("control_network_status", map[string]any{"networkId": "string"}))

	s.AddTool(mcp.NewTool("control_list_agents",
		mcp.WithDescription("The network's agent definitions with their live instances (status/host)."),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
	), br.Handle("control_list_agents", map[string]any{"networkId": "string"}))

	s.AddTool(mcp.NewTool("control_find_agents",
		mcp.WithDescription("Deterministic candidate discovery: which agents in the network fit a resource + action."),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
		mcp.WithString("resourceKey", mcp.Description("canonical resource key (e.g. github.com/org/repo)")),
		mcp.WithString("action", mcp.Description("the action (e.g. implement, review)")),
	), br.Handle("control_find_agents", map[string]any{
		"networkId": "string", "resourceKey": "string", "action": "string",
	}))

	s.AddTool(mcp.NewTool("control_list_tasks",
		mcp.WithDescription("The network's tasks, optionally filtered by status."),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
		mcp.WithString("status", mcp.Description("pending | offered | accepted | working | blocked | completed | failed | cancelled")),
		mcp.WithNumber("limit", mcp.Description("max tasks (default 50)")),
	), br.Handle("control_list_tasks", map[string]any{
		"networkId": "string", "status": "string", "limit": "number",
	}))

	s.AddTool(mcp.NewTool("control_task_status",
		mcp.WithDescription("Read one task: state, objective, acceptance criteria, status history, dependencies, artifacts."),
		mcp.WithString("taskId", mcp.Required(), mcp.Description("the task id")),
	), br.Handle("control_task_status", map[string]any{"taskId": "string", "networkId": "string"}))

	s.AddTool(mcp.NewTool("control_list_blocked",
		mcp.WithDescription("Blocked tasks and blocked instances in the network (where work is stuck)."),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
	), br.Handle("control_list_blocked", map[string]any{"networkId": "string"}))

	s.AddTool(mcp.NewTool("control_ask",
		mcp.WithDescription("Ask an agent in the network on the human's behalf. The recipient is woken if hibernated. Requires the communicate grant."),
		mcp.WithString("body", mcp.Required(), mcp.Description("the message text")),
		mcp.WithString("toAgent", mcp.Description("recipient agent name")),
		mcp.WithString("toInstance", mcp.Description("recipient instance id (takes precedence)")),
		mcp.WithString("threadId", mcp.Description("existing thread (otherwise a new one)")),
		mcp.WithString("subject", mcp.Description("thread subject for a new thread")),
		mcp.WithString("taskId", mcp.Description("related task id")),
		mcp.WithString("resource", mcp.Description("resource key this ask is about")),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
	), br.Handle("control_ask", map[string]any{
		"body": "string", "toAgent": "string", "toInstance": "string",
		"threadId": "string", "subject": "string", "taskId": "string",
		"resource": "string", "networkId": "string",
	}))

	s.AddTool(mcp.NewTool("control_reply",
		mcp.WithDescription("Reply within an existing network thread. Requires the communicate grant."),
		mcp.WithString("threadId", mcp.Required(), mcp.Description("the thread to reply in")),
		mcp.WithString("body", mcp.Required(), mcp.Description("the reply text")),
	), br.Handle("control_reply", map[string]any{
		"threadId": "string", "body": "string", "networkId": "string",
	}))

	s.AddTool(mcp.NewTool("control_delegate",
		mcp.WithDescription("Create and delegate a durable task in the network on the human's behalf. Requires the delegate grant."),
		mcp.WithString("objective", mcp.Required(), mcp.Description("what to achieve")),
		mcp.WithString("title", mcp.Description("short title (defaults to the objective)")),
		mcp.WithArray("acceptanceCriteria", mcp.Description("how done is verified"), mcp.WithStringItems()),
		mcp.WithString("toAgent", mcp.Description("target agent name")),
		mcp.WithString("toInstance", mcp.Description("target instance id")),
		mcp.WithString("resource", mcp.Description("resource key the task is about")),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
	), br.Handle("control_delegate", map[string]any{
		"objective": "string", "title": "string", "acceptanceCriteria": "array",
		"toAgent": "string", "toInstance": "string", "resource": "string",
		"networkId": "string",
	}))

	s.AddTool(mcp.NewTool("control_wake_agent",
		mcp.WithDescription("Wake a hibernated agent in the network. Requires the operate grant."),
		mcp.WithString("toAgent", mcp.Description("agent name to wake")),
		mcp.WithString("toInstance", mcp.Description("instance id to wake (takes precedence)")),
		mcp.WithString("reason", mcp.Description("why (default explicit)")),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
	), br.Handle("control_wake_agent", map[string]any{
		"toAgent": "string", "toInstance": "string", "reason": "string", "networkId": "string",
	}))

	s.AddTool(mcp.NewTool("control_launch_agent",
		mcp.WithDescription("Launch a worker instance for a network agent definition. Requires the operate grant."),
		mcp.WithString("agentName", mcp.Description("agent definition name")),
		mcp.WithString("definitionId", mcp.Description("agent definition id (takes precedence)")),
		mcp.WithString("hostId", mcp.Description("host to launch on (default: an online host)")),
		mcp.WithString("runtime", mcp.Description("runtime override (default: the definition's)")),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
	), br.Handle("control_launch_agent", map[string]any{
		"agentName": "string", "definitionId": "string",
		"hostId": "string", "runtime": "string", "networkId": "string",
	}))

	s.AddTool(mcp.NewTool("control_stop_agent",
		mcp.WithDescription("STOP an agent instance. HIGH-RISK: requires your owner's explicit user confirmation. First call returns a confirmationId; after the owner approves, retry with confirmationId."),
		mcp.WithString("instanceId", mcp.Required(), mcp.Description("the instance to stop")),
		mcp.WithString("confirmationId", mcp.Description("an approved confirmation id (from the first call)")),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
	), br.Handle("control_stop_agent", map[string]any{
		"instanceId": "string", "confirmationId": "string", "networkId": "string",
	}))

	s.AddTool(mcp.NewTool("control_restart_agent",
		mcp.WithDescription("RESTART an agent instance (fresh session). HIGH-RISK: requires your owner's explicit user confirmation. First call returns a confirmationId; after approval, retry with confirmationId."),
		mcp.WithString("instanceId", mcp.Required(), mcp.Description("the instance to restart")),
		mcp.WithString("confirmationId", mcp.Description("an approved confirmation id (from the first call)")),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
	), br.Handle("control_restart_agent", map[string]any{
		"instanceId": "string", "confirmationId": "string", "networkId": "string",
	}))

	s.AddTool(mcp.NewTool("control_get_history",
		mcp.WithDescription("Recent domain events + messages in the network (what happened, for status answers to the human)."),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
		mcp.WithNumber("limit", mcp.Description("max entries (default 50)")),
	), br.Handle("control_get_history", map[string]any{
		"networkId": "string", "limit": "number",
	}))

	s.AddTool(mcp.NewTool("control_get_thread",
		mcp.WithDescription("Read one network thread with its messages."),
		mcp.WithString("threadId", mcp.Required(), mcp.Description("the thread id")),
	), br.Handle("control_get_thread", map[string]any{
		"threadId": "string", "networkId": "string",
	}))

	s.AddTool(mcp.NewTool("control_get_graph",
		mcp.WithDescription("The network's coordination graph: agents, instances, tasks, resources, and their edges (who runs what, who is assigned to what, who messaged whom)."),
		mcp.WithString("networkId", mcp.Description("defaults to the active network")),
	), br.Handle("control_get_graph", map[string]any{"networkId": "string"}))

	s.AddTool(mcp.NewTool("control_channel_send",
		mcp.WithDescription("Send a message back to the human on the bound channel (the current conversation, or an explicit one of yours)."),
		mcp.WithString("body", mcp.Required(), mcp.Description("the message text")),
		mcp.WithString("conversationId", mcp.Description("defaults to the current conversation")),
	), br.Handle("control_channel_send", map[string]any{
		"body": "string", "conversationId": "string",
	}))

	s.AddTool(mcp.NewTool("control_channel_history",
		mcp.WithDescription("The human conversation's message history (both directions)."),
		mcp.WithString("conversationId", mcp.Description("defaults to the current conversation")),
		mcp.WithNumber("limit", mcp.Description("max messages (default 100)")),
	), br.Handle("control_channel_history", map[string]any{
		"conversationId": "string", "limit": "number",
	}))
}
