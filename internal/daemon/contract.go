package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"pagnet/internal/domain"
	"pagnet/internal/transport"
)

// writeContract (re)renders the pagnet coordination contract (§16:
// "inject a short coordination contract into every managed agent") for the
// instance. It returns the file path the runtime is pointed at AND the
// rendered text: the daemon appends the text to a fresh session's first
// turn (§23/§24 — the contract must reach the model, not just the
// environment). It is idempotent and safe to call per turn: the file
// lives in the daemon state dir, never in the workspace.
//
// The contract is kind-aware: workers get the network_* surface and the
// capability-declaration duty; representatives get the control_* surface
// and the channel-reply duty (a human only sees control_channel_send).
func (d *Daemon) writeContract(row *InstanceRow) (string, string, error) {
	name := row.AgentName
	if name == "" {
		name = "agent"
	}
	var text string
	if row.Kind == "representative" {
		text = fmt.Sprintf(`PAGNET COORDINATION CONTRACT

You are a representative: a persistent agent that acts on a human's
behalf across the pagnet networks they have granted you. You are not a
worker of any single network.

Use the control_* MCP tools to see and act on those networks:
control_list_networks / control_use_network to switch context,
control_list_agents / control_find_agents to discover peers,
control_ask / control_delegate / control_wake_agent to work with them.

When a human messages you (a delivery whose <pagnet-message> has
kind="channel"), reply with control_channel_send so the answer reaches
them in the channel. Plain turn output is NOT delivered to the human.

Never use a runtime-native SendMessage/subagent tool to contact a
pagnet peer; runtime-native tools are only for workers owned by this
runtime session.

Your pagnet identity:
  agent:    %s
  instance: %s
  networks: via your grants (control_list_networks)
`, name, row.InstanceID)
	} else {
		network := row.NetworkID
		if network == "" {
			network = "(unscoped)"
		}
		text = fmt.Sprintf(`PAGNET COORDINATION CONTRACT

You are a persistent member of an pagnet network.

There are two different kinds of agents available to you:

1. LOCAL RUNTIME SUBAGENTS
   These are temporary workers created by your current runtime.
   Use the runtime's native agent/subagent mechanisms for them.

2. PAGNET NETWORK PEERS
   These are persistent agents registered in pagnet and may run on
   another runtime, repository, machine, or server.
   Always use the network_* MCP tools to discover, ask, delegate,
   reply to, or coordinate with these agents.

Never use a runtime-native SendMessage/subagent tool to contact an
pagnet peer.

If work belongs to a resource you do not own, discover the responsible
pagnet peer instead of modifying that resource yourself.

When you receive a message from a human or a pagnet peer (a delivery
whose <pagnet-message> has kind="ask" or kind="reply"), reply with
network_reply using the thread id from the message attributes — or
network_ask to start a new thread. Plain turn output is NOT delivered
to the sender.

Capabilities: the capabilities set by your operator on your definition
are fixed — you can read them (network_whoami) but you cannot change
them. When you understand your mission, declare the capabilities you
can actually perform for it with network_register_capabilities (id,
name, description). Declare what you can do, not what you may do.

Your pagnet identity:
  agent:    %s
  network:  %s
  instance: %s
`, name, network, row.InstanceID)
	}

	// SEC-407 (defense in depth): the id becomes a path component — a
	// non-UUID can never reach the join.
	if _, err := domain.ParseID(row.InstanceID); err != nil {
		return "", "", fmt.Errorf("invalid instance id for contract: %s", row.InstanceID)
	}
	path := filepath.Join(d.StateDir, "contracts", row.InstanceID+".md")
	// SEC-415: coordination state is operator data, not public.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return "", "", err
	}
	return path, text, nil
}

// deliveryInput renders the turn input for a network delivery as a
// self-describing XML envelope. The message body is wrapped in
// <pagnet-message> with routing attributes, and a <pagnet-action> block
// states the immediate action for THIS delivery kind. XML tags are the
// de-facto standard for structuring LLM prompt context, and the envelope
// makes "this is a network message, not a human at your terminal" explicit
// in every delivery. It complements the standing coordination contract:
// the contract explains the model (once, at session start), the envelope
// says what to do right now — so even a resumed session that predates the
// contract still carries the reply duty on each message.
func deliveryInput(row *InstanceRow, p transport.NetworkEventPayload) string {
	kind := p.Kind
	if kind == "" {
		kind = "notice"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<pagnet-message kind=%s from=%s", xmlAttr(kind), xmlAttr(p.FromAgent))
	switch kind {
	case "ask", "reply":
		if p.ThreadID != "" {
			fmt.Fprintf(&b, " thread=%s", xmlAttr(p.ThreadID))
		}
		if p.MessageID != "" {
			fmt.Fprintf(&b, " message-id=%s", xmlAttr(p.MessageID))
		}
	case "task":
		if p.TaskID != "" {
			fmt.Fprintf(&b, " task-id=%s", xmlAttr(p.TaskID))
		}
	case "channel":
		if p.ConversationID != "" {
			fmt.Fprintf(&b, " conversation=%s", xmlAttr(p.ConversationID))
		}
		if p.NetworkID != "" {
			fmt.Fprintf(&b, " network=%s", xmlAttr(p.NetworkID))
		}
		if p.MessageID != "" {
			fmt.Fprintf(&b, " message-id=%s", xmlAttr(p.MessageID))
		}
	}
	b.WriteString(">\n")
	// The body and criteria are untrusted (another agent or a human wrote
	// them): escape them so they cannot close the element and inject fake
	// <pagnet-action> instructions into the recipient's prompt.
	b.WriteString(xmlText(p.Body))
	if len(p.AcceptanceCriteria) > 0 {
		crits := make([]string, len(p.AcceptanceCriteria))
		for i, c := range p.AcceptanceCriteria {
			crits[i] = xmlText(c)
		}
		b.WriteString("\n\nAcceptance criteria:\n- " + strings.Join(crits, "\n- "))
	}
	b.WriteString("\n</pagnet-message>\n\n<pagnet-action>\n")
	switch kind {
	case "ask", "reply":
		if p.ThreadID != "" {
			fmt.Fprintf(&b, "This is a message from a pagnet network participant, not a human at your terminal.\nAnswer it, then deliver your answer with the network_reply tool (threadId: %s).\nPlain turn output is NOT delivered to the sender — only pagnet tool calls are.\n", p.ThreadID)
		} else {
			b.WriteString("This is a message from a pagnet network participant, not a human at your terminal.\nAnswer it, then deliver your answer with the network_ask tool (toAgent: the sender).\nPlain turn output is NOT delivered to the sender — only pagnet tool calls are.\n")
		}
	case "task":
		fmt.Fprintf(&b, "This is a delegated task. Work on it in your workspace, update its state with network_task_update (taskId: %s), and deliver results with network_publish_artifact.\n", dashOr(p.TaskID))
	case "channel":
		fmt.Fprintf(&b, "This is a message from a human in your channel, not a pagnet peer.\nReply with the control_channel_send tool (conversation: %s) so the answer reaches them in the channel.\nPlain turn output is NOT delivered to the human.\n", dashOr(p.ConversationID))
	default: // status, notice, user_input
		b.WriteString("No reply is required. Act on it if it is relevant to your mission.\n")
	}
	b.WriteString("</pagnet-action>")
	return b.String()
}

// xmlAttr escapes a value for use inside a double-quoted XML attribute.
func xmlAttr(s string) string {
	if s == "" {
		s = "unknown"
	}
	return `"` + strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;",
	).Replace(s) + `"`
}

// xmlText escapes untrusted content for use inside an XML element.
func xmlText(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;",
	).Replace(s)
}
