package daemon

import (
	"fmt"
	"os"
	"path/filepath"

	"pagnet/internal/domain"
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

When a human messages you (a [pagnet channel] turn), reply with
control_channel_send so the answer reaches them in the channel.
Plain turn output is NOT delivered to the human.

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
