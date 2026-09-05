package daemon

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeContract (re)renders the pagnet coordination contract (§16:
// "inject a short coordination contract into every managed agent") for the
// instance and returns the file path the runtime is pointed at. It is
// idempotent and safe to call per turn: the file lives in the daemon state
// dir, never in the workspace.
func (d *Daemon) writeContract(row *InstanceRow) (string, error) {
	name := row.AgentName
	if name == "" {
		name = "agent"
	}
	network := row.NetworkID
	if network == "" {
		network = "(unscoped)"
	}
	text := fmt.Sprintf(`PAGNET COORDINATION CONTRACT

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

Your pagnet identity:
  agent:    %s
  network:  %s
  instance: %s
`, name, network, row.InstanceID)

	path := filepath.Join(d.StateDir, "contracts", row.InstanceID+".md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
