package runtime

import (
	"os"
	"os/exec"
	"strings"
	"sync"
)

// ChildEnv builds the environment for a spawned runtime process.
//
// The inherited environment is FILTERED before anything else is appended:
// runtime processes are untrusted (an LLM with shell access), and the
// daemon's own environment may carry control-plane material —
// PAGNET_* (admin/host credentials, runtime knobs), database DSNs —
// that must never be readable from an agent (spec §5/§15/§86.10).
//
// Explicit pairs passed by the caller (adapter knobs, per-instance
// injection like the MCP bridge config and the identity vars) are
// appended after the filter, in order, and always win. Provider API keys
// (ANTHROPIC_API_KEY, DASHSCOPE_API_KEY, ...) are NOT on the blocklist and
// keep flowing through — the runtimes need them.
func ChildEnv(extra ...[]string) []string {
	out := make([]string, 0, len(os.Environ())+8)
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if !ok || isControlPlaneEnvKey(key) {
			continue
		}
		out = append(out, kv)
	}
	for _, pairs := range extra {
		out = append(out, pairs...)
	}
	return out
}

// isControlPlaneEnvKey reports whether an inherited env key must not reach
// an agent process: pagnet's own configuration/credentials, plus
// database connection strings.
func isControlPlaneEnvKey(key string) bool {
	switch {
	case strings.HasPrefix(key, "PAGNET_"):
		return true
	case key == "DATABASE_URL" || key == "TEST_DATABASE_URL":
		return true
	case strings.HasPrefix(key, "POSTGRES_") || strings.HasPrefix(key, "PGPASS"):
		return true
	}
	return false
}

// procTracker tracks the running turn process per instance so adapters can
// answer Stop and PID (§59) consistently.
type procTracker struct {
	mu    sync.Mutex
	procs map[string]*exec.Cmd
}

func (t *procTracker) track(instanceID string, cmd *exec.Cmd) {
	t.mu.Lock()
	t.procs[instanceID] = cmd
	t.mu.Unlock()
}

// release drops the entry if it still points at cmd (a later turn may have
// replaced it).
func (t *procTracker) release(instanceID string, cmd *exec.Cmd) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur, ok := t.procs[instanceID]; ok && cur == cmd {
		delete(t.procs, instanceID)
	}
}

func (t *procTracker) stop(instanceID string) error {
	t.mu.Lock()
	cmd := t.procs[instanceID]
	t.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		return cmd.Process.Kill()
	}
	return nil
}

func (t *procTracker) pid(instanceID string) *int {
	t.mu.Lock()
	cmd := t.procs[instanceID]
	t.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		p := cmd.Process.Pid
		return &p
	}
	return nil
}
