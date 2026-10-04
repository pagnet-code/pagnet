package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pagnet-code/pagnet/internal/sandbox"
)

// This file is the per-driver construction point for the per-instance
// filesystem sandbox spec (S2, H4): every driver builds its allowlist
// from what it KNOWS for this instance through driverSandbox — the
// workspace + the instance's pagnet session/state dir (RW), the
// runtime's OWN native state dir (RW), the coarse system read + binary
// support paths (RO, via sandbox.NewSpec), the daemon bridge worker's
// binary dir (RO — the runtime EXECs it as its MCP server), and the
// daemon bridge socket. The daemon's state dir is never a grant: only
// the socket's traversal chain reaches it, so its secret file contents
// stay denied.
//
// Scratch: every driver creates <stateDir>/scratch and points the child's
// TMPDIR at it (an explicit env pair — ChildEnv guarantees it overrides
// any inherited TMPDIR, whose target, e.g. /tmp, is NOT in the
// allowlist). The scratch lives INSIDE the granted state dir (a
// path-beneath grant covers its subtree) so a driver never needs an
// extra grant to point TMPDIR somewhere writable.

// scratchName is the per-instance scratch subdir (TMPDIR target) inside
// the driver's per-instance state dir.
const scratchName = "scratch"

// scratchPath is the deterministic per-instance scratch location for a
// driver state dir: <stateDir>/scratch. The driver creates it before
// launch (H3: RW paths the spec grants must exist — the wrapper refuses
// a missing allowlist path) and both the SandboxSpec (pure) and the
// launch path (side-effecting) derive it from the same state dir, so
// they can never disagree.
func scratchPath(stateDir string) string {
	return filepath.Join(stateDir, scratchName)
}

// ensureScratch creates the per-instance scratch dir (0700) so the
// sandboxed child's TMPDIR is a real, writable, ALLOWED location.
func ensureScratch(stateDir string) (string, error) {
	dir := scratchPath(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil { // SEC-415: runtime state
		return "", fmt.Errorf("sandbox scratch %s: %w", dir, err)
	}
	return dir, nil
}

// ensureNativeDirs creates the runtime's own native state dirs (0700) before
// launch — the H3 existence guarantee for the native-dir RW grants the
// driver's spec carries: the wrapper refuses a missing mandatory (RW) path,
// and on FIRST USE the runtime's native state (e.g. ~/.claude,
// ~/.config/opencode) does not exist yet. Creating the empty owner-only dir
// is exactly what the runtime CLI does itself on its first launch, so the
// sandbox never refuses a first use. Every dir the spec grants in RW must be
// created by the launch path — this is that guarantee for the native dirs
// (workspace/sessionDir/scratch are created by the same launch path).
func ensureNativeDirs(dirs ...string) error {
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if err := os.MkdirAll(d, 0o700); err != nil { // SEC-415: runtime state
			return fmt.Errorf("sandbox native state dir %s: %w", d, err)
		}
	}
	return nil
}

// homeNativeDirs returns the runtime's own native state dirs under the
// user's home ("" home = none: an unresolvable home means the spec is
// built without them — and a missing granted path would fail the launch
// closed anyway, so nothing is silently skipped).
func homeNativeDirs(entries ...string) []string {
	home := sandbox.Home()
	if home == "" {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, filepath.Join(home, e))
	}
	return out
}

// driverSandboxOpts is what a driver knows when building the spec.
type driverSandboxOpts struct {
	// workspace: the instance's working dir (RW).
	workspace string
	// stateDir: the instance's pagnet session/state dir (RW; the scratch
	// subdir lives inside it).
	stateDir string
	// nativeDirs: the runtime's OWN native state dirs (RW) — the runtime
	// LLM auth + sessions legitimately live there (H4).
	nativeDirs []string
	// binary: the resolved runtime CLI (RO support paths derived).
	binary string
	// env: the launch env — the daemon bridge socket is recovered from
	// the daemon-rendered PAGNET_MCP_CONFIG it carries.
	env []string
	// extraRW: driver-specific RW additions.
	extraRW []string
	// denied: the containment set (F-CFG-1) — paths that must not be
	// equal to or path-beneath any RW grant (the daemon's own state dir).
	// Carried from the turn spec / session by the driver; the spec's
	// Normalize refuses a violating spec and the supervisor's wrap fails
	// the launch before any process starts.
	denied []string
}

// driverSandbox assembles the per-instance allowlist (H4). It is PURE
// (no filesystem side effects) so the Adapter's SandboxSpec method can
// derive the exact spec a launch will use; the launch path calls
// ensureScratch first so the granted scratch exists by the time the
// wrapper applies the rules.
//
// Both bridge targets are recovered from the daemon-rendered
// PAGNET_MCP_CONFIG in the launch env: the socket (its `--socket`
// argument) and the bridge worker's binary dir (its `command`) — the
// sandboxed runtime must be able to EXEC its own MCP server, or it loses
// its network tools at first use.
func driverSandbox(o driverSandboxOpts) *sandbox.Spec {
	mcp := pagnetMCPConfig(o.env)
	// Explicit finalized runtime profile HOME wins over the controller process
	// environment, exactly as ChildEnv does when constructing the launched child.
	var home string
	for _, pair := range o.env {
		if key, value, ok := strings.Cut(pair, "="); ok && key == "HOME" {
			home = value
		}
	}
	return sandbox.NewSpec(sandbox.Options{
		Workspace:  o.workspace,
		StateDirs:  []string{o.stateDir},
		NativeDirs: o.nativeDirs,
		Binary:     o.binary,
		Home:       home,
		Socket:     sandbox.SocketFromMCPConfig(mcp),
		BridgeDir:  sandbox.BridgeDirFromMCPConfig(mcp),
		ExtraRW:    o.extraRW,
		Denied:     o.denied,
	})
}

// fakeBridgeResultDir returns the directory of the
// PAGNET_FAKE_BRIDGE_RESULT_FILE test knob found in env ("" when unset):
// the S1 bridge e2e fixture writes its observed-response file there, so
// a sandboxed fake runtime needs that one test-scoped dir in RW. It is
// the documented PAGNET_FAKE_* simulation namespace (the same class as
// the other fake knobs), never a production path.
func fakeBridgeResultDir(env []string) string {
	for _, kv := range env {
		if strings.HasPrefix(kv, "PAGNET_FAKE_BRIDGE_RESULT_FILE=") {
			p := strings.TrimPrefix(kv, "PAGNET_FAKE_BRIDGE_RESULT_FILE=")
			if p != "" {
				return filepath.Dir(p)
			}
		}
	}
	return ""
}
