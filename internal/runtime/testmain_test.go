package runtime

import (
	"fmt"
	"os"
	"testing"

	"github.com/pagnet-code/pagnet/internal/sandbox"
)

// TestMain (S2) — two duties before the suite runs:
//
//  1. Intercept the sandbox-wrapper re-exec. On sandbox-requiring
//     platforms (Linux) the supervisor wraps EVERY launch that carries a
//     spec — including the launches these adapter tests drive through the
//     private supervisor (proc.DefaultConfig) — and an empty
//     SandboxWrapper resolves to os.Executable(): THIS test binary. The
//     production pagnet main() intercepts the `sandbox-exec` subcommand
//     before the CLI tree; the test binary must do the same here, before
//     any test runs. Without it the re-exec falls through to the Go test
//     main and (re)runs the whole suite as the "runtime" — the wrapped
//     process never reaches its target and the driving test blocks on its
//     stdout forever (the same seam daemon and proc use in their
//     TestMains).
//
//  2. Hermetic HOME. The per-instance spec grants the runtime's own
//     native state dirs under $HOME (H4), and the launch path creates
//     them before launch (H3: every granted RW path must exist — first
//     use on a fresh host included). Pointing HOME at a scratch dir keeps
//     the suite from creating or touching the real user's ~/.claude,
//     ~/.qwen, ~/.codex, ~/.config/opencode, ... and makes the first-use
//     creation path (native dir missing → launch path creates it)
//     deterministic.
func TestMain(m *testing.M) {
	if len(os.Args) >= 2 && os.Args[1] == sandbox.Subcommand {
		os.Exit(sandbox.RunWrapperMain(os.Args[2:]))
	}
	if len(os.Args) >= 2 && os.Args[1] == "claude-stream-fixture" {
		os.Exit(runClaudeStreamFixture())
	}
	if len(os.Args) >= 2 && os.Args[1] == "opencode-acp-fixture" {
		os.Exit(runOpenCodeACPFixture())
	}
	if len(os.Args) >= 2 && os.Args[1] == "grok-acp-fixture" {
		os.Exit(runGrokACPFixture())
	}
	home, err := os.MkdirTemp("", "pagnet-runtime-test-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "runtime TestMain: temp home:", err)
		os.Exit(1)
	}
	if err := os.Setenv("HOME", home); err != nil {
		fmt.Fprintln(os.Stderr, "runtime TestMain: set HOME:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}
