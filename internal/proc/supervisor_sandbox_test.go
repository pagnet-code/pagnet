//go:build unix

// Supervisor-level sandbox tests (S2): the single policy point at which
// every launch class is wrapped, and the fail-closed gate that refuses a
// launch the sandbox cannot be applied to (H2/H3). The platform-specific
// behaviors are gated at runtime (sandbox.MustSandbox / sandbox.Available)
// so the file runs on Unix platforms with the supervisor's process helpers
// and /bin test commands available.
package proc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/sandbox"
)

// TestMain intercepts the S2 sandbox-wrapper re-exec: in tests the
// supervisor's SandboxWrapper is THIS test binary, so a wrapped launch
// execs `<this test binary> sandbox-exec ...`. The production pagnet
// main() intercepts that subcommand before the CLI tree; the test binary
// does the same here, before any test runs.
func TestMain(m *testing.M) {
	if len(os.Args) >= 2 && os.Args[1] == sandbox.Subcommand {
		os.Exit(sandbox.RunWrapperMain(os.Args[2:]))
	}
	os.Exit(m.Run())
}

// skipNoSandboxPlatform skips where the platform does not require the
// sandbox (darwin: honest no-op, H5) — the refusal-gate behavior under
// test only exists on sandbox-requiring platforms.
func skipNoSandboxPlatform(t *testing.T) {
	t.Helper()
	if !sandbox.MustSandbox() {
		t.Skip("this platform does not require the sandbox (H5 no-op)")
	}
}

// TestWrapSandboxed_ArgvShape pins the wrap: the supervisor-started process
// becomes `<wrapper> sandbox-exec <allowlist argv> -- <target> <args...>`
// (H1: the wrapper then execs the target IN PLACE, so the recorded PID is
// the runtime's PID).
func TestWrapSandboxed_ArgvShape(t *testing.T) {
	d := t.TempDir()
	req := LaunchRequest{
		Cmd: exec.Command("/bin/echo", "alpha", "beta"),
		Sandbox: &sandbox.Spec{
			RW:      []string{d},
			RO:      []string{"/usr"},
			Sockets: []string{filepath.Join(d, "pagnetd.sock")},
		},
	}
	if err := wrapSandboxed(&req, os.Args[0]); err != nil {
		t.Fatalf("wrapSandboxed: %v", err)
	}
	if req.Cmd.Path != os.Args[0] {
		t.Fatalf("Cmd.Path = %q, want the wrapper %q", req.Cmd.Path, os.Args[0])
	}
	wantPrefix := []string{os.Args[0], sandbox.Subcommand,
		"--rw", d,
		"--ro", "/usr",
		"--sock", filepath.Join(d, "pagnetd.sock"),
		"--",
	}
	if len(req.Cmd.Args) < len(wantPrefix) {
		t.Fatalf("args too short: %v", req.Cmd.Args)
	}
	for i, w := range wantPrefix {
		if req.Cmd.Args[i] != w {
			t.Fatalf("args[%d] = %q, want %q (full: %v)", i, req.Cmd.Args[i], w, req.Cmd.Args)
		}
	}
	tail := req.Cmd.Args[len(req.Cmd.Args)-3:]
	if tail[0] != "/bin/echo" || tail[1] != "alpha" || tail[2] != "beta" {
		t.Fatalf("args do not end with the target + its args: %v", req.Cmd.Args)
	}
}

// TestWrapSandboxed_Refusals pins the wrap's fail-closed inputs: a relative
// target (unresolvable after the wrapper's exec), a missing wrapper, and a
// wrapper that is a directory all refuse — nothing is launched.
func TestWrapSandboxed_Refusals(t *testing.T) {
	d := t.TempDir()
	mkReq := func() *LaunchRequest {
		return &LaunchRequest{
			Cmd:     exec.Command("/bin/true"),
			Sandbox: &sandbox.Spec{RW: []string{d}},
		}
	}
	// Relative target.
	rel := mkReq()
	rel.Cmd.Path = "not-absolute"
	rel.Cmd.Args = []string{"not-absolute"}
	if err := wrapSandboxed(rel, os.Args[0]); err == nil || !strings.Contains(err.Error(), "not an absolute path") {
		t.Fatalf("relative target: err = %v, want the absolute-path refusal", err)
	}
	// Missing wrapper.
	if err := wrapSandboxed(mkReq(), filepath.Join(d, "absent-wrapper")); err == nil || !strings.Contains(err.Error(), "absent-wrapper") {
		t.Fatalf("missing wrapper: err = %v, want the refusal naming the wrapper", err)
	}
	// Directory wrapper.
	if err := wrapSandboxed(mkReq(), d); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("directory wrapper: err = %v, want the directory refusal", err)
	}
}

// TestLaunch_RequireSandbox_NilSpecRefused pins H3 at the daemon boundary:
// on a sandbox-requiring platform, a launch that carries NO sandbox spec is
// refused (fail closed) when the supervisor is configured to require the
// sandbox — never launched unsandboxed.
func TestLaunch_RequireSandbox_NilSpecRefused(t *testing.T) {
	skipNoSandboxPlatform(t)
	s := newTestSupervisor(t, Config{
		MaxActiveTurns:  8,
		MonitorInterval: time.Hour,
		RequireSandbox:  true,
	})
	_, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-sb", TurnID: "turn-sb",
		Runtime: "test", Class: ClassTurn,
		Cmd: exec.Command("sleep", "3600"),
	})
	if err == nil {
		t.Fatal("spec-less launch on a sandbox-requiring platform: accepted, want a refusal")
	}
	if !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("refusal = %v, want %v", err, ErrSandboxUnavailable)
	}
	if !strings.Contains(err.Error(), "no sandbox spec") {
		t.Fatalf("refusal = %q, want the explicit no-spec reason", err)
	}
}

// TestLaunch_LandlockUnavailable_Refused pins H3's kernel branch: a spec is
// carried, but the kernel cannot provide the required Landlock protection —
// the launch is refused. The availability probe is faked via the seam; a
// kernel without Landlock or with an insufficient ABI follows the same branch.
func TestLaunch_LandlockUnavailable_Refused(t *testing.T) {
	skipNoSandboxPlatform(t)
	prev := sandboxAvailable
	sandboxAvailable = func() bool { return false }
	defer func() { sandboxAvailable = prev }()
	s := newTestSupervisor(t, Config{
		MaxActiveTurns:  8,
		MonitorInterval: time.Hour,
		RequireSandbox:  true,
		SandboxWrapper:  os.Args[0],
	})
	_, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-noll", TurnID: "turn-noll",
		Runtime: "test", Class: ClassTurn,
		Cmd:     exec.Command("sleep", "3600"),
		Sandbox: &sandbox.Spec{RW: []string{t.TempDir()}},
	})
	if err == nil {
		t.Fatal("launch with Landlock unavailable: accepted, want a refusal")
	}
	if !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("refusal = %v, want %v", err, ErrSandboxUnavailable)
	}
	if !strings.Contains(err.Error(), "Landlock ABI3 or newer") || !strings.Contains(err.Error(), "truncation protection") {
		t.Fatalf("refusal = %q, want the actionable minimum Landlock requirement", err)
	}
}

// TestLaunch_DeniedContainment_Refused pins F-CFG-1 at the single policy
// point every launch passes: a spec whose RW grant covers a Denied path —
// the $HOME-shape (a workspace that contains the daemon's state dir) — is
// refused BEFORE any process starts, with an explicit error naming the
// denied path. The target must never run.
func TestLaunch_DeniedContainment_Refused(t *testing.T) {
	skipNoSandboxPlatform(t)
	s := newTestSupervisor(t, Config{
		MaxActiveTurns:  8,
		MonitorInterval: time.Hour,
		RequireSandbox:  true,
	})
	// The $HOME shape: the workspace is the parent of the (denied) daemon
	// state dir, and the instance's session dir is the state dir's child
	// (the normal production layout — it stays granted).
	home := t.TempDir()
	stateDir := filepath.Join(home, ".pagnet")
	if err := os.MkdirAll(filepath.Join(stateDir, "sessions", "inst-dc"), 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "denied-containment-ran")
	_, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-dc", TurnID: "turn-dc",
		Runtime: "test", Class: ClassTurn,
		Cmd: exec.Command("touch", marker),
		Sandbox: sandbox.NewSpec(sandbox.Options{
			Workspace: home,
			StateDirs: []string{filepath.Join(stateDir, "sessions", "inst-dc")},
			Binary:    "/bin/true",
			Denied:    []string{stateDir},
		}),
	})
	if err == nil {
		t.Fatal("launch with a workspace covering the denied state dir: accepted, want a refusal")
	}
	if !strings.Contains(err.Error(), "denied path") || !strings.Contains(err.Error(), stateDir) {
		t.Fatalf("refusal = %q, want the explicit containment refusal naming the state dir", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatal("the target ran despite the refused launch (marker exists) — the refusal is not fail-closed")
	}
}

// TestLaunch_SandboxedTurn_RunsAndReaps proves the full path on a
// Landlock-capable kernel: the supervisor wraps the launch, the wrapper
// applies the real sandbox, execs the target IN PLACE, and the supervisor
// reaps the (wrapped) process cleanly. This is the H1/H2 integration at
// the supervisor level (the wrapper's own behavior is pinned by the
// sandbox package's re-exec tests).
func TestLaunch_SandboxedTurn_RunsAndReaps(t *testing.T) {
	skipNoSandboxPlatform(t)
	if !sandbox.Available() {
		t.Skipf("kernel %s has no Landlock", sandbox.KernelRelease())
	}
	d := t.TempDir()
	s := newTestSupervisor(t, Config{
		MaxActiveTurns:  8,
		MonitorInterval: time.Hour,
		RequireSandbox:  true,
		SandboxWrapper:  os.Args[0],
	})
	h, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-sbt", TurnID: "turn-sbt",
		Runtime: "test", Class: ClassTurn,
		Cmd:    exec.Command("/bin/true"),
		Marker: "PAGNET_TURN_ID=turn-sbt",
		Sandbox: sandbox.NewSpec(sandbox.Options{
			Workspace: d,
			Binary:    "/bin/true",
		}),
	})
	if err != nil {
		t.Fatalf("sandboxed launch: %v", err)
	}
	defer h.Close()
	waitForPID(t, h)
	if err := h.Wait(); err != nil {
		t.Fatalf("sandboxed /bin/true: Wait = %v, want a clean exit (the wrapper applied and exec'd in place)", err)
	}
}
