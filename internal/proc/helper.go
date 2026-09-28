package proc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pagnet-code/pagnet/internal/sandbox"
)

// Helper is the bounded short-lived-command executor (§37): git probes,
// runtime version checks, worktree operations. Every helper command
// runs under a caller-supplied context timeout AND a global
// concurrency limit, so inventory/discovery can never spawn hundreds of
// git processes in parallel (§36).
type Helper struct {
	sem chan struct{}
}

// NewHelper bounds concurrent helper commands to concurrency (0 = 4).
func NewHelper(concurrency int) *Helper {
	if concurrency <= 0 {
		concurrency = 4
	}
	return &Helper{sem: make(chan struct{}, concurrency)}
}

// Run executes one bounded helper command and returns its stdout.
// ctx MUST carry a timeout (the caller owns the policy: 3s for version
// probes, 5s for git probes, 60s for worktree operations).
func (h *Helper) Run(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	if err := h.acquire(ctx); err != nil {
		return nil, err
	}
	defer h.release()
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	return cmd.Output()
}

// RunCombined is Run with combined output (callers that need the error
// text on failure, e.g. git worktree operations).
func (h *Helper) RunCombined(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	if err := h.acquire(ctx); err != nil {
		return nil, err
	}
	defer h.release()
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	return cmd.CombinedOutput()
}

// RunSandboxed is Run through the sandbox wrapper (S2) for helper commands
// that exec UNTRUSTED binaries — the runtime CLI version probes
// (--version/-v). The runtime is an LLM with shell access; even its
// "version" entrypoint is its code, so it is probed under the same
// fail-closed filesystem policy as a full launch (brief default: sandbox
// the probe). `wrapper` is the pagnet binary ("" = os.Executable());
// `spec` is the allowlist (for a probe: no RW — a version probe writes
// nothing — plus the coarse system read and the runtime's binary support
// paths).
//
// On Linux this FAILS CLOSED: no Landlock or a missing allowlist path makes
// the wrapper child refuse (non-zero exit), and the probe reports failure —
// an unverified runtime is unavailable, never probed unsandboxed. On
// non-Linux the wrapper is an honest passthrough (H5). Combined output is
// returned so a refusal's explicit security error is visible to the caller.
func (h *Helper) RunSandboxed(ctx context.Context, wrapper string, spec *sandbox.Spec, dir, name string, args ...string) ([]byte, error) {
	if err := h.acquire(ctx); err != nil {
		return nil, err
	}
	defer h.release()
	if spec == nil {
		return nil, fmt.Errorf("sandboxed helper: missing sandbox spec (fail closed)")
	}
	if err := spec.Normalize(); err != nil {
		return nil, fmt.Errorf("sandboxed helper: spec: %w (fail closed)", err)
	}
	if !filepath.IsAbs(name) {
		return nil, fmt.Errorf("sandboxed helper: target %q must be an absolute path (fail closed)", name)
	}
	w := wrapper
	if w == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("sandboxed helper: wrapper (os.Executable): %w (fail closed)", err)
		}
		w = exe
	}
	if st, err := os.Stat(w); err != nil {
		return nil, fmt.Errorf("sandboxed helper: wrapper %s: %w (fail closed)", w, err)
	} else if st.IsDir() {
		return nil, fmt.Errorf("sandboxed helper: wrapper %s is a directory (fail closed)", w)
	}
	cmd := exec.CommandContext(ctx, w,
		append([]string{sandbox.Subcommand}, sandbox.WrapperArgs(spec, name, args)...)...)
	if dir != "" {
		cmd.Dir = dir
	}
	return cmd.CombinedOutput()
}

func (h *Helper) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("helper command cancelled while waiting for a slot: %w", ctx.Err())
	}
}

func (h *Helper) release() { <-h.sem }

// DefaultHelperConcurrency is the default helper concurrency bound.
const DefaultHelperConcurrency = 4
