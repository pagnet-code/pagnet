package proc

import (
	"context"
	"fmt"
	"os/exec"
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
