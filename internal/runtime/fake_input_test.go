//go:build !windows

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/sandbox"
)

func TestFakeEarlyExitPreservesStderrOnInputFailure(t *testing.T) {
	if sandbox.MustSandbox() && !sandbox.Available() {
		t.Skip("kernel has no Landlock")
	}
	workspace := t.TempDir()
	binary := filepath.Join(workspace, "fake-early-exit")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf 'explicit early runtime refusal\\n' >&2\nexit 23\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Larger than a pipe buffer, so the input writer cannot finish before
	// the child exits without reading. This deterministically produces EPIPE.
	err := NewFake(binary).StartTurn(ctx, TurnSpec{InstanceID: "early-exit", TurnID: "early-input", Workspace: workspace, SessionDir: t.TempDir(), Input: strings.Repeat("x", 1<<20)}, make(chan TurnEvent, 8))
	if err == nil || !strings.Contains(err.Error(), "explicit early runtime refusal") || !strings.Contains(err.Error(), "fake runtime input") {
		t.Fatalf("early child failure lost stderr diagnostics: %v", err)
	}
}
