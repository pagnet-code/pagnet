package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// p0FakeBinary builds (when stale/missing) the pagnet-fake-runtime
// fixture binary into the scratch dir (NEVER into the repo's bin/) and
// returns an ABSOLUTE path (the adapter sets cmd.Dir to the workspace;
// a relative binary path would resolve against that directory).
//
// The helper is platform-independent (go build + stat) and is shared by
// the linux-only PTY leak fixtures and the platform-agnostic persistent
// delivery tests, so it lives in an ungated file.
func p0FakeBinary(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("PAGNET_P0_BIN_DIR")
	if dir == "" {
		abs, err := filepath.Abs(filepath.Join("..", "..", "..", ".qwen", "tmp", "p0-bin"))
		if err != nil {
			t.Fatalf("resolve scratch bin dir: %v", err)
		}
		dir = abs
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir scratch bin dir: %v", err)
	}
	bin := filepath.Join(dir, "pagnet-fake-runtime")
	needBuild := true
	if fi, err := os.Stat(bin); err == nil {
		// Track the NEWEST source file in the package (not just main.go):
		// the fake runtime spans multiple files (main.go, persistent.go,
		// ...), and a change to ANY of them must trigger a rebuild — a
		// main.go-only check silently serves a stale binary after a
		// non-main.go edit.
		srcFiles, gerr := filepath.Glob(filepath.Join("..", "..", "cmd", "pagnet-fake-runtime", "*.go"))
		if gerr == nil {
			var newest time.Time
			for _, f := range srcFiles {
				if s, serr := os.Stat(f); serr == nil && s.ModTime().After(newest) {
					newest = s.ModTime()
				}
			}
			if !newest.IsZero() && fi.ModTime().After(newest) {
				needBuild = false
			}
		}
	}
	if needBuild {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(ctx, "go", "build",
			"-o", bin, filepath.Join("..", "..", "cmd", "pagnet-fake-runtime")).CombinedOutput()
		if err != nil {
			t.Fatalf("build fake runtime fixture: %v\n%s", err, out)
		}
	}
	return bin
}
