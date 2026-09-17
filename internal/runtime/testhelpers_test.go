package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// p0FakeBinary builds (when stale/missing) the pagnet-fake-runtime
// fixture binary into the scratch dir (NEVER into the repo's bin/). It
// returns an ABSOLUTE path: the adapter sets cmd.Dir to the workspace,
// and a relative binary path would be resolved against that directory
// (fork/exec ENOENT).
//
// The helper is platform-independent (go build + stat) and is shared by
// the linux-only P0 leak fixtures and the platform-agnostic persistent
// fake tests, so it lives in an ungated file.
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
		if src, err := os.Stat(filepath.Join("..", "..", "cmd", "pagnet-fake-runtime", "main.go")); err == nil && fi.ModTime().After(src.ModTime()) {
			needBuild = false
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
