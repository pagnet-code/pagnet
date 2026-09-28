//go:build !linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The non-Linux platform is an HONEST no-op (H5): no kernel boundary
// exists, the launch is NOT sandboxed, and the platform is reported as
// non-isolated. These tests pin that contract: the wrapper is a pure
// passthrough (still in-place exec, H1), and nothing pretends to have
// applied a boundary.

func TestPlatformFlags(t *testing.T) {
	if MustSandbox() {
		t.Fatal("MustSandbox = true on a non-Linux platform; the launch would be refused by design (it must PROCEED non-isolated)")
	}
	if Available() {
		t.Fatal("Available = true on a non-Linux platform; no Landlock exists here")
	}
	if LandlockAvailable() {
		t.Fatal("LandlockAvailable = true on a non-Linux platform")
	}
}

func TestApply_IsValidationOnly(t *testing.T) {
	s := &Spec{RW: []string{"/a"}, RO: []string{"/b"}}
	if err := Apply(s); err != nil {
		t.Fatalf("Apply(valid): %v — the no-op apply must only validate the spec", err)
	}
	bad := &Spec{RW: []string{"relative"}}
	if err := Apply(bad); err == nil {
		t.Fatal("Apply(relative path): accepted, want the fail-closed validation error")
	}
}

// TestWrapperPassthrough runs the real wrapper path (re-exec'd child): it
// must exec the target in place WITHOUT a sandbox — the probe therefore
// finds EVERYTHING allowed (that is the honest, documented behavior:
// non-isolated by design, reported as unsupported_platform).
func TestWrapperPassthrough(t *testing.T) {
	base := t.TempDir()
	rwDir := filepath.Join(base, "rw")
	roDir := filepath.Join(base, "ro")
	secretDir := filepath.Join(base, "secret")
	for _, d := range []string{rwDir, roDir, secretDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(roDir, "rofile"), filepath.Join(secretDir, "secret.txt")} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spec := &Spec{RW: []string{rwDir}, RO: []string{roDir, "/bin", "/usr", "/proc/self"}}
	out := filepath.Join(rwDir, "probe-result.json")
	res, wc, err := runSandboxedProbe(t, spec, out, map[string]string{
		"PROBE_SECRET": filepath.Join(secretDir, "secret.txt"),
		"PROBE_EXEC":   "/bin/true",
	})
	if err != nil {
		t.Fatalf("runSandboxedProbe: %v", err)
	}
	if wc.code != 0 {
		t.Fatalf("probe child exit %d (stderr: %s)", wc.code, wc.stderr)
	}
	// Honest no-op: nothing is restricted. (In particular the secret IS
	// readable here — the platform reports itself non-isolated, so this is
	// expected and documented, not a test failure.)
	assertProbe(t, res,
		"rwWrite", "ok",
		"rwRead", "ok",
		"roRead", "ok",
		"roWrite", "ok",
		"secret", "ok",
		"exec", "ok",
	)
	if res.NoNewPrivs != "0" && !strings.HasPrefix(res.NoNewPrivs, "err:") {
		t.Errorf("NoNewPrivs = %q, want 0 (no privilege boundary is installed on this platform)", res.NoNewPrivs)
	}
}
