//go:build darwin

package sandbox

import (
	"fmt"
	"os"
)

// MustSandbox remains false until production Darwin runtime probes pass.
// The supervisor continues to launch Darwin runtimes directly, non-isolated.
func MustSandbox() bool { return false }

// Available remains false so the daemon does not advertise Darwin isolation.
func Available() bool { return false }

// LandlockAvailable is false because Darwin uses Seatbelt, not Landlock.
func LandlockAvailable() bool { return false }

// KernelRelease has no Landlock kernel release to report on Darwin.
func KernelRelease() string { return "" }

// Apply only validates the spec. Darwin isolation requires the explicit wrapper
// entrypoint, which execs /usr/bin/sandbox-exec before running the target.
func Apply(spec *Spec) error { return spec.Normalize() }

// RunWrapper applies Seatbelt only when explicitly invoked through the hidden
// sandbox-exec command. Failures refuse the launch without an unsandboxed fallback.
func RunWrapper(argv []string) error { return RunDarwinWrapper(argv) }

// RunWrapperMain returns a failure code if the sandboxed exec cannot proceed.
func RunWrapperMain(argv []string) int {
	if err := RunWrapper(argv); err != nil {
		fmt.Fprintln(os.Stderr, "pagnet sandbox-exec:", err)
		return 1
	}
	return 0
}
