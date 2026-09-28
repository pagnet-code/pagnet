//go:build !linux

package sandbox

import (
	"fmt"
	"os"
	"syscall"
)

// MustSandbox is false on non-Linux (H5): no Landlock exists, so the launch
// is NOT sandboxed and the platform is reported as non-isolated
// (unsupported_platform). Activation proceeds on owner-scoped dev machines.
func MustSandbox() bool { return false }

// Available is false on non-Linux (Landlock is Linux-only). Here false means
// "non-isolated by design", not "failure" — the supervisor must check
// MustSandbox() to tell the two apart.
func Available() bool { return false }

// LandlockAvailable is false on non-Linux.
func LandlockAvailable() bool { return false }

// KernelRelease is "" on non-Linux (there is no Landlock to report on).
func KernelRelease() string { return "" }

// Apply is an honest no-op on platforms without Landlock (H5): it validates
// the spec but applies no kernel boundary. The launch is NOT sandboxed; the
// platform state is reported as unsupported.
func Apply(spec *Spec) error {
	return spec.Normalize()
}

// RunWrapper is an honest no-op passthrough on non-Linux: it validates the
// spec, then EXECs the target IN PLACE without a sandbox (H1 still holds —
// in-place exec, stable PID). The supervisor does not invoke the wrapper on
// non-Linux (it launches the target directly), so this path is only reached
// if someone runs `pagnet sandbox-exec` by hand on a non-Linux host.
func RunWrapper(argv []string) error {
	spec, target, targetArgs, err := ParseWrapperArgs(argv)
	if err != nil {
		return err
	}
	if err := spec.Normalize(); err != nil {
		return err
	}
	if err := syscall.Exec(target, append([]string{target}, targetArgs...), os.Environ()); err != nil {
		return fmt.Errorf("exec %s: %v", target, err)
	}
	return nil // unreachable on a successful exec
}

// RunWrapperMain runs the wrapper and returns the process exit code. On
// success it never returns (exec replaces the process).
func RunWrapperMain(argv []string) int {
	if err := RunWrapper(argv); err != nil {
		fmt.Fprintln(os.Stderr, "pagnet sandbox-exec:", err)
		return 1
	}
	return 0
}
