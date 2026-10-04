//go:build !linux && !darwin

package fabricnative

import "os/exec"

func launcherSupported() bool      { return false }
func detachWorker(*exec.Cmd) error { return launchDenied() }
