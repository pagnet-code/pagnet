//go:build linux || darwin

package fabricnative

import (
	"os/exec"
	"syscall"
)

func launcherSupported() bool        { return true }
func detachWorker(c *exec.Cmd) error { c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}; return nil }
