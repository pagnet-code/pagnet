//go:build windows

package daemon

import "errors"

// Native host execution needs Job Object containment and ConPTY support.
// Remote CLI, SDK and external MCP clients do not require a local daemon.
var errWindowsHostUnsupported = errors.New("native Windows host execution is not supported yet; run the Pagnet host daemon in WSL2 or on Linux/macOS, and use this client for remote operations")

func (d *Daemon) acquireServeLock() (func(), error)                { return nil, errWindowsHostUnsupported }
func (d *Daemon) adoptServeLock(path, fdStr string) (func(), bool) { return nil, false }
func (d *Daemon) serveLockExecEnv() (string, error)                { return "", errWindowsHostUnsupported }
func readDiskFree(path string) (int64, error)                      { return 0, errWindowsHostUnsupported }
func reexecDaemon(path string, args, env []string) error           { return errWindowsHostUnsupported }

func hostPlatformError() error { return errWindowsHostUnsupported }
