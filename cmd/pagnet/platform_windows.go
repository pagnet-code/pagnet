//go:build windows

package main

import (
	"errors"
	"syscall"
	"time"

	"golang.org/x/term"
)

func detachedProcessAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008 /* DETACHED_PROCESS */}
}

// Windows consoles expose dimensions through GetConsoleScreenBufferInfo,
// not SIGWINCH. Send only dimension changes, and stop polling on detach.
func watchTerminalResize(fd int, resize func(int, int)) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		lastCols, lastRows, _ := term.GetSize(fd)
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				cols, rows, err := term.GetSize(fd)
				if err == nil && (cols != lastCols || rows != lastRows) {
					lastCols, lastRows = cols, rows
					resize(cols, rows)
				}
			}
		}
	}()
	return func() { close(done) }
}

func hostPlatformError() error {
	return errors.New("native Windows host execution is not supported yet; run pagnet serve in WSL2 or on Linux/macOS")
}
