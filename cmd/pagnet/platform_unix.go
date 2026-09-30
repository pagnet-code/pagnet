//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

func detachedProcessAttrs() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }

// Signal registration and the resize goroutine both end with the attach.
func watchTerminalResize(fd int, resize func(int, int)) func() {
	events := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(events, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-events:
				if cols, rows, err := term.GetSize(fd); err == nil {
					resize(cols, rows)
				}
			}
		}
	}()
	return func() { signal.Stop(events); close(done) }
}

func hostPlatformError() error { return nil }
