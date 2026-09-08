//go:build linux

package main

import "golang.org/x/sys/unix"

// setRawInput puts stdin in raw mode (see the comment in runPTY) and
// returns a restore function. Linux exposes TCGETS/TCSETS, so the REPL
// can clear ECHOCTL as well and own ALL input echo.
func setRawInput(fd int) func() {
	var old *unix.Termios
	if t, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
		old = t
		raw := *t
		raw.Lflag &^= unix.ICANON | unix.ISIG | unix.ECHO | unix.ECHOCTL
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, &raw)
		return func() {
			if old != nil {
				_ = unix.IoctlSetTermios(fd, unix.TCSETS, old)
			}
		}
	}
	return func() {}
}
