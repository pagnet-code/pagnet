//go:build !linux

package main

import "golang.org/x/term"

// setRawInput puts stdin in raw mode off Linux via x/term (TCGETS/TCSETS
// do not exist on Darwin). x/term's MakeRaw does not clear ECHOCTL, so the
// kernel may still echo a few control characters — the fake runtime is a
// Linux test fixture, so this degraded echo is acceptable.
func setRawInput(fd int) func() {
	if state, err := term.MakeRaw(fd); err == nil {
		return func() { _ = term.Restore(fd, state) }
	}
	return func() {}
}
