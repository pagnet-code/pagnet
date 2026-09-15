//go:build !unix

package proc

import (
	"errors"
	"syscall"
)

// Non-Unix platforms (Windows, §53): the supervisor's platform seams
// exist but are not implemented yet — Windows will use Job Objects for
// process-tree ownership. Every call fails explicitly (fail closed):
// pagnet refuses to run a turn it cannot contain rather than spawning
// uncontained processes.

var errUnsupported = errors.New("proc: process containment is not implemented on this platform")

// GroupAttrs is unsupported here.
func GroupAttrs() *syscall.SysProcAttr { return nil }

// SessionAttrs is unsupported here.
func SessionAttrs() *syscall.SysProcAttr { return nil }

// SignalGroup is unsupported here.
func SignalGroup(pgid int, sig syscall.Signal) error { return errUnsupported }

// ErrGroupGone reports that a process group no longer exists.
var ErrGroupGone = errors.New("process group no longer exists")

// GroupAlive is unsupported here (reports false: nothing verifiable).
func GroupAlive(pgid int) bool { return false }

// ProcessAlive is unsupported here.
func ProcessAlive(pid int) bool { return false }

// ProcessLimit is unsupported here (0 = unknown).
func ProcessLimit() int { return 0 }

// CountGroup is unsupported here.
func CountGroup(pgid int) int { return 0 }

// CountOwned is unsupported here.
func CountOwned(groups map[int]bool) int { return 0 }

// CountGroups is unsupported here.
func CountGroups(groups map[int]bool) map[int]int { return map[int]int{} }

// GroupMembers is unsupported here.
func GroupMembers(pgid int) []int { return nil }

// GroupHasLiveMember is unsupported here (reports false: nothing
// verifiable, consistent with GroupAlive).
func GroupHasLiveMember(pgid int) bool { return false }

// UserProcessCount is unsupported here.
func UserProcessCount() (int, error) { return 0, errUnsupported }

// StartIdentity is unsupported here.
func StartIdentity(pid int) (string, error) { return "", errUnsupported }

// EnvHasMarker is unsupported here.
func EnvHasMarker(pid int, marker string) (bool, error) { return false, ErrMarkerUnavailable }
