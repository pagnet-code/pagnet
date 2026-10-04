//go:build !linux && !darwin && !windows

package privatefs

import (
	"errors"
	"io"
)

func Acquire(string, string) (io.Closer, error) {
	return nil, errors.New("exclusive private private state locking is unavailable on this platform")
}
func ReadFile(string, int) ([]byte, error) {
	return nil, errors.New("private state file verification is unavailable on this platform")
}
func CheckFile(string, int64) error {
	return errors.New("private private state database verification is unavailable on this platform")
}

func CreateDirectory(string) error {
	return errors.New("private private state bootstrap is unavailable on this platform")
}
func Publish(string, string) error {
	return errors.New("durable private file installation is unavailable on this platform")
}
func SyncDirectory(string, ...string) error {
	return errors.New("durable private metadata synchronization is unavailable on this platform")
}
