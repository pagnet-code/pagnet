//go:build !linux && !darwin && !windows

package registry

import (
	"errors"
	"io"
)

func lockDirectory(string) (io.Closer, error) {
	return nil, errors.New("exclusive private registry locking is unavailable on this platform")
}
func readPrivate(string, int) ([]byte, error) {
	return nil, errors.New("private registry state verification is unavailable on this platform")
}
func checkPrivateDatabase(string, int64) error {
	return errors.New("private registry database verification is unavailable on this platform")
}

func createPrivateDirectory(string) error {
	return errors.New("private registry bootstrap is unavailable on this platform")
}
func publishPrivate(string, string) error {
	return errors.New("durable private file installation is unavailable on this platform")
}
func syncDirectory(string) error {
	return errors.New("durable private metadata synchronization is unavailable on this platform")
}
