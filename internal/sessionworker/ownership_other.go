//go:build !linux && !darwin

package sessionworker

import (
	"errors"
	"io"
)

func acquireOwnership(string) (io.Closer, error) {
	return nil, errors.New("private session worker ownership is unsupported on this platform")
}

func removeStaleSocket(string) error {
	return errors.New("private session worker transport unsupported")
}
func privateSocket(string) error { return errors.New("private session worker transport unsupported") }
