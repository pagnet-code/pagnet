//go:build !linux && !darwin

package sessionworker

import (
	"context"
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

func readPrivateFile(string, int) ([]byte, error) {
	return nil, errors.New("private session worker bootstrap unsupported")
}
func workerSignals(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(ctx)
}
