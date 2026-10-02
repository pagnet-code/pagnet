//go:build !linux && !darwin

package crypto

import (
	"context"
	"errors"
)

func lockContextKeyring(context.Context, string, bool) (func(), error) {
	return nil, errors.New("protected context process-safe authority locking is unsupported")
}

func lockNetworkKeyring(_ context.Context, _ string, exclusive bool) (func(), error) {
	if exclusive {
		return func() {}, nil
	} // Legacy atomic network storage remains available.
	return nil, errors.New("network process-safe authority locking is unsupported")
}
