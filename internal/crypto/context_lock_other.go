//go:build !linux && !darwin

package crypto

import (
	"context"
	"errors"
)

func lockContextKeyring(context.Context, string, bool) (func(), error) {
	return nil, errors.New("protected context process-safe authority locking is unsupported")
}
