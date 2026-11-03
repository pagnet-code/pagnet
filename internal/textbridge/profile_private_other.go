//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package textbridge

import (
	"context"
	"errors"
)

// PrivateDir creates or checks a private directory owned by the current OS user.
func PrivateDir(string) error {
	return errors.New("text bridge private storage is unsupported on this platform")
}

// ReadPrivate reads a bounded private regular file without following symlinks.
func ReadPrivate(string, int64) ([]byte, error) {
	return nil, errors.New("text bridge private storage is unsupported on this platform")
}

// LockProfile takes the nonblocking exclusive local responder lock.
func LockProfile(string) (func(), error) {
	return nil, errors.New("text bridge private locking is unsupported on this platform")
}

// LockProfilePolicy takes the exclusive cross-process policy lock. When both
// locks are needed, acquire run.lock before policy.lock; never acquire run.lock
// while holding policy.lock.
func LockProfilePolicy(ctx context.Context, _ string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("text bridge private locking is unsupported on this platform")
}
