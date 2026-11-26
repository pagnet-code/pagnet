//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

var errDirectEndpointLocalBusy = errors.New("direct endpoint local state is busy or unavailable")

// These helpers attempt acquisition once, without changing the caller's lock
// order. Cancellation observed after acquisition releases the lock immediately.
func directEndpointTryLock(ctx context.Context, mu *sync.Mutex) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	locked := mu.TryLock()
	if err := ctx.Err(); err != nil {
		if locked {
			mu.Unlock()
		}
		return nil, err
	}
	if !locked {
		return nil, errDirectEndpointLocalBusy
	}
	return mu.Unlock, nil
}

func directEndpointTryRLock(ctx context.Context, mu *sync.RWMutex) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	locked := mu.TryRLock()
	if err := ctx.Err(); err != nil {
		if locked {
			mu.RUnlock()
		}
		return nil, err
	}
	if !locked {
		return nil, errDirectEndpointLocalBusy
	}
	return mu.RUnlock, nil
}

func directEndpointTryFlock(ctx context.Context, file *os.File) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// EINTR also fails promptly: endpoint work must never retry a local lock.
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	unlock := func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN) }
	if ctxErr := ctx.Err(); ctxErr != nil {
		if err == nil {
			unlock()
		}
		return nil, ctxErr
	}
	if err != nil {
		return nil, errDirectEndpointLocalBusy
	}
	return unlock, nil
}

func directEndpointTryNativeRegistryCustodyLock(ctx context.Context, root *os.File) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lock, err := nativeRegistryCustodyOpenLock(root)
	if err != nil {
		return nil, err
	}
	if _, err = directEndpointTryFlock(ctx, lock); err == nil {
		err = lock.Sync()
	}
	if err == nil {
		err = root.Sync()
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		lock.Close()
		return nil, err
	}
	return lock, nil
}

func directEndpointTryNativeShareHolderLockMode(ctx context.Context, directory *os.File, create bool) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lock, err := nativeShareHolderOpenLock(directory, create)
	if err != nil {
		return nil, err
	}
	if _, err = directEndpointTryFlock(ctx, lock); err == nil && create {
		err = lock.Sync()
		if err == nil {
			err = directory.Sync()
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		lock.Close()
		return nil, err
	}
	return lock, nil
}
