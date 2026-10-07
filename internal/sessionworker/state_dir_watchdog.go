package sessionworker

import (
	"context"
	"os"
	"time"
)

// stateDirWatchInterval is the period at which a worker re-checks that its
// own state directory still exists. Package-level so tests can shorten it;
// the watchdog captures it once at start, so concurrent tests never race on
// the variable.
var stateDirWatchInterval = 30 * time.Second

// stateDirGone reports whether err is a strict ENOENT for the watched path.
// Any other result (nil, EACCES, ...) must NOT retire the worker: the
// directory may still exist and the worker may still be recoverable.
func stateDirGone(err error) bool { return os.IsNotExist(err) }

// stateDirWatchdog retires the worker when its own state directory
// disappears. Recovery reads the native_workers registry FROM the worker
// state dir, so a worker whose dir is deleted can never be recovered — it
// is a zombie by the design's own standard and must self-exit. Two
// consecutive strict-ENOENT Lstat results call cancel (the existing ctx
// plumbing closes owner/journal/servers for a clean exit); any other result
// resets the consecutive counter. The goroutine exits when ctx completes.
func stateDirWatchdog(ctx context.Context, dir string, cancel context.CancelFunc) {
	interval := stateDirWatchInterval
	go func() {
		consecutive := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
			}
			_, err := os.Lstat(dir)
			if !stateDirGone(err) {
				consecutive = 0
				continue
			}
			if consecutive++; consecutive >= 2 {
				cancel()
				return
			}
		}
	}()
}
