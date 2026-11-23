//go:build linux || darwin

package sessionworker

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireWorkerLifetimeLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireWorkerLifetimeLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := AcquireWorkerLifetimeLock(dir); !errors.Is(err, ErrWorkerOwned) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("live ownership not excluded: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "intents.sqlite")); !os.IsNotExist(err) {
		t.Fatal("lock opened journal")
	}
	if err = lock.Close(); err != nil {
		t.Fatal(err)
	}
	retry, err := AcquireWorkerLifetimeLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	retry.Close()
}
