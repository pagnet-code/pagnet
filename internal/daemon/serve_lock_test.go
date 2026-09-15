package daemon

import "testing"

// TestServeLockExcludesSecondDaemon (external audit F-006): a second
// daemon with the same state dir must fail to acquire the serve lock while
// the first holds it, and succeed after the first releases. Without the
// lock, two daemons on one host would both run and fight over the host
// identity (each new connection supersedes the other) and double-launch
// processes.
func TestServeLockExcludesSecondDaemon(t *testing.T) {
	d := newTestDaemon(t)

	release, err := d.acquireServeLock()
	if err != nil {
		t.Fatalf("first daemon acquireServeLock: %v", err)
	}

	// A second daemon with the same state dir must be refused.
	if _, err := d.acquireServeLock(); err == nil {
		t.Fatal("second daemon acquired the serve lock while the first holds it")
	}

	// After the first releases, the second can acquire.
	release()
	release2, err := d.acquireServeLock()
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	release2()
}
