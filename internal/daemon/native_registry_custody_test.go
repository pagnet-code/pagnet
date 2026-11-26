//go:build linux || darwin

package daemon

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func registryCustodyState(t *testing.T) string {
	t.Helper()
	state := t.TempDir()
	if e := os.Chmod(state, 0700); e != nil {
		t.Fatal(e)
	}
	return state
}
func TestNativeRegistryCustodyRejectsUnsafeFiles(t *testing.T) {
	for _, name := range []string{"registry.sqlite", "registry.sqlite-wal", "registry.sqlite-shm", "registry.sqlite-journal", "registry.custody.lock"} {
		for _, kind := range []string{"symlink", "hardlink", "mode", "fifo"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				state := registryCustodyState(t)
				root := filepath.Join(state, "native-workers")
				if e := os.Mkdir(root, 0700); e != nil {
					t.Fatal(e)
				}
				if name != "registry.sqlite" {
					if e := os.WriteFile(filepath.Join(root, "registry.sqlite"), nil, 0600); e != nil {
						t.Fatal(e)
					}
				}
				sentinel := filepath.Join(state, "sentinel")
				content := []byte("sentinel must remain unchanged")
				if e := os.WriteFile(sentinel, content, 0600); e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(root, name)
				var e error
				switch kind {
				case "symlink":
					e = os.Symlink(sentinel, path)
				case "hardlink":
					e = os.Link(sentinel, path)
				case "mode":
					e = os.WriteFile(path, content, 0644)
				case "fifo":
					e = unix.Mkfifo(path, 0600)
				}
				if e != nil {
					t.Fatal(e)
				}
				if r, e := OpenNativeWorkerRegistry(state); e == nil {
					r.Close()
					t.Fatal("unsafe custody file accepted")
				}
				actual, e := os.ReadFile(sentinel)
				if e != nil || !bytes.Equal(actual, content) {
					t.Fatal("sentinel modified")
				}
				if kind == "mode" {
					info, e := os.Lstat(path)
					if e != nil || info.Mode().Perm() != 0644 {
						t.Fatal("unsafe file repaired")
					}
				}
			})
		}
	}
}
func TestNativeRegistryCustodyRejectsOrphansAndAncestors(t *testing.T) {
	for _, name := range []string{"registry.sqlite-wal", "registry.sqlite-shm", "registry.sqlite-journal"} {
		t.Run(name, func(t *testing.T) {
			state := registryCustodyState(t)
			root := filepath.Join(state, "native-workers")
			if e := os.Mkdir(root, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(root, name), []byte("orphan"), 0600); e != nil {
				t.Fatal(e)
			}
			if r, e := OpenNativeWorkerRegistry(state); e == nil {
				r.Close()
				t.Fatal("orphan accepted")
			}
			if _, e := os.Lstat(filepath.Join(root, "registry.sqlite")); !os.IsNotExist(e) {
				t.Fatal("database created before orphan rejection")
			}
		})
	}
	t.Run("writable ancestor", func(t *testing.T) {
		base := registryCustodyState(t)
		ancestor := filepath.Join(base, "unsafe")
		state := filepath.Join(ancestor, "private")
		if e := os.MkdirAll(state, 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(ancestor, 0777); e != nil {
			t.Fatal(e)
		}
		if r, e := OpenNativeWorkerRegistry(state); e == nil {
			r.Close()
			t.Fatal("writable ancestor accepted")
		}
		if _, e := os.Stat(filepath.Join(state, "native-workers")); !os.IsNotExist(e) {
			t.Fatal("created descendants under unsafe ancestor")
		}
	})
	t.Run("symlink ancestor", func(t *testing.T) {
		base := registryCustodyState(t)
		target := filepath.Join(base, "target")
		if e := os.Mkdir(target, 0700); e != nil {
			t.Fatal(e)
		}
		link := filepath.Join(base, "link")
		if e := os.Symlink(target, link); e != nil {
			t.Fatal(e)
		}
		if r, e := OpenNativeWorkerRegistry(link); e == nil {
			r.Close()
			t.Fatal("symlink ancestor accepted")
		}
	})
}
func TestNativeRegistryCloseWaitsForCustody(t *testing.T) {
	r, err := OpenNativeWorkerRegistry(registryCustodyState(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	root, err := nativeRegistryProtectedDirectory(r.root)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	custody, err := nativeRegistryCustodyLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	// Wait until Close has entered its critical section before checking that
	// custody blocks it, so an unscheduled goroutine cannot satisfy the test.
	deadline := time.Now().Add(5 * time.Second)
	for r.mu.TryLock() {
		r.mu.Unlock()
		select {
		case err := <-closed:
			t.Fatalf("Close returned while custody was held: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not enter its critical section")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-closed:
		t.Fatalf("Close returned while custody was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := r.db.Ping(); err != nil {
		t.Fatalf("database closed while custody was held: %v", err)
	}
	if err := custody.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish after custody release")
	}
}

func TestNativeRegistryCloseCustodyFailureIsRetryable(t *testing.T) {
	for _, name := range []string{".", "registry.custody.lock"} {
		t.Run(name, func(t *testing.T) {
			r, err := OpenNativeWorkerRegistry(registryCustodyState(t))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(r.root, name)
			mode := os.FileMode(0600)
			if name == "." {
				mode = 0700
			}
			t.Cleanup(func() {
				_ = os.Chmod(path, mode)
				_ = r.Close()
			})
			if err := os.Chmod(path, mode|0044); err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err == nil {
				t.Fatal("Close accepted unsafe custody")
			}
			if err := r.db.Ping(); err != nil {
				t.Fatalf("custody failure closed the database: %v", err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatalf("Close retry failed: %v", err)
			}
		})
	}
}

func TestNativeRegistryCloseFailureReportedByDaemon(t *testing.T) {
	d := newTestDaemon(t)
	r := d.nativeRegistry
	t.Cleanup(func() {
		_ = os.Chmod(r.root, 0700)
		_ = r.Close()
	})
	if err := os.Chmod(r.root, 0744); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); !errors.Is(err, errNativeShareHolder) {
		t.Fatalf("Close did not report registry custody failure: %v", err)
	}
	if d.turnCtx.Err() == nil {
		t.Fatal("registry failure interrupted daemon shutdown")
	}
}

func TestNativeRegistryCustodyConcurrentSafeOpens(t *testing.T) {
	state := registryCustodyState(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := OpenNativeWorkerRegistry(state)
			if e == nil {
				e = r.Close()
			}
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	r, e := OpenNativeWorkerRegistry(state)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	root, e := nativeShareHolderDirectory(r.root)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if _, e = nativeRegistryInspectFiles(root, r.custodyIdentity, false); e != nil {
		t.Fatal(e)
	}
}
func TestDirectEnrollmentRechecksCustodyBeforeWrite(t *testing.T) {
	for _, name := range []string{"registry.sqlite", "registry.sqlite-wal", "registry.sqlite-shm"} {
		t.Run(name, func(t *testing.T) {
			j, s, b, _ := enrollmentFixture(t)
			path := filepath.Join(j.registry.root, name)
			if _, e := os.Stat(path); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(path, 0644); e != nil {
				t.Fatal(e)
			}
			if _, e := j.reserve(s, b); e == nil {
				t.Fatal("unsafe secret-write path accepted")
			}
			info, e := os.Stat(path)
			if e != nil || info.Mode().Perm() != 0644 {
				t.Fatal("unsafe permissions repaired")
			}
		})
	}
}
