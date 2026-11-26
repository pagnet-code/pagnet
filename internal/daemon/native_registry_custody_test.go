//go:build linux || darwin

package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

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
