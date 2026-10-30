//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package textbridge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func textBridgePrivateTestDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestTextBridgePrivateDir(t *testing.T) {
	root := textBridgePrivateTestDir(t)
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "new", "private")
	if err := PrivateDir(path); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Dir(path), path} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("directory mode: %v, %v", info, err)
		}
	}
	if err := PrivateDir(root); err == nil {
		t.Fatal("accepted public final directory")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Dir(path), link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, filepath.Join(link, "private"), link + "/../new/private"} {
		if err := PrivateDir(p); err == nil {
			t.Fatalf("accepted symlink component %q", p)
		}
	}
}

func TestTextBridgeReadPrivate(t *testing.T) {
	root := textBridgePrivateTestDir(t)
	path := filepath.Join(root, "credentials")
	secret := "sensitive-test-content"
	if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadPrivate(path, int64(len(secret)))
	if err != nil || string(data) != secret {
		t.Fatalf("private read failed: %v", err)
	}
	if data, err := ReadPrivate(path, 3); err == nil || data != nil || strings.Contains(err.Error(), secret) {
		t.Fatal("oversized read did not fail safely")
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(path, 100); err == nil {
		t.Fatal("accepted public file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(link, 100); err == nil {
		t.Fatal("accepted symlink file")
	}
	dirLink := filepath.Join(root, "directory-link")
	if err := os.Symlink(root, dirLink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(filepath.Join(dirLink, "credentials"), 100); err == nil {
		t.Fatal("accepted symlink parent directory")
	}
	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fifo, root} {
		if _, err := ReadPrivate(p, 100); err == nil {
			t.Fatal("accepted nonregular file")
		}
	}
}

func TestTextBridgeLock(t *testing.T) {
	root := textBridgePrivateTestDir(t)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(root, "directory-link")
	if err := os.Symlink(root, dirLink); err != nil {
		t.Fatal(err)
	}
	if unlock, err := LockProfile(dirLink); err == nil {
		unlock()
		t.Fatal("accepted symlink lock directory")
	}
	unlock, err := LockProfile(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if other, err := LockProfile(root); err == nil {
		other()
		t.Fatal("acquired contended lock")
	}
	unlock()
	unlock()
	other, err := LockProfile(root)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	other()
	path := filepath.Join(root, "run.lock")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if unlock, err := LockProfile(root); err == nil {
		unlock()
		t.Fatal("accepted insecure lock file")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "target"), path); err != nil {
		t.Fatal(err)
	}
	if unlock, err := LockProfile(root); err == nil {
		unlock()
		t.Fatal("accepted symlink lock file")
	}
}

func TestTextBridgePrivateUnsafeAncestors(t *testing.T) {
	root := textBridgePrivateTestDir(t)
	parent := filepath.Join(root, "writable")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "private")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(child, "credentials")
	if err := os.WriteFile(file, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(child); err == nil {
		t.Fatal("accepted world-writable ancestor without sticky bit")
	}
	if _, err := ReadPrivate(file, 100); err == nil {
		t.Fatal("read through world-writable ancestor without sticky bit")
	}
	if unlock, err := LockProfile(child); err == nil {
		unlock()
		t.Fatal("locked through world-writable ancestor without sticky bit")
	}
}

func TestTextBridgePrivateStickyAncestor(t *testing.T) {
	root := textBridgePrivateTestDir(t)
	// The standard temporary directory is normally a root-owned sticky
	// directory; the user-owned temporary child must remain usable.
	if err := PrivateDir(root); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		t.Skip("creating root-owned sticky directory requires root")
	}
	sticky := filepath.Join(root, "sticky")
	if err := os.Mkdir(sticky, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, os.ModeSticky|0777); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(sticky, "private")
	if err := PrivateDir(child); err != nil {
		t.Fatalf("rejected user-owned child of sticky directory: %v", err)
	}
	foreign := filepath.Join(sticky, "foreign")
	if err := os.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(foreign, 1, -1); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(filepath.Join(foreign, "private")); err == nil {
		t.Fatal("accepted foreign-owned child of sticky directory")
	}
}

func TestTextBridgePrivateForeignAncestor(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("changing directory ownership requires root")
	}
	root := textBridgePrivateTestDir(t)
	parent := filepath.Join(root, "foreign")
	child := filepath.Join(parent, "private")
	if err := os.MkdirAll(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 1, -1); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(child); err == nil {
		t.Fatal("accepted foreign-owned writable ancestor")
	}
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(child); err == nil {
		t.Fatal("accepted foreign-owned ancestor")
	}
}
