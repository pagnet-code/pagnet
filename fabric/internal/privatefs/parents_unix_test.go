//go:build linux || darwin

package privatefs

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func parentFixture(t *testing.T) string {
	t.Helper()
	dir, e := os.MkdirTemp("", "pgn-private-parents-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	dir, e = filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	return dir
}
func TestPrepareParentsCreatesOnlyVerifiedParentsNotSecretLeaf(t *testing.T) {
	root := parentFixture(t)
	target := filepath.Join(root, "new", "nested", "authority")
	if e := PrepareParents(target); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(target); !os.IsNotExist(e) {
		t.Fatal("parent preparation created secret leaf")
	}
	for _, dir := range []string{filepath.Join(root, "new"), filepath.Join(root, "new", "nested")} {
		if e := verifyOwnedParent(dir); e != nil {
			t.Fatal(e)
		}
		info, e := os.Stat(dir)
		if e != nil || info.Mode().Perm() != 0700 {
			t.Fatal("new parent not private", e)
		}
	}
	if e := PrepareParents(target); e != nil {
		t.Fatal("existing verified parent not reusable", e)
	}
}
func TestPrepareParentsRejectsLinksForeignAndSharedWriters(t *testing.T) {
	for _, mode := range []string{"symlink", "shared-writer", "foreign-owner"} {
		t.Run(mode, func(t *testing.T) {
			root := parentFixture(t)
			anchor := filepath.Join(root, "existing")
			if e := os.Mkdir(anchor, 0700); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "symlink":
				destination := filepath.Join(root, "target")
				if e := os.Rename(anchor, destination); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(destination, anchor); e != nil {
					t.Fatal(e)
				}
			case "shared-writer":
				if e := os.Chmod(anchor, 0777); e != nil {
					t.Fatal(e)
				}
			case "foreign-owner":
				if os.Getuid() != 0 {
					// The real filesystem root is owned by UID 0. Verify this
					// foreign kernel owner directly; no chown or fake UID.
					var st unix.Stat_t
					if err := unix.Stat(string(filepath.Separator), &st); err != nil {
						t.Fatal(err)
					}
					if st.Uid == uint32(os.Getuid()) {
						t.Fatal("filesystem root unexpectedly has fixture owner")
					}
					if err := verifyOwnedParent(string(filepath.Separator)); err == nil {
						t.Fatal("foreign kernel owner accepted")
					}
					return
				}
				if e := unix.Chown(anchor, 12345, 12345); e != nil {
					t.Fatal(e)
				}
				defer unix.Chown(anchor, os.Getuid(), os.Getgid())
			}
			target := filepath.Join(anchor, "created", "authority")
			if e := PrepareParents(target); e == nil {
				t.Fatal("unsafe existing parent accepted")
			}
			if _, e := os.Lstat(filepath.Join(anchor, "created")); !os.IsNotExist(e) {
				t.Fatal("unsafe parent created state before rejection")
			}
		})
	}
}
