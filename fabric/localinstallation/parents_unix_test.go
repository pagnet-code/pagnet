//go:build linux || darwin

package localinstallation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitBootstrapParentsKeepSecretLeafAbsentAndSocketPrivate(t *testing.T) {
	root, e := os.MkdirTemp("", "pgn-install-parents-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		t.Fatal(e)
	}
	directory := filepath.Join(root, "state", "fabric", "authority")
	socket := filepath.Join(root, "state", "run", "fabric", "local.sock")
	settings := DefaultSettings(socket)
	if e = PrepareBootstrapParents(directory, settings); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(directory); !os.IsNotExist(e) {
		t.Fatal("parent preparation precreated secret authority")
	}
	info, e := os.Stat(filepath.Dir(socket))
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("direct socket parent not private", e)
	}
	// Configuration rejection comes before parent creation, so a socket inside
	// authority cannot accidentally precreate an unusable secret installation.
	other := filepath.Join(root, "not-created", "authority")
	if e = PrepareBootstrapParents(other, DefaultSettings(filepath.Join(other, "run", "socket"))); e == nil {
		t.Fatal("socket inside authority accepted")
	}
	if _, e = os.Lstat(filepath.Dir(other)); !os.IsNotExist(e) {
		t.Fatal("invalid settings prepared private state")
	}
	if e = os.Chmod(filepath.Dir(socket), 0755); e != nil {
		t.Fatal(e)
	}
	if e = PrepareBootstrapParents(directory, settings); e == nil {
		t.Fatal("nonprivate socket parent accepted")
	}
	info, e = os.Stat(filepath.Dir(socket))
	if e != nil || info.Mode().Perm() != 0755 {
		t.Fatal("existing socket parent permissions silently changed", e)
	}
}
