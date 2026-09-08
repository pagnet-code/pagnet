package daemon

// SetAllowedRoots / allowedRoots — the runtime roots replacement driven
// by host.update_roots (the server-side list is the source of truth).

import (
	"path/filepath"
	"testing"
)

func TestSetAllowedRoots(t *testing.T) {
	d := newTestDaemon(t)
	root := t.TempDir()
	other := t.TempDir()

	d.SetAllowedRoots([]string{root})
	if got := d.allowedRoots(); len(got) != 1 || got[0] != root {
		t.Fatalf("allowedRoots() = %v, want [%s]", got, root)
	}

	// The snapshot must not share backing storage with the daemon.
	d.allowedRoots()[0] = "mutated"
	if got := d.allowedRoots(); got[0] != root {
		t.Fatalf("allowedRoots() leaked backing array: %v", got)
	}

	// Containment follows the current roots.
	if !d.workspaceAllowed(filepath.Join(root, "proj")) {
		t.Fatal("a subpath of the current root must be allowed")
	}
	if d.workspaceAllowed(filepath.Join(other, "proj")) {
		t.Fatal("a path outside the current roots must be refused")
	}

	// Replacing the roots swaps enforcement atomically.
	d.SetAllowedRoots([]string{other})
	if d.workspaceAllowed(filepath.Join(root, "proj")) {
		t.Fatal("the old root must stop being allowed after replacement")
	}
	if !d.workspaceAllowed(filepath.Join(other, "proj")) {
		t.Fatal("the new root must be allowed after replacement")
	}
}
