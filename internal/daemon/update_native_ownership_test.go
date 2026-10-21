//go:build linux || darwin

package daemon

import "testing"

func TestUpdateDefersForDetachedNativeOwnership(t *testing.T) {
	for _, state := range []string{"reserved", "launching", "launched"} {
		t.Run(state, func(t *testing.T) {
			d := newTestDaemon(t)
			registry, scope, spec := nativeRegistryFixture(t)
			d.nativeRegistry = registry
			if _, err := registry.Reserve(scope, spec, "original", ""); err != nil {
				t.Fatal(err)
			}
			if _, err := registry.db.Exec(`UPDATE native_workers SET launch_state=? WHERE instance_id=?`, state, scope.InstanceID); err != nil {
				t.Fatal(err)
			}
			if err := d.state.UpsertInstance(InstanceRow{InstanceID: scope.InstanceID, DefinitionID: "def-1", Runtime: string(spec.Runtime), Status: "idle"}); err != nil {
				t.Fatal(err)
			}
			// No attached native link, turn, PTY, or supervisor endpoint exists.
			assertNativeOwnershipBlocksUpdate(t, d)
		})
	}
}

func TestUpdateDefersWhenNativeRegistryUnknown(t *testing.T) {
	for _, failure := range []string{"read", "identity"} {
		t.Run(failure, func(t *testing.T) {
			d := newTestDaemon(t)
			registry, scope, spec := nativeRegistryFixture(t)
			d.nativeRegistry = registry
			if failure == "read" {
				if err := registry.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := registry.Reserve(scope, spec, "original", ""); err != nil {
					t.Fatal(err)
				}
				if _, err := registry.db.Exec(`UPDATE native_workers SET payload='{}' WHERE instance_id=?`, scope.InstanceID); err != nil {
					t.Fatal(err)
				}
			}
			assertNativeOwnershipBlocksUpdate(t, d)
		})
	}
}

func assertNativeOwnershipBlocksUpdate(t *testing.T, d *Daemon) {
	t.Helper()
	if n := d.activeWorkCount(); n != 1 {
		t.Fatalf("native ownership or unknown registry must count as busy, got %d", n)
	}
	if d.finalizeIdleUpdate(func() { t.Fatal("finalized with native ownership or unknown registry") }) {
		t.Fatal("accepted busy update")
	}
	d.performAutoUpdate("1.0.1")
	if !d.lastAttempt.IsZero() {
		t.Fatal("native ownership must defer before attempting a download")
	}
}

func TestUpdatePermittedWithoutNativeOwnership(t *testing.T) {
	for _, registryPresent := range []bool{false, true} {
		name := "no registry"
		if registryPresent {
			name = "empty registry"
		}
		t.Run(name, func(t *testing.T) {
			d := newTestDaemon(t)
			if registryPresent {
				d.nativeRegistry, _, _ = nativeRegistryFixture(t)
			}
			if n := d.activeWorkCount(); n != 0 {
				t.Fatalf("no native ownership must remain idle, got %d", n)
			}
			called := false
			if !d.finalizeIdleUpdate(func() { called = true }) || !called {
				t.Fatal("idle daemon without native ownership must permit finalization")
			}
			d.ServerURL = "" // Fail download before network I/O, after admission.
			d.performAutoUpdate("1.0.1")
			if d.lastAttempt.IsZero() {
				t.Fatal("idle daemon without native ownership must attempt the update")
			}
		})
	}
}
