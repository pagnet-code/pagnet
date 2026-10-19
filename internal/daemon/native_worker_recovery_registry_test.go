//go:build linux || darwin

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func TestNativeWorkerRecoveryDurableFenceAndPhases(t *testing.T) {
	registry, scope, spec := nativeRegistryFixture(t)
	original, err := registry.Reserve(scope, spec, "original", "")
	if err != nil {
		t.Fatal(err)
	}
	recovery := NativeWorkerRecovery{RecoveryID: domain.NewID().String(), InstanceID: scope.InstanceID, OriginalGeneration: scope.Generation, PrepareBootIdentity: "linux-boot-id:11111111-1111-4111-8111-111111111111", Phase: "prepared"}
	if got, err := registry.PrepareRecovery(recovery); err != nil || got != recovery {
		t.Fatalf("prepare: %+v err=%v", got, err)
	}
	var synchronous int
	if err := registry.db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil || synchronous != 2 {
		t.Fatalf("recovery commits lack FULL fsync: mode=%d err=%v", synchronous, err)
	}
	for _, phase := range []string{"prepared", "committed", "collected"} {
		if phase != "prepared" {
			from := "prepared"
			if phase == "collected" {
				from = "committed"
			}
			if err := registry.AdvanceRecoveryPhase(recovery.RecoveryID, from, phase); err != nil {
				t.Fatal(err)
			}
			if err := registry.AdvanceRecoveryPhase(recovery.RecoveryID, from, phase); err != nil {
				t.Fatal("exact phase replay rejected", err)
			}
		}
		replay, err := registry.PrepareRecovery(recovery)
		if err != nil || replay.Phase != phase {
			t.Fatalf("prepare replay regressed phase: %+v err=%v", replay, err)
		}
		reopened, err := OpenNativeWorkerRegistry(filepath.Dir(registry.root))
		if err != nil {
			t.Fatal(err)
		}
		got, lookupErr := reopened.LookupRecovery(recovery.RecoveryID)
		fenced, fenceErr := reopened.RecoveryTombstoned(scope.InstanceID, scope.Generation)
		reopened.Close()
		if lookupErr != nil || got != replay || fenceErr != nil || !fenced {
			t.Fatalf("durable %s fence missing: %+v lookup=%v fence=%v", phase, got, lookupErr, fenceErr)
		}
		if _, err := registry.Reserve(scope, spec, "original", ""); err == nil {
			t.Fatalf("%s tombstone allowed reservation replay", phase)
		}
		if err := EnsureNativeWorker(context.Background(), registry, original, "/does-not-exist", nil, ""); err == nil || !strings.Contains(err.Error(), "fenced by recovery") {
			t.Fatalf("%s tombstone did not refuse activation: %v", phase, err)
		}
		if _, err := os.Stat(original.Dir); !os.IsNotExist(err) {
			t.Fatalf("fenced activation created bootstrap state: %v", err)
		}
		d := &Daemon{nativeRegistry: registry, nativeWorkers: map[string]*nativeWorkerLink{scope.InstanceID: {proxy: &NativeWorkerProxy{scope: scope}}}}
		if _, err := d.nativeWorkerFor(nil, scope.InstanceID); err == nil {
			t.Fatalf("%s tombstone allowed cached worker reuse", phase)
		}
		if err := d.connectNativeWorker(nil, nil, original); err == nil {
			t.Fatalf("%s tombstone allowed cached connection activation", phase)
		}
	}
	if err := registry.AdvanceRecoveryPhase(recovery.RecoveryID, "prepared", "committed"); err == nil {
		t.Fatal("stale phase CAS accepted after collection")
	}
	if fenced, err := registry.RecoveryTombstoned(scope.InstanceID, domain.NewID().String()); err != nil || fenced {
		t.Fatalf("different generation incorrectly fenced: %v %v", fenced, err)
	}
}

func TestNativeWorkerRecoveryIdentityAndTransitionConflicts(t *testing.T) {
	registry, scope, spec := nativeRegistryFixture(t)
	if _, err := registry.Reserve(scope, spec, "original", ""); err != nil {
		t.Fatal(err)
	}
	original := NativeWorkerRecovery{RecoveryID: domain.NewID().String(), InstanceID: scope.InstanceID, OriginalGeneration: scope.Generation, PrepareBootIdentity: "linux-boot-id:11111111-1111-4111-8111-111111111111", Phase: "prepared"}
	if _, err := registry.PrepareRecovery(original); err != nil {
		t.Fatal(err)
	}
	changes := []func(*NativeWorkerRecovery){
		func(r *NativeWorkerRecovery) { r.RecoveryID = domain.NewID().String() },
		func(r *NativeWorkerRecovery) { r.InstanceID = domain.NewID().String() },
		func(r *NativeWorkerRecovery) { r.OriginalGeneration = domain.NewID().String() },
		func(r *NativeWorkerRecovery) { r.PrepareBootIdentity = "different-boot" },
		func(r *NativeWorkerRecovery) { r.Phase = "committed" },
		func(r *NativeWorkerRecovery) { r.PrepareBootIdentity = "" },
		func(r *NativeWorkerRecovery) { r.RecoveryID = strings.Repeat("x", 129) },
	}
	for index, change := range changes {
		changed := original
		change(&changed)
		if _, err := registry.PrepareRecovery(changed); err == nil {
			t.Fatalf("recovery identity mutation %d accepted", index)
		}
	}
	if err := registry.AdvanceRecoveryPhase(original.RecoveryID, "prepared", "collected"); err == nil {
		t.Fatal("skipped phase accepted")
	}
	if err := registry.AdvanceRecoveryPhase(original.RecoveryID, "committed", "collected"); err == nil {
		t.Fatal("wrong prior phase accepted")
	}
	if got, err := registry.LookupRecovery(original.RecoveryID); err != nil || got != original {
		t.Fatalf("conflicts mutated identity: %+v err=%v", got, err)
	}
}

func TestNativeWorkerRecoveryConcurrentExactReplay(t *testing.T) {
	registry, scope, spec := nativeRegistryFixture(t)
	if _, err := registry.Reserve(scope, spec, "original", ""); err != nil {
		t.Fatal(err)
	}
	recovery := NativeWorkerRecovery{RecoveryID: domain.NewID().String(), InstanceID: scope.InstanceID, OriginalGeneration: scope.Generation, PrepareBootIdentity: "linux-boot-id:11111111-1111-4111-8111-111111111111", Phase: "prepared"}
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			got, err := registry.PrepareRecovery(recovery)
			if err != nil || got != recovery {
				t.Errorf("concurrent replay: %+v err=%v", got, err)
			}
		}()
	}
	group.Wait()
	var count int
	if err := registry.db.QueryRow(`SELECT COUNT(*) FROM native_worker_recoveries`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate recovery rows: count=%d err=%v", count, err)
	}
	registry.Close()
	if fenced, err := registry.RecoveryTombstoned(scope.InstanceID, scope.Generation); err == nil || !fenced {
		t.Fatalf("registry failure did not fail closed: %v %v", fenced, err)
	}
}
