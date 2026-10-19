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
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeWorkerRecoveryDurableFenceAndPhases(t *testing.T) {
	registry, scope, spec := nativeRegistryFixture(t)
	original, err := registry.Reserve(scope, spec, "original", "")
	if err != nil {
		t.Fatal(err)
	}
	recovery := NativeWorkerRecovery{RecoveryID: domain.NewID().String(), InstanceID: scope.InstanceID, OriginalGeneration: scope.Generation, Action: "replace", PrepareBoot: recoveryBoot("11111111-1111-4111-8111-111111111111"), FenceBoot: recoveryBoot("11111111-1111-4111-8111-111111111111"), LocalGeneration: scope.Generation, Phase: "prepared"}
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
	original := NativeWorkerRecovery{RecoveryID: domain.NewID().String(), InstanceID: scope.InstanceID, OriginalGeneration: scope.Generation, Action: "replace", PrepareBoot: recoveryBoot("11111111-1111-4111-8111-111111111111"), FenceBoot: recoveryBoot("11111111-1111-4111-8111-111111111111"), LocalGeneration: scope.Generation, Phase: "prepared"}
	if _, err := registry.PrepareRecovery(original); err != nil {
		t.Fatal(err)
	}
	changes := []func(*NativeWorkerRecovery){
		func(r *NativeWorkerRecovery) { r.Action = "delete" },
		func(r *NativeWorkerRecovery) { r.FenceBoot.Identity = "22222222-2222-4222-8222-222222222222" },
		func(r *NativeWorkerRecovery) { r.OriginalBoot = r.PrepareBoot },
		func(r *NativeWorkerRecovery) { r.PrepareBoot.Source = "darwin_bootsessionuuid" },
		func(r *NativeWorkerRecovery) { r.LocalGeneration = "" },
		func(r *NativeWorkerRecovery) { r.RecoveryID = domain.NewID().String() },
		func(r *NativeWorkerRecovery) { r.InstanceID = domain.NewID().String() },
		func(r *NativeWorkerRecovery) { r.OriginalGeneration = domain.NewID().String() },
		func(r *NativeWorkerRecovery) { r.PrepareBoot.Identity = "22222222-2222-4222-8222-222222222222" },
		func(r *NativeWorkerRecovery) { r.Phase = "committed" },
		func(r *NativeWorkerRecovery) { r.PrepareBoot.Identity = "" },
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
	recovery := NativeWorkerRecovery{RecoveryID: domain.NewID().String(), InstanceID: scope.InstanceID, OriginalGeneration: scope.Generation, Action: "replace", PrepareBoot: recoveryBoot("11111111-1111-4111-8111-111111111111"), FenceBoot: recoveryBoot("11111111-1111-4111-8111-111111111111"), LocalGeneration: scope.Generation, Phase: "prepared"}
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

func recoveryBoot(identity string) transport.KernelBootEvidence {
	return transport.KernelBootEvidence{Identity: identity, Source: "linux_boot_id", Quality: "boot_uuid"}
}

func TestNativeWorkerRecoveryLegacyWildcard(t *testing.T) {
	for _, localWorker := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "local"}[localWorker], func(t *testing.T) {
			registry, scope, spec := nativeRegistryFixture(t)
			localGeneration := ""
			if localWorker {
				if _, err := registry.Reserve(scope, spec, "", ""); err != nil {
					t.Fatal(err)
				}
				localGeneration = scope.Generation
			}
			recovery := NativeWorkerRecovery{RecoveryID: domain.NewID().String(), InstanceID: scope.InstanceID, Action: "delete", PrepareBoot: recoveryBoot("11111111-1111-4111-8111-111111111111"), FenceBoot: recoveryBoot("22222222-2222-4222-8222-222222222222"), LocalGeneration: localGeneration, Phase: "prepared"}
			if got, err := registry.PrepareRecovery(recovery); err != nil || got != recovery {
				t.Fatalf("legacy preparation: %+v %v", got, err)
			}
			reopened, err := OpenNativeWorkerRegistry(filepath.Dir(registry.root))
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			for _, generation := range []string{scope.Generation, domain.NewID().String(), ""} {
				if fenced, err := reopened.RecoveryTombstoned(scope.InstanceID, generation); err != nil || !fenced {
					t.Fatalf("wildcard failed: %v %v", fenced, err)
				}
			}
			other := recovery
			other.RecoveryID = domain.NewID().String()
			other.OriginalGeneration = scope.Generation
			if _, err := registry.PrepareRecovery(other); err == nil {
				t.Fatal("overlapping exact recovery accepted")
			}
			if _, err := registry.Reserve(scope, spec, "", ""); err == nil {
				t.Fatal("legacy fence allowed launch")
			}
			if got, err := reopened.LookupRecovery(recovery.RecoveryID); err != nil || got != recovery {
				t.Fatalf("legacy identity lost: %+v %v", got, err)
			}
		})
	}
}

func TestNativeWorkerRecoveryMissingLocalWorker(t *testing.T) {
	registry, scope, _ := nativeRegistryFixture(t)
	recovery := NativeWorkerRecovery{RecoveryID: domain.NewID().String(), InstanceID: scope.InstanceID, OriginalGeneration: scope.Generation, Action: "replace", PrepareBoot: recoveryBoot("11111111-1111-4111-8111-111111111111"), FenceBoot: recoveryBoot("11111111-1111-4111-8111-111111111111"), Phase: "prepared"}
	if got, err := registry.PrepareRecovery(recovery); err != nil || got != recovery {
		t.Fatalf("missing local record rejected: %+v %v", got, err)
	}
}

func TestNativeWorkerRecoveryOldTombstoneFailsClosed(t *testing.T) {
	registry, scope, spec := nativeRegistryFixture(t)
	// Recreate the previous release's schema, which had no evidence payload.
	if _, err := registry.db.Exec(`DROP TABLE native_worker_recoveries`); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.db.Exec(`CREATE TABLE native_worker_recoveries(recovery_id TEXT PRIMARY KEY,instance_id TEXT NOT NULL,original_generation TEXT NOT NULL,prepare_boot_identity TEXT NOT NULL,phase TEXT NOT NULL,UNIQUE(instance_id,original_generation))`); err != nil {
		t.Fatal(err)
	}
	id := domain.NewID().String()
	if _, err := registry.db.Exec(`INSERT INTO native_worker_recoveries VALUES(?,?,?,?,?)`, id, scope.InstanceID, scope.Generation, "old-boot", "prepared"); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenNativeWorkerRegistry(filepath.Dir(registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if fenced, err := reopened.RecoveryTombstoned(scope.InstanceID, scope.Generation); err != nil || !fenced {
		t.Fatalf("old fence lost: %v %v", fenced, err)
	}
	if _, err := reopened.LookupRecovery(id); err == nil {
		t.Fatal("invented missing immutable evidence")
	}
	if err := reopened.AdvanceRecoveryPhase(id, "prepared", "committed"); err == nil {
		t.Fatal("old fence advanced without evidence")
	}
	if _, err := reopened.Reserve(scope, spec, "", ""); err == nil {
		t.Fatal("old fence allowed launch")
	}
}

func TestNativeWorkerRecoveryRequiresBootAfterBothFences(t *testing.T) {
	original := recoveryBoot("11111111-1111-4111-8111-111111111111")
	prepared := recoveryBoot("22222222-2222-4222-8222-222222222222")
	fenced := recoveryBoot("33333333-3333-4333-8333-333333333333")
	current := recoveryBoot("44444444-4444-4444-8444-444444444444")
	for _, owned := range []bool{false, true} {
		r := NativeWorkerRecovery{PrepareBoot: prepared, FenceBoot: fenced}
		if owned {
			r.OriginalBoot = original
		}
		if !r.ProvesNewBoot(current) {
			t.Fatal("new UUID boot rejected")
		}
		for _, unchanged := range []transport.KernelBootEvidence{prepared, fenced, {}, {Identity: "1710000000.123456", Source: "darwin_boottime", Quality: "boot_time"}} {
			if r.ProvesNewBoot(unchanged) {
				t.Fatalf("insufficient evidence authorized death: %+v", unchanged)
			}
		}
		changedSource := current
		changedSource.Source = "darwin_bootsessionuuid"
		if r.ProvesNewBoot(changedSource) {
			t.Fatal("source change authorized death")
		}
		if owned && r.ProvesNewBoot(original) {
			t.Fatal("original worker boot authorized death")
		}
	}
}
