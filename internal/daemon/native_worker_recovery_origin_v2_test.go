//go:build linux || darwin

package daemon

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const inheritedSourceRecoveryQueryV2 = "?direct_managed_source_prepare=inherited&direct_managed_source_prepare=duplicate&direct_managed_source_pop=inherited&direct_managed_source_credential=inherited"

func TestNativeWorkerRecoveryInheritedOriginV2(t *testing.T) {
	for _, action := range []string{"replace", "delete"} {
		t.Run(action, func(t *testing.T) {
			d, _, p, acks, dir := recoveryProtocolFixture(t)
			d.DirectManagedSourceV2Enabled = true
			d.ServerURL += inheritedSourceRecoveryQueryV2
			p.Action = action
			local, err := d.nativeRegistry.Lookup(p.InstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			evidence := []byte("retained recovery evidence")
			if err := os.WriteFile(filepath.Join(dir, "intents.sqlite"), evidence, 0600); err != nil {
				t.Fatal(err)
			}
			if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
				t.Fatalf("initial fence: %v", err)
			}
			retained, err := d.nativeRegistry.Lookup(p.InstanceID)
			if err != nil || retained.Scope != local.Scope {
				t.Fatalf("recovery rewrote worker scope: %v", err)
			}
			next := recoveryBoot("22222222-2222-4222-8222-222222222222")
			if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err != nil {
				t.Fatal("prepared", err)
			}
			p.State = "committed"
			if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err != nil {
				t.Fatal("committed", err)
			}
			if len(*acks) != 2 || (*acks)[0].LocalPhase != "prepared" || (*acks)[1].LocalPhase != "collected" || (*acks)[1].Action != action {
				t.Fatalf("incorrect recovery ACKs: %+v", *acks)
			}
			if _, err := d.nativeRegistry.Lookup(p.InstanceID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("exact worker not collected", err)
			}
			archived, err := os.ReadFile(filepath.Join(d.nativeRegistry.root, "recovery-"+p.RecoveryID, "intents.sqlite"))
			if err != nil || string(archived) != string(evidence) {
				t.Fatal("retained evidence changed", err)
			}
			p.State = "cleaned"
			if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err != nil {
				t.Fatal("cleaned", err)
			}
			recovery, err := d.nativeRegistry.LookupRecovery(p.RecoveryID)
			if err != nil || !recovery.ServerCleaned {
				t.Fatal("cleanup confirmation lost", err)
			}
		})
	}
}

func TestNativeWorkerRecoveryPriorLaunchInheritedOriginV2(t *testing.T) {
	for _, action := range []string{"replace", "delete"} {
		t.Run(action, func(t *testing.T) {
			d, p, acks, local := priorLaunchFixture(t)
			d.DirectManagedSourceV2Enabled = true
			d.ServerURL += inheritedSourceRecoveryQueryV2
			p.Action = action
			if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); err != nil {
				t.Fatal("prepared prior-launch proof", err)
			}
			if len(*acks) != 1 || (*acks)[0].DeathProof == nil || (*acks)[0].DeathProof.Kind != "prior_launch_boot" || (*acks)[0].DeathProof.LaunchBoot != *local.LaunchBoot {
				t.Fatal("prior-launch proof was suppressed")
			}
			recovery, err := d.nativeRegistry.LookupRecovery(p.RecoveryID)
			if err != nil || recovery.LaunchProof.Scope != local.Scope {
				t.Fatal("proof changed persisted scope", err)
			}
			retained, err := d.nativeRegistry.Lookup(p.InstanceID)
			if err != nil || retained.Scope != local.Scope {
				t.Fatal("worker scope rewritten", err)
			}
			p.State = "committed"
			if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); err != nil {
				t.Fatal("committed prior-launch proof", err)
			}
			if len(*acks) != 2 || (*acks)[1].DeathProof == nil || *(*acks)[1].DeathProof != *(*acks)[0].DeathProof || (*acks)[1].LocalPhase != "collected" {
				t.Fatal("collection lost exact prior-launch proof")
			}
		})
	}
}

func TestNativeWorkerRecoveryRejectsOriginMismatchV2(t *testing.T) {
	for _, scenario := range []string{"default-off", "malformed", "connection", "retained"} {
		t.Run(scenario, func(t *testing.T) {
			d, native, p, acks, _ := recoveryProtocolFixture(t)
			d.DirectManagedSourceV2Enabled = scenario != "default-off"
			d.ServerURL += inheritedSourceRecoveryQueryV2
			local, err := d.nativeRegistry.Lookup(p.InstanceID)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "malformed":
				d.ServerURL += "&direct_managed_source_prepare=%zz"
			case "connection":
				native.serverURL = "https://foreign.test"
			case "retained":
				scope := local.Scope
				scope.ServerURL = d.ServerURL
				if _, err := d.nativeRegistry.db.Exec(`DELETE FROM native_workers WHERE instance_id=?`, p.InstanceID); err != nil {
					t.Fatal(err)
				}
				local, err = d.nativeRegistry.Reserve(scope, local.Spec, local.Profile, local.OriginalOwnershipID)
				if err != nil {
					t.Fatal(err)
				}

			}
			if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); !errors.Is(err, ErrNativeObservationConflict) {
				t.Fatalf("unsafe origin accepted: %v", err)
			}
			if len(*acks) != 0 {
				t.Fatal("unsafe origin acknowledged")
			}
			if _, err := d.nativeRegistry.LookupRecovery(p.RecoveryID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("unsafe origin prepared recovery", err)
			}
			retained, err := d.nativeRegistry.Lookup(p.InstanceID)
			if err != nil || retained.Scope != local.Scope {
				t.Fatal("mismatched persisted scope rewritten", err)
			}
		})
	}
}
