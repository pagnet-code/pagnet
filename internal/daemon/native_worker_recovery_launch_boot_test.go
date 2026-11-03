//go:build linux || darwin

package daemon

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func priorLaunchFixture(t *testing.T) (*Daemon, transport.NativeWorkerRecoveryState, *[]transport.NativeWorkerRecoveryAck, NativeWorkerRecord) {
	t.Helper()
	d, c, p, acks, _ := recoveryProtocolFixture(t)
	c.session.ProtocolFeatures = append(c.session.ProtocolFeatures, transport.NativeWorkerPriorLaunchBootRecoveryProtocol)
	local, err := d.nativeRegistry.Lookup(p.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	local.OriginalOwnershipID = p.OwnershipID
	raw, _ := json.Marshal(local)
	if _, err = d.nativeRegistry.db.Exec(`UPDATE native_workers SET payload=? WHERE instance_id=?`, raw, p.InstanceID); err != nil {
		t.Fatal(err)
	}
	if err = d.nativeRegistry.prepare(local); err != nil {
		t.Fatal(err)
	}
	if claimed, err := d.nativeRegistry.claimLaunch(local, *p.OriginalBoot); err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	local, err = d.nativeRegistry.Lookup(p.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	p.PrepareBoot = recoveryBoot("22222222-2222-4222-8222-222222222222")
	return d, p, acks, local
}

func TestNativeWorkerRecoveryPriorLaunchBoot(t *testing.T) {
	d, p, acks, local := priorLaunchFixture(t)
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); err != nil {
		t.Fatal(err)
	}
	if len(*acks) != 1 || (*acks)[0].DeathProof == nil || (*acks)[0].DeathProof.Kind != "prior_launch_boot" || (*acks)[0].DeathProof.LaunchBoot != *local.LaunchBoot {
		t.Fatalf("missing proof: %+v", *acks)
	}
	frozen, err := d.nativeRegistry.LookupRecovery(p.RecoveryID)
	if err != nil || frozen.LaunchProof.Scope != local.Scope || frozen.LaunchProof.ProfileFingerprint != local.ProfileFingerprint {
		t.Fatalf("missing frozen claim: %+v %v", frozen, err)
	}
	reopened, err := OpenNativeWorkerRegistry(filepath.Dir(d.nativeRegistry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	d.nativeRegistry = reopened
	if err = d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); err != nil {
		t.Fatal(err)
	}
	changed := frozen
	changed.LaunchProof.Profile = "different"
	if _, err = reopened.PrepareRecovery(changed); err == nil {
		t.Fatal("persisted proof was mutable")
	}
	retry, err := reopened.LookupRecovery(p.RecoveryID)
	if err != nil || retry != frozen {
		t.Fatalf("proof mutated on retry: %+v %v", retry, err)
	}
	p.State = "committed"
	if err = d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); err != nil {
		t.Fatal(err)
	}
	d.resumeNativeWorkerRecoveryAcks(nil)
	if len(*acks) != 4 || (*acks)[3].DeathProof == nil || *(*acks)[3].DeathProof != *(*acks)[0].DeathProof {
		t.Fatal("collected retry lost proof")
	}
}

func TestNativeWorkerRecoveryPriorLaunchBootRejects(t *testing.T) {
	for _, name := range []string{"feature", "same-boot", "source", "coarse", "missing", "ownership", "namespace", "profile", "live-lock", "original-boot"} {
		t.Run(name, func(t *testing.T) {
			d, p, acks, local := priorLaunchFixture(t)
			current := p.PrepareBoot
			switch name {
			case "feature":
				d.nativeConn.session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.NativeWorkerRecoveryProtocol}
			case "same-boot":
				current = *local.LaunchBoot
			case "source":
				current.Source = "darwin_bootsessionuuid"
			case "coarse":
				current = transport.KernelBootEvidence{Identity: "123.000001", Source: "darwin_boottime", Quality: "boot_time"}
			case "missing":
				local.LaunchBoot = nil
			case "ownership":
				local.OriginalOwnershipID = "different"
			case "namespace":
				d.ServerURL = "https://different.example"
			case "profile":
				local.ProfileFingerprint = "wrong"
			case "live-lock":
				lock, err := sessionworker.AcquireWorkerLifetimeLock(local.Dir)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			case "original-boot":
				p.OriginalBoot = &current
			}
			if name == "missing" || name == "ownership" || name == "profile" {
				raw, _ := json.Marshal(local)
				if _, err := d.nativeRegistry.db.Exec(`UPDATE native_workers SET payload=? WHERE instance_id=?`, raw, p.InstanceID); err != nil {
					t.Fatal(err)
				}
			}
			if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(current)); err == nil {
				t.Fatal("unsafe proof accepted")
			}
			if len(*acks) != 0 {
				t.Fatal("unsafe acknowledgement sent")
			}
		})
	}
}

func TestNativeWorkerRecoveryPriorLaunchBootFenceRetry(t *testing.T) {
	d, p, acks, local := priorLaunchFixture(t)
	lock, err := sessionworker.AcquireWorkerLifetimeLock(local.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatal(err)
	}
	fenced, err := d.nativeRegistry.LookupRecovery(p.RecoveryID)
	if err != nil || fenced.LaunchProof != (NativeWorkerLaunchRecoveryProof{}) {
		t.Fatalf("fence not committed before lock: %+v %v", fenced, err)
	}
	if err = d.nativeRegistry.checkRecoveryFence(local.Scope.InstanceID, local.Scope.Generation); err == nil {
		t.Fatal("launch not fenced")
	}
	lock.Close()
	reopened, err := OpenNativeWorkerRegistry(filepath.Dir(d.nativeRegistry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	d.nativeRegistry = reopened
	if err = d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); err != nil {
		t.Fatal(err)
	}
	local.Profile = "changed"
	raw, _ := json.Marshal(local)
	if _, err = d.nativeRegistry.db.Exec(`UPDATE native_workers SET payload=? WHERE instance_id=?`, raw, p.InstanceID); err != nil {
		t.Fatal(err)
	}
	if err = d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatalf("frozen claim mutation accepted: %v", err)
	}
	if len(*acks) != 1 {
		t.Fatal("mutated claim acknowledged")
	}
}

func TestNativeWorkerRecoveryPriorLaunchBootFeatureDowngrade(t *testing.T) {
	d, p, acks, _ := priorLaunchFixture(t)
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); err != nil {
		t.Fatal(err)
	}
	d.nativeConn.session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.NativeWorkerRecoveryProtocol}
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatalf("downgrade bypassed legacy boot proof: %v", err)
	}
	next := recoveryBoot("33333333-3333-4333-8333-333333333333")
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err != nil {
		t.Fatal(err)
	}
	if len(*acks) != 2 || (*acks)[1].DeathProof != nil {
		t.Fatal("legacy socket received unsupported proof")
	}
}
