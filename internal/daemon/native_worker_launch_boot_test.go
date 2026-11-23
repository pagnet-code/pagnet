//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func launchBootRecord(t *testing.T) (*NativeWorkerRegistry, NativeWorkerRecord) {
	t.Helper()
	r, scope, spec := nativeRegistryFixture(t)
	record, err := r.Reserve(scope, spec, "original", "")
	if err != nil {
		t.Fatal(err)
	}
	return r, record
}

func assertLaunchBoot(t *testing.T, r *NativeWorkerRegistry, record NativeWorkerRecord, state string, boot *transport.KernelBootEvidence) {
	t.Helper()
	got, err := r.Lookup(record.Scope.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LaunchState != state || (got.LaunchBoot == nil) != (boot == nil) || (boot != nil && *got.LaunchBoot != *boot) {
		t.Fatalf("launch claim: state=%s boot=%+v; want state=%s boot=%+v", got.LaunchState, got.LaunchBoot, state, boot)
	}
}

func launchBootPayload(t *testing.T, r *NativeWorkerRegistry, record NativeWorkerRecord) []byte {
	t.Helper()
	var raw []byte
	if err := r.db.QueryRow(`SELECT payload FROM native_workers WHERE instance_id=?`, record.Scope.InstanceID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNativeWorkerLaunchBootDurableClaim(t *testing.T) {
	r, record := launchBootRecord(t)
	boot := recoveryBoot("11111111-1111-4111-8111-111111111111")
	if claimed, err := r.claimLaunch(record, boot); err != nil || !claimed {
		t.Fatalf("claim=%v err=%v", claimed, err)
	}
	reopened, err := OpenNativeWorkerRegistry(filepath.Dir(r.root))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLaunchBoot(t, reopened, record, "launching", &boot)
	before := launchBootPayload(t, reopened, record)
	otherBoot := recoveryBoot("22222222-2222-4222-8222-222222222222")
	if claimed, err := reopened.claimLaunch(record, otherBoot); err != nil || claimed {
		t.Fatalf("consumed claim=%v err=%v", claimed, err)
	}
	if !bytes.Equal(before, launchBootPayload(t, reopened, record)) {
		t.Fatal("consumed claim payload rewritten")
	}
	if started, err := reopened.startLaunch(context.Background(), record, boot, func() error { return nil }); err != nil || !started {
		t.Fatalf("start=%v err=%v", started, err)
	}
	assertLaunchBoot(t, r, record, "launched", &boot)
	before = launchBootPayload(t, r, record)
	if claimed, err := r.claimLaunch(record, otherBoot); err != nil || claimed {
		t.Fatalf("launched claim=%v err=%v", claimed, err)
	}
	if !bytes.Equal(before, launchBootPayload(t, r, record)) {
		t.Fatal("launched claim payload rewritten")
	}
}

func TestNativeWorkerLaunchBootLegacyConsumed(t *testing.T) {
	for _, state := range []string{"launching", "launched"} {
		t.Run(state, func(t *testing.T) {
			r, record := launchBootRecord(t)
			if err := r.prepare(record); err != nil {
				t.Fatal(err)
			}
			if _, err := r.db.Exec(`UPDATE native_workers SET launch_state=? WHERE instance_id=?`, state, record.Scope.InstanceID); err != nil {
				t.Fatal(err)
			}
			before := launchBootPayload(t, r, record)
			boot := recoveryBoot("11111111-1111-4111-8111-111111111111")
			if claimed, err := r.claimLaunch(record, boot); err != nil || claimed {
				t.Fatalf("legacy claim=%v err=%v", claimed, err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			if err := EnsureNativeWorker(ctx, r, record, "/does-not-exist", nil, ""); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("legacy ensure=%v", err)
			}
			assertLaunchBoot(t, r, record, state, nil)
			if !bytes.Equal(before, launchBootPayload(t, r, record)) {
				t.Fatal("legacy launch evidence rewritten")
			}
		})
	}
}

func TestNativeWorkerLaunchBootProvenStartFailure(t *testing.T) {
	r, record := launchBootRecord(t)
	if err := EnsureNativeWorker(context.Background(), r, record, "/does-not-exist", nil, ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing executable start error=%v", err)
	}
	assertLaunchBoot(t, r, record, "reserved", nil)
}

func TestNativeWorkerLaunchBootCancellationAndStartError(t *testing.T) {
	for _, canceled := range []bool{true, false} {
		name := "start_error"
		if canceled {
			name = "cancellation"
		}
		t.Run(name, func(t *testing.T) {
			r, record := launchBootRecord(t)
			boot := recoveryBoot("11111111-1111-4111-8111-111111111111")
			if claimed, err := r.claimLaunch(record, boot); err != nil || !claimed {
				t.Fatalf("claim=%v err=%v", claimed, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if canceled {
				cancel()
			}
			callbackErr := errors.New("start proved no process")
			called := false
			started, err := r.startLaunch(ctx, record, boot, func() error { called = true; return callbackErr })
			if started {
				t.Fatal("failed start reported started")
			}
			if canceled {
				if called || !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled callback=%v err=%v", called, err)
				}
				assertLaunchBoot(t, r, record, "launching", &boot)
			} else {
				if !called || !errors.Is(err, callbackErr) {
					t.Fatalf("failed callback=%v err=%v", called, err)
				}
				assertLaunchBoot(t, r, record, "reserved", nil)
				if claimed, err := r.claimLaunch(record, boot); err != nil || !claimed {
					t.Fatalf("retry claim=%v err=%v", claimed, err)
				}
			}
		})
	}
}

func TestNativeWorkerLaunchBootRecoveryOrdering(t *testing.T) {
	for _, fenceFirst := range []bool{true, false} {
		name := "start_first"
		if fenceFirst {
			name = "fence_first"
		}
		t.Run(name, func(t *testing.T) {
			r, record := launchBootRecord(t)
			other, err := OpenNativeWorkerRegistry(filepath.Dir(r.root))
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			boot := recoveryBoot("11111111-1111-4111-8111-111111111111")
			recovery := NativeWorkerRecovery{RecoveryID: domain.NewID().String(), InstanceID: record.Scope.InstanceID, OriginalGeneration: record.Scope.Generation, Action: "replace", PrepareBoot: boot, FenceBoot: boot, LocalGeneration: record.Scope.Generation, Phase: "prepared"}
			if claimed, err := r.claimLaunch(record, boot); err != nil || !claimed {
				t.Fatalf("claim=%v err=%v", claimed, err)
			}
			if fenceFirst {
				if _, err := other.PrepareRecovery(recovery); err != nil {
					t.Fatal(err)
				}
				called := false
				started, err := r.startLaunch(context.Background(), record, boot, func() error { called = true; return nil })
				if started || called || !errors.Is(err, errNativeWorkerRecoveryFenced) {
					t.Fatalf("fenced start=%v callback=%v err=%v", started, called, err)
				}
				assertLaunchBoot(t, r, record, "launching", &boot)
				return
			}
			entered := make(chan struct{})
			release := make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			startDone := make(chan error, 1)
			go func() {
				started, err := r.startLaunch(context.Background(), record, boot, func() error { close(entered); <-release; return nil })
				if err == nil && !started {
					err = errors.New("callback completed without started result")
				}
				startDone <- err
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("start callback did not enter")
			}
			preparing := make(chan struct{})
			recoveryDone := make(chan error, 1)
			go func() { close(preparing); _, err := other.PrepareRecovery(recovery); recoveryDone <- err }()
			<-preparing
			select {
			case err := <-recoveryDone:
				t.Fatalf("recovery completed while callback holds writer lock: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			select {
			case err := <-startDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("start did not complete")
			}
			select {
			case err := <-recoveryDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("recovery did not complete after start")
			}
			assertLaunchBoot(t, r, record, "launched", &boot)
			if fenced, err := other.RecoveryTombstoned(record.Scope.InstanceID, record.Scope.Generation); err != nil || !fenced {
				t.Fatalf("fence=%v err=%v", fenced, err)
			}
		})
	}
}

func TestNativeWorkerLaunchBootUnavailableEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		boot transport.KernelBootEvidence
		err  error
	}{
		{name: "collector_error", err: errors.New("collector unavailable")},
		{name: "malformed", boot: transport.KernelBootEvidence{Identity: "invalid", Source: "linux_boot_id", Quality: "boot_uuid"}},
		{name: "boot_time", boot: transport.KernelBootEvidence{Identity: "1710000000.123456", Source: "darwin_boottime", Quality: "boot_time"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, record := launchBootRecord(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			called := false
			err := ensureNativeWorker(ctx, r, record, "/bin/true", nil, "", func() (transport.KernelBootEvidence, error) { called = true; return tc.boot, tc.err })
			if !called {
				t.Fatal("boot collector was not called")
			}
			if err == nil {
				t.Fatal("non-worker executable unexpectedly became ready")
			}
			assertLaunchBoot(t, r, record, "launched", nil)
		})
	}
}

func TestNativeWorkerLaunchBootPublicCollector(t *testing.T) {
	r, record := launchBootRecord(t)
	boot, bootErr := CollectKernelBootEvidence()
	var expected *transport.KernelBootEvidence
	if bootErr == nil && boot.Valid() && boot.Quality == "boot_uuid" {
		expected = &boot
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := EnsureNativeWorker(ctx, r, record, "/bin/true", nil, ""); err == nil {
		t.Fatal("non-worker executable unexpectedly became ready")
	}
	assertLaunchBoot(t, r, record, "launched", expected)
}
