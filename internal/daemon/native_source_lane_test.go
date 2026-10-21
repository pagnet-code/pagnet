//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeSourceLaneDeletionWaitAndCancellation(t *testing.T) {
	proxy := &NativeWorkerProxy{done: make(chan struct{})}
	entered, release := make(chan struct{}), make(chan struct{})
	blocked := errors.New("ordinary drain finished")
	proxy.ordinarySourceAdmission = func() error {
		close(entered)
		<-release
		return blocked
	}
	ordinary := make(chan error, 1)
	go func() { ordinary <- proxy.DrainSources(t.Context()) }()
	<-entered
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := proxy.acquireSourceLane(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("lane wait ignored cancellation", err)
	}
	deletion := make(chan error, 1)
	go func() {
		ctx, stop, err := proxy.beginDeletion(t.Context())
		if err != nil {
			deletion <- err
			return
		}
		defer stop()
		deletion <- ctx.Err()
	}()
	// The ordinary lane can outlast the entire deletion execution budget.
	time.Sleep(2100 * time.Millisecond)
	close(release)
	if err := <-ordinary; !errors.Is(err, blocked) {
		t.Fatal(err)
	}
	if err := <-deletion; err != nil {
		t.Fatal("deletion budget expired while queued", err)
	}
}

func TestNativeSourceLaneDurableDeletionFenceSurvivesReconnect(t *testing.T) {
	registry, scope, _ := nativeRegistryFixture(t)
	marker, err := json.Marshal(nativeWorkerGC{Phase: "waiting", Ownership: transport.NativeWorkerOwnership{InstanceID: scope.InstanceID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.db.Exec(`INSERT INTO native_worker_gc VALUES(?,?)`, scope.InstanceID, marker); err != nil {
		t.Fatal(err)
	}
	for _, lease := range []string{"original", "reconnected"} {
		t.Run(lease, func(t *testing.T) {
			proxy := &NativeWorkerProxy{done: make(chan struct{}), ordinarySourceAdmission: func() error {
				return registry.ordinarySourceDrainAdmission(scope.InstanceID)
			}}
			for range 2 {
				// No controller is needed: a fenced drain must never reach RPC.
				if err := proxy.DrainSources(t.Context()); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
					t.Fatal("ordinary drain passed deletion fence", err)
				}
			}
		})
	}
}
