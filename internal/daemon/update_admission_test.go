//go:build unix

package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
)

// Pause after the final idle snapshot, then race the actual process-launch
// path. Its side effect must happen only after finalization releases the gate.
func TestUpdateFinalizationExcludesRealLaunch(t *testing.T) {
	d := newTestDaemon(t)
	originalSupervisor := d.sup
	t.Cleanup(func() { originalSupervisor.StopAll(time.Second) })
	d.sup = proc.NewSupervisor(proc.Config{StateDir: privateDaemonStateDir(t)}, d.Log)
	marker := filepath.Join(t.TempDir(), "started")
	finalizing, finish, finalized := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	var finishOnce sync.Once
	releaseFinalization := func() { finishOnce.Do(func() { close(finish) }) }
	t.Cleanup(releaseFinalization)
	go func() { finalized <- d.finalizeIdleUpdate(func() { close(finalizing); <-finish }) }()
	select {
	case <-finalizing:
	case accepted := <-finalized:
		t.Fatalf("finalization returned before callback: %v", accepted)
	case <-time.After(5 * time.Second):
		t.Fatal("finalization did not enter callback")
	}
	launched := make(chan error, 1)
	attempting := make(chan struct{})
	go func() {
		close(attempting)
		cmd := exec.Command("/bin/sh", "-c", `printf started > "$PAGNET_TEST_MARKER"`)
		cmd.Env = append(os.Environ(), "PAGNET_TEST_MARKER="+marker)
		h, err := d.sup.Launch(context.Background(), proc.LaunchRequest{InstanceID: domain.NewID().String(), TurnID: domain.NewID().String(), Runtime: "test", Class: proc.ClassTurn, Cmd: cmd})
		if err == nil {
			_, err = h.WaitDeadline(5 * time.Second)
		}
		launched <- err
	}()
	<-attempting
	select {
	case err := <-launched:
		releaseFinalization()
		t.Fatalf("launch crossed final idle barrier: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		releaseFinalization()
		t.Fatalf("runtime started during finalization: %v", err)
	}
	releaseFinalization()
	if !<-finalized {
		t.Fatal("idle finalization was refused")
	}
	if err := <-launched; err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(marker); err != nil || string(b) != "started" {
		t.Fatalf("launch not released: %q %v", b, err)
	}
}

func TestUpdateAdmissionDefersWithoutWaitingAndSupportsNestedReservations(t *testing.T) {
	d := newTestDaemon(t)
	release := d.admitWork()
	nested := d.admitWork()
	called := false
	if d.finalizeIdleUpdate(func() { called = true }) || called {
		t.Fatal("updated while work was admitted")
	}
	nested()
	release()
	if !d.finalizeIdleUpdate(func() { called = true }) || !called {
		t.Fatal("admission not released")
	}
	// A failed exec/replacement returns normally from the callback. Subsequent
	// work and a later update must remain possible.
	release = d.admitWork()
	release()
	if !d.finalizeIdleUpdate(func() {}) {
		t.Fatal("finalization retained barrier after returning")
	}
}

func TestUpdateDefersForPersistentTurnBeforeStatusWrite(t *testing.T) {
	d := newTestDaemon(t)
	id := domain.NewID().String()
	d.markTurnInFlight(id)
	defer d.clearTurnInFlight(id)
	if d.activeWorkCount() == 0 {
		t.Fatal("persistent admission invisible before working status")
	}
	if d.finalizeIdleUpdate(func() { t.Fatal("finalized during persistent turn") }) {
		t.Fatal("accepted busy update")
	}
}

func TestUpdateDefersWhenInstanceStateUnknown(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.state.db.Close(); err != nil {
		t.Fatal(err)
	}
	if d.activeWorkCount() == 0 {
		t.Fatal("closed database treated as idle")
	}
	if d.finalizeIdleUpdate(func() { t.Fatal("finalized with unknown instance state") }) {
		t.Fatal("accepted unknown state")
	}
}

func TestUpdateCannotOvertakeQueuedCommandAndQueueCancellationReleasesAdmission(t *testing.T) {
	d := newTestDaemon(t)
	firstRunning, releaseFirst, firstDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	id := domain.NewID().String()
	if !d.enqueueInstance(id, func() { close(firstRunning); <-releaseFirst; close(firstDone) }) {
		t.Fatal("first enqueue failed")
	}
	<-firstRunning
	if !d.enqueueInstance(id, func() { t.Error("abandoned command executed") }) {
		t.Fatal("second enqueue failed")
	}
	if d.finalizeIdleUpdate(func() { t.Fatal("updated ahead of queued work") }) {
		t.Fatal("admitted pending work was invisible")
	}
	d.finishQueue(id)
	close(releaseFirst)
	<-firstDone
	deadline := time.Now().Add(time.Second)
	for !d.finalizeIdleUpdate(func() {}) {
		if time.Now().After(deadline) {
			t.Fatal("canceled queue retained admission")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUpdateQueueOverflowDoesNotLeakAdmission(t *testing.T) {
	d := newTestDaemon(t)
	started, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	id := domain.NewID().String()
	if !d.enqueueInstance(id, func() { close(started); <-finish; close(done) }) {
		t.Fatal("enqueue failed")
	}
	<-started
	for i := 0; i < 64; i++ {
		if !d.enqueueInstance(id, func() {}) {
			t.Fatalf("queue filled early at %d", i)
		}
	}
	if d.enqueueInstance(id, func() { t.Error("overflow job executed") }) {
		t.Fatal("overflow accepted")
	}
	d.finishQueue(id)
	close(finish)
	<-done
	deadline := time.Now().Add(time.Second)
	for !d.finalizeIdleUpdate(func() {}) {
		if time.Now().After(deadline) {
			t.Fatal("overflow reservation leaked")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUpdateFinalizationBlocksQueuedArrivalUntilRelease(t *testing.T) {
	d := newTestDaemon(t)
	finalizing, finish, result := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	var once sync.Once
	release := func() { once.Do(func() { close(finish) }) }
	t.Cleanup(release)
	go func() { result <- d.finalizeIdleUpdate(func() { close(finalizing); <-finish }) }()
	select {
	case <-finalizing:
	case r := <-result:
		t.Fatalf("finalization refused: %v", r)
	case <-time.After(time.Second):
		t.Fatal("finalization stalled")
	}
	arriving, accepted, ran := make(chan struct{}), make(chan bool, 1), make(chan struct{})
	go func() { close(arriving); accepted <- d.enqueueInstance(domain.NewID().String(), func() { close(ran) }) }()
	<-arriving
	select {
	case <-accepted:
		t.Fatal("queued command admitted during finalization")
	case <-time.After(30 * time.Millisecond):
	}
	release()
	if !<-result {
		t.Fatal("idle update refused")
	}
	select {
	case ok := <-accepted:
		if !ok {
			t.Fatal("enqueue failed after finalization")
		}
	case <-time.After(time.Second):
		t.Fatal("enqueue not released")
	}
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("admitted command not executed")
	}
}

func TestStoppedQueueReleasesCommandClaimForDurableRedelivery(t *testing.T) {
	d := newTestDaemon(t)
	instance, command, processed := domain.NewID().String(), domain.NewID().String(), domain.NewID().String()
	if err := d.state.MarkProcessed(processed, "", nil); err != nil {
		t.Fatal(err)
	}
	d.seen[processed] = time.Now() // A completed-command tombstone is independent.
	running, finish, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(finish) }) }
	t.Cleanup(release)
	if !d.enqueueInstance(instance, func() { close(running); <-finish; close(finished) }) {
		t.Fatal("enqueue failed")
	}
	<-running
	d.enqueueCommand(nil, instance, command, func() { t.Error("abandoned command executed") })
	d.seenMu.Lock()
	_, claimed := d.seen[command]
	d.seenMu.Unlock()
	if !claimed {
		t.Fatal("command was not initially claimed")
	}
	d.finishQueue(instance)
	release()
	<-finished
	deadline := time.Now().Add(time.Second)
	for {
		d.seenMu.Lock()
		_, claimed = d.seen[command]
		_, retained := d.seen[processed]
		d.seenMu.Unlock()
		if !retained || !d.alreadyProcessed(processed) {
			t.Fatal("processed tombstone removed")
		}
		if !claimed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("abandoned claim suppressed durable redelivery")
		}
		time.Sleep(time.Millisecond)
	}
	resent := make(chan struct{})
	d.enqueueCommand(nil, instance, command, func() { close(resent) })
	select {
	case <-resent:
	case <-time.After(time.Second):
		t.Fatal("same command could not be redelivered")
	}
}
