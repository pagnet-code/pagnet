package daemon

import (
	"errors"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func TestTerminalRetiredExitCannotHibernateReplacement(t *testing.T) {
	for _, killed := range []bool{true, false} {
		t.Run(map[bool]string{true: "explicit-stop", false: "displaced-generation"}[killed], func(t *testing.T) {
			d := newTestDaemon(t)
			instance := domain.NewID().String()
			if err := d.state.UpsertInstance(InstanceRow{InstanceID: instance, Runtime: "fake", Status: "idle", SessionID: "replacement-native"}); err != nil {
				t.Fatal(err)
			}
			live := make(chan struct{})
			close(live)
			replacement := &ptySession{instanceID: instance, live: live, endpointView: true}
			d.terminal.sessions[instance] = replacement
			retired := &ptySession{instanceID: instance, killed: killed}
			d.terminal.finishExitedPTY(retired, errors.New("old process terminated"))
			row, ok, err := d.state.GetInstance(instance)
			if err != nil || !ok || row.Status != "idle" || row.SessionID != "replacement-native" {
				t.Fatalf("retired process changed replacement state: %+v %v", row, err)
			}
			if d.terminal.get(instance) != replacement {
				t.Fatal("retired process removed replacement terminal")
			}
		})
	}
}

func TestTerminalRetiringGenerationDefersAttach(t *testing.T) {
	tm := inputTestManager(t)
	done := make(chan struct{})
	live := make(chan struct{})
	close(live)
	tm.sessions["agent"] = &ptySession{instanceID: "agent", live: live, endpointView: true, exitSettled: done}
	t.Cleanup(func() { close(done) })
	if _, err := tm.start("agent", false); !errors.Is(err, ErrDeferred) {
		t.Fatalf("attach returned retiring generation: %v", err)
	}
}

func TestTerminalNaturalExitDefersNewViewerUntilStateSettles(t *testing.T) {
	d := newTestDaemon(t)
	instance := domain.NewID().String()
	if err := d.state.UpsertInstance(InstanceRow{InstanceID: instance, Runtime: "fake", Status: "idle"}); err != nil {
		t.Fatal(err)
	}
	live := make(chan struct{})
	close(live)
	retiring := &ptySession{instanceID: instance, live: live}
	d.terminal.sessions[instance] = retiring
	d.addAttach(instance, "old-view")
	// Pause the actual outbound path after the watcher claims finalization.
	// An attach must defer without binding a viewer to the dead generation.
	d.connMu.Lock()
	released := false
	release := func() {
		if !released {
			released = true
			d.connMu.Unlock()
		}
	}
	t.Cleanup(release)
	finished := make(chan struct{})
	go func() { defer close(finished); d.terminal.finishExitedPTY(retiring, nil) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		d.terminal.mu.Lock()
		claimed := retiring.exitSettled != nil
		d.terminal.mu.Unlock()
		if claimed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("natural exit never claimed finalization")
		}
		time.Sleep(time.Millisecond)
	}
	if err := d.doAttach(nil, transport.TerminalAttachPayload{InstanceID: instance, SessionID: "new-view"}); !errors.Is(err, ErrDeferred) {
		t.Fatalf("attach joined retiring generation: %v", err)
	}
	d.attachMu.Lock()
	_, added := d.attaches[instance]["new-view"]
	d.attachMu.Unlock()
	if added {
		t.Fatal("deferred attach registered a phantom viewer")
	}
	release()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("natural exit did not settle")
	}
	if d.terminal.get(instance) != nil {
		t.Fatal("retiring slot remained after state settled")
	}
}

// gatedInteractiveFake pauses command construction, not process execution,
// so cancellation is tested against the actual slow-launch boundary.
type gatedInteractiveFake struct {
	*agentruntime.Fake
	entered chan struct{}
	release chan struct{}
}

func (f *gatedInteractiveFake) InteractiveCmd(spec agentruntime.TurnSpec) (*exec.Cmd, error) {
	close(f.entered)
	<-f.release
	return f.Fake.InteractiveCmd(spec)
}
func TestTerminalDetachDuringLaunchCannotRecreateViewer(t *testing.T) {
	t.Setenv("PAGNET_P0_BIN_DIR", filepath.Join(t.TempDir(), "bin"))
	d := newTestDaemon(t)
	f := &gatedInteractiveFake{Fake: agentruntime.NewFake(p0FakeBinary(t)), entered: make(chan struct{}), release: make(chan struct{})}
	d.adapters[domain.RuntimeFake] = f
	instance := domain.NewID().String()
	if err := d.state.UpsertInstance(InstanceRow{InstanceID: instance, Runtime: "fake", Status: "idle", Workspace: t.TempDir(), Access: "read_write"}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- d.doAttach(nil, transport.TerminalAttachPayload{InstanceID: instance, SessionID: "cancelled-view"})
	}()
	released := false
	release := func() {
		if !released {
			released = true
			close(f.release)
		}
	}
	t.Cleanup(release)
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("launch never reached command construction")
	}
	if err := d.doDetach(nil, transport.DetachTerminalPayload{InstanceID: instance, SessionID: "cancelled-view"}); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled launch never settled")
	}
	d.attachMu.Lock()
	_, added := d.attaches[instance]["cancelled-view"]
	d.attachMu.Unlock()
	if added {
		t.Fatal("slow launch recreated a cancelled terminal viewer")
	}
	detached, err := d.state.TerminalDetached(instance, "cancelled-view")
	if err != nil || !detached {
		t.Fatalf("cancellation was not durable: %v %v", detached, err)
	}
}

func TestTerminalPersistentDetachDuringActivationCannotRecreateViewer(t *testing.T) {
	d := newTestDaemon(t)
	drv := &gatedPTYDriver{gate: make(chan struct{}), launched: make(chan struct{})}
	d.sessions.RegisterDriver(drv)
	instance := domain.NewID().String()
	if err := d.state.UpsertInstance(InstanceRow{InstanceID: instance, Runtime: string(drv.Name()), Status: "hibernated", Workspace: t.TempDir(), Access: domain.AccessReadWrite}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- d.doAttach(nil, transport.TerminalAttachPayload{InstanceID: instance, SessionID: "cancelled-persistent-view"})
	}()
	released := false
	release := func() {
		if !released {
			released = true
			close(drv.gate)
		}
	}
	t.Cleanup(func() {
		release()
		if drv.master != nil {
			drv.master.Close()
		}
		if drv.slave != nil {
			drv.slave.Close()
		}
	})
	select {
	case <-drv.launched:
	case <-time.After(5 * time.Second):
		t.Fatal("activation never reached handshake")
	}
	if err := d.doDetach(nil, transport.DetachTerminalPayload{InstanceID: instance, SessionID: "cancelled-persistent-view"}); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled activation never settled")
	}
	if d.attached(instance) {
		t.Fatal("persistent activation recreated cancelled viewer")
	}
}

func TestTerminalRemoveAttachReportsOnlyLastRecordedViewer(t *testing.T) {
	d := newTestDaemon(t)
	d.addAttach("agent", "first")
	d.addAttach("agent", "second")
	if d.removeAttach("agent", "first") {
		t.Fatal("closing first viewer reported last attach")
	}
	if !d.attached("agent") {
		t.Fatal("closing first viewer removed surviving viewer")
	}
	if d.removeAttach("agent", "missing") {
		t.Fatal("missing viewer reported last attach")
	}
	if !d.removeAttach("agent", "second") {
		t.Fatal("closing last viewer did not report last attach")
	}
	if d.attached("agent") {
		t.Fatal("last viewer was not removed")
	}
}
