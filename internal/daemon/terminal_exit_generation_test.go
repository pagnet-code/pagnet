package daemon

import (
	"errors"
	"github.com/pagnet-code/pagnet/transport"
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
