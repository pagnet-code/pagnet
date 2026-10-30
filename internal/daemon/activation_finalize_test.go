package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

type finalizationDriver struct {
	hibernated chan struct{}
}

func (*finalizationDriver) Name() domain.RuntimeName { return "test-finalization" }

func (*finalizationDriver) Capabilities() session.Capabilities {
	return session.Capabilities{PersistentEndpoint: true, StructuredEvents: true, NativeSubmit: true}
}

func (d *finalizationDriver) Activate(ctx context.Context, sess *session.RuntimeSession, events chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
	events <- session.SessionEvent{Type: session.EventSessionStarted, SessionID: "cold-native"}
	return &session.RuntimeEndpoint{
		ID: "ep-" + sess.InstanceID, Runtime: sess.Runtime,
		Ownership: session.OwnershipPagnet, Lease: session.LeaseClaimed,
		Healthy: true, Transport: "none", StartedAt: time.Now(),
	}, nil
}

func (d *finalizationDriver) Hibernate(context.Context, *session.RuntimeSession) error {
	close(d.hibernated)
	return nil
}

func (*finalizationDriver) Submit(context.Context, *session.RuntimeSession, session.SubmitRequest, chan<- session.SessionEvent) error {
	return errors.New("finalization test driver does not submit")
}

func (*finalizationDriver) Stop(string) error { return nil }
func (*finalizationDriver) PID(string) *int   { return nil }
func (*finalizationDriver) Live(string) bool  { return false }

func TestDaemonTerminalStopWaitsForActivationFinalization(t *testing.T) {
	d := newTestDaemon(t)
	driver := &finalizationDriver{hibernated: make(chan struct{})}
	d.sessions.RegisterDriver(driver)
	id := domain.NewID().String()
	row := InstanceRow{InstanceID: id, Runtime: string(driver.Name()), Kind: "representative", Status: "idle"}
	if err := d.state.UpsertInstance(row); err != nil {
		t.Fatal(err)
	}
	// Pause the first activation report, before its working/idle writes. The
	// Manager has completed activation, but daemon publication is unfinished.
	d.connMu.Lock()
	released := false
	release := func() {
		if !released {
			released = true
			d.connMu.Unlock()
		}
	}
	defer release()
	activation := make(chan error, 1)
	go func() { activation <- d.activateSessionIdle(nil, &row) }()
	deadline := time.After(5 * time.Second)
	for {
		state, ok := d.sessions.State(id)
		if ok && state == session.StateIdle {
			break
		}
		select {
		case <-deadline:
			t.Fatal("activation did not reach finalization")
		case <-time.After(time.Millisecond):
		}
	}
	stopped := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		stopped <- d.doTerminalStop(nil, transport.TerminalStopPayload{InstanceID: id})
	}()
	<-started
	select {
	case <-driver.hibernated:
		t.Fatal("terminal stop passed unfinished activation publication")
	case err := <-stopped:
		t.Fatalf("terminal stop returned before publication: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	release()
	for _, done := range []chan error{activation, stopped} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("lifecycle transition did not finish")
		}
	}
	current, _, err := d.state.GetInstance(id)
	if err != nil || current.Status != "hibernated" {
		t.Fatalf("late activation overwrote stop: %+v %v", current, err)
	}
	state, _ := d.sessions.State(id)
	if state != session.StateInactive || d.terminal.get(id) != nil || d.settleGeneration(id) != 1 {
		t.Fatalf("unsettled stop: state=%s generation=%d", state, d.settleGeneration(id))
	}
}
