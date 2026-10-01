package daemon

import (
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
	"testing"
)

func TestDaemonHibernateRejectsLogicalTurnWithIdleRow(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()
	id := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{CommandID: "logical-guard-launch", InstanceID: id, Runtime: string(domain.RuntimeFakePersistent), Kind: "representative"})
	waitForEndpointLive(t, d, id)
	pid := d.sup.EndpointPID(id)
	d.markTurnInFlight(id)
	if err := d.hibernateInstance(client, id, "attach_closed"); !errors.Is(err, session.ErrBusy) {
		t.Fatalf("idle row overrode logical turn: %v", err)
	}
	d.clearTurnInFlight(id)
	after := d.sup.EndpointPID(id)
	if pid == nil || after == nil || *pid != *after {
		t.Fatal("active endpoint was stopped")
	}
}

// Embedding only Driver deliberately hides the fixture's extra safety proof,
// modeling a runtime with unenumerated native schedules/background jobs.
type unprovenSuspendDriver struct{ session.Driver }

func TestDaemonLastAttachKeepsUnprovenNativeSchedulesAlive(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	id := domain.NewID().String()
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{CommandID: "native-schedule-launch", InstanceID: id, Runtime: string(domain.RuntimeFakePersistent), Kind: "representative"})
	waitForEndpointLive(t, d, id)
	original := d.sup.EndpointPID(id)
	d.sessions.RegisterDriver(unprovenSuspendDriver{d.sessions.DriverFor(domain.RuntimeFakePersistent)})
	d.addAttach(id, "closing")
	if err := d.doDetach(client, transport.DetachTerminalPayload{InstanceID: id, SessionID: "closing"}); err != nil {
		t.Fatal(err)
	}
	row, _, err := d.state.GetInstance(id)
	if err != nil || row.Status != "idle" {
		t.Fatalf("detach suspended unknown native work: %+v %v", row, err)
	}
	after := d.sup.EndpointPID(id)
	if original == nil || after == nil || *original != *after {
		t.Fatal("detach destroyed persistent endpoint")
	}
	// An explicit stop is still allowed; it is separate from closing a view.
	if err := d.doStop(client, id); err != nil {
		t.Fatal(err)
	}
	if d.sup.EndpointPID(id) != nil {
		t.Fatal("explicit stop could not terminate endpoint")
	}
}
