package daemon

import (
	"context"
	"errors"
	"github.com/pagnet-code/pagnet/internal/session"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDaemon_PersistentWakeActivatesWithoutSyntheticPrompt(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()
	id := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{CommandID: "idle-wake-launch", InstanceID: id, Runtime: string(domain.RuntimeFakePersistent), Kind: "representative"})
	waitForEndpointLive(t, d, id)
	if err := d.hibernateInstance(client, id, "test"); err != nil {
		t.Fatal(err)
	}
	wake := transport.WakeAgentPayload{WakeRequestID: "idle-wake", InstanceID: id, Reason: "work_queued"}
	envs := driveCommand(t, d, server, transport.MsgWakeAgent, wake, wake.WakeRequestID)
	if hasEnvelopeType(envs, transport.MsgRuntimeTurnStarted) || hasEnvelopeType(envs, transport.MsgRuntimeTurnCompleted) {
		t.Fatal("waking fabricated a provider prompt before the real queued work")
	}
	row, ok, err := d.state.GetInstance(id)
	if err != nil || !ok || row.Status != "idle" {
		t.Fatalf("wake did not activate idle endpoint: %+v %v", row, err)
	}
	if mat, _ := d.sessions.Materialised(id); mat {
		t.Fatal("pure wake created resumable conversation without real exchange")
	}
	// The real channel message is the first prompt, and uses the very endpoint
	// that wake established. No extra process or invented greeting is needed.
	endpointPID := d.sup.EndpointPID(id)
	envs = driveDeliver(t, d, server, transport.NetworkEventPayload{CommandID: "idle-wake-real-message", InstanceID: id, Kind: "channel", ConversationID: "conversation", Body: "actual human message"})
	if !hasEnvelopeType(envs, transport.MsgRuntimeTurnStarted) || !hasEnvelopeType(envs, transport.MsgRuntimeTurnCompleted) {
		t.Fatal("real message was not processed")
	}
	after := d.sup.EndpointPID(id)
	if endpointPID == nil || after == nil || *endpointPID != *after {
		t.Fatal("wake and delivery did not share one endpoint")
	}
}

type wakeFailureDriver struct {
	gatedPTYDriver
	d              *Daemon
	err            error
	observedStatus string
}

func (g *wakeFailureDriver) Activate(ctx context.Context, sess *session.RuntimeSession, events chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
	row, _, _ := g.d.state.GetInstance(sess.InstanceID)
	g.observedStatus = row.Status
	return nil, g.err
}

func TestDaemon_PersistentWakeActivationFailureSettlesWithoutPrompt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status string
	}{
		{"startup", errors.New("runtime startup refused"), "failed"},
		{"shutdown", context.Canceled, "hibernated"},
		{"lost", session.ErrSessionLost, "blocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDaemon(t)
			drv := &wakeFailureDriver{d: d, err: tc.err}
			d.sessions.RegisterDriver(drv)
			id := domain.NewID().String()
			if err := d.state.UpsertInstance(InstanceRow{InstanceID: id, Runtime: string(drv.Name()), Kind: "representative", Status: "hibernated", Workspace: t.TempDir()}); err != nil {
				t.Fatal(err)
			}
			if err := d.doWake(nil, id, "work_queued"); err == nil {
				t.Fatal("activation failure silently succeeded")
			}
			if drv.observedStatus != "waking" {
				t.Fatalf("heartbeat could publish stale state during activation: %q", drv.observedStatus)
			}
			row, _, err := d.state.GetInstance(id)
			if err != nil || row.Status != tc.status {
				t.Fatalf("wake failure left wrong status: %+v %v", row, err)
			}
		})
	}
}
