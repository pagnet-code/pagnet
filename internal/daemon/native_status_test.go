package daemon

import (
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
	"sync/atomic"
	"testing"
)

type nativeStatusDriver struct {
	session.Driver
	active atomic.Bool
}

func (d *nativeStatusDriver) ActiveWork(string) bool { return d.active.Load() }
func TestHeartbeatDerivesWorkingOnlyFromPositiveNativeActivity(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()
	id := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{CommandID: "native-status-launch", InstanceID: id, Runtime: string(domain.RuntimeFakePersistent), Kind: "representative"})
	waitForEndpointLive(t, d, id)
	driver := &nativeStatusDriver{Driver: d.sessions.DriverFor(domain.RuntimeFakePersistent)}
	d.sessions.RegisterDriver(driver)
	readStatus := func() string {
		t.Helper()
		d.sendHeartbeat(client)
		for {
			var env transport.Envelope
			if err := server.ReadJSON(&env); err != nil {
				t.Fatal(err)
			}
			if env.Type != transport.MsgHeartbeat {
				continue
			}
			var p transport.HeartbeatPayload
			if err := env.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			for _, row := range p.Instances {
				if row.InstanceID == id {
					return row.Status
				}
			}
			t.Fatal("instance omitted from heartbeat")
		}
	}
	if got := readStatus(); got != "idle" {
		t.Fatalf("idle live endpoint became %s", got)
	}
	driver.active.Store(true)
	if got := readStatus(); got != "working" {
		t.Fatalf("native active turn hidden: %s", got)
	}
	row, ok, err := d.state.GetInstance(id)
	if err != nil || !ok || row.Status != "idle" {
		t.Fatal("observed activity mutated persisted lifecycle/task state")
	}
	driver.active.Store(false)
	if got := readStatus(); got != "idle" {
		t.Fatalf("completed native turn stayed %s", got)
	}
	if d.sup.EndpointPID(id) == nil {
		t.Fatal("status observation stopped endpoint")
	}
}
