package session

// Phase 3 (terminal session unification) D3 tests: the narrow OPTIONAL
// PTYOwner interface and the Manager.PTYMaster seam. PTY ownership stays
// OPTIONAL per endpoint (invariant I1): the generic architecture supports
// both the PTY-owning topology (the fake; Qwen/Claude later) and the
// no-PTY topology (server-class runtimes). PTYMaster is nil-safe on every
// missing link, and the *os.File it returns is HUMAN-PLANE only (I2: no
// pipe/file member is added to the base Driver contract).

import (
	"context"
	"os"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

// ptyTestDriver is a minimal Driver for the PTYMaster seam tests. It tracks
// a live flag and (for the PTYOwner variant) a master. It does NOT implement
// PTYOwner — ptyOwnerDriver adds that.
type ptyTestDriver struct {
	name   domain.RuntimeName
	live   bool
	master *os.File
}

func (d *ptyTestDriver) Name() domain.RuntimeName { return d.name }

func (d *ptyTestDriver) Capabilities() Capabilities { return Capabilities{} }

func (d *ptyTestDriver) Activate(ctx context.Context, sess *RuntimeSession, events chan<- SessionEvent) (*RuntimeEndpoint, error) {
	d.live = true
	sess.NativeID = "native-1"
	sess.State = StateIdle
	sess.Endpoint = &RuntimeEndpoint{ID: "ep-" + sess.InstanceID, Runtime: d.name, Healthy: true}
	return sess.Endpoint, nil
}

func (d *ptyTestDriver) Submit(ctx context.Context, sess *RuntimeSession, req SubmitRequest, events chan<- SessionEvent) error {
	return nil
}

func (d *ptyTestDriver) Hibernate(ctx context.Context, sess *RuntimeSession) error {
	d.live = false
	sess.State = StateInactive
	sess.Endpoint = nil
	return nil
}

func (d *ptyTestDriver) Stop(instanceID string) error {
	d.live = false
	return nil
}

func (d *ptyTestDriver) PID(instanceID string) *int { return nil }

func (d *ptyTestDriver) Live(instanceID string) bool { return d.live }

// ptyOwnerDriver adds PTYMaster, so it implements PTYOwner.
type ptyOwnerDriver struct {
	*ptyTestDriver
}

func (d *ptyOwnerDriver) PTYMaster(instanceID string) *os.File {
	if !d.live {
		return nil
	}
	return d.master
}

// dummyMaster is a stand-in PTY master (a real file; the test only checks
// identity and nil-ness, never reads/writes it).
func dummyMaster(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "master")
	if err != nil {
		t.Fatalf("create dummy master: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestManagerPTYMaster_PTYOwner: a driver that implements PTYOwner exposes
// its live endpoint's master through Manager.PTYMaster; after hibernate
// (no live endpoint) it returns nil.
func TestManagerPTYMaster_PTYOwner(t *testing.T) {
	m := NewManager()
	d := &ptyOwnerDriver{ptyTestDriver: &ptyTestDriver{name: "test-pty", master: dummyMaster(t)}}
	m.RegisterDriver(d)
	sess := m.Session("inst-1", d.name, t.TempDir())

	ctx := context.Background()
	if _, err := d.Activate(ctx, sess, nil); err != nil {
		t.Fatalf("activate: %v", err)
	}
	master := m.PTYMaster("inst-1")
	if master == nil {
		t.Fatal("PTYMaster is nil for a live PTY endpoint")
	}
	if master != d.master {
		t.Fatal("PTYMaster returned the wrong master")
	}

	// Hibernate: no live endpoint → nil.
	if err := d.Hibernate(ctx, sess); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	if got := m.PTYMaster("inst-1"); got != nil {
		t.Fatalf("PTYMaster is non-nil after hibernate: %v", got)
	}
}

// TestManagerPTYMaster_NoPTYOwner: a driver that does NOT implement PTYOwner
// (the no-PTY topology) yields nil — a clean defined refusal, never a crash.
func TestManagerPTYMaster_NoPTYOwner(t *testing.T) {
	m := NewManager()
	d := &ptyTestDriver{name: "test-nopTY"} // no PTYMaster method
	m.RegisterDriver(d)
	sess := m.Session("inst-2", d.name, t.TempDir())

	ctx := context.Background()
	if _, err := d.Activate(ctx, sess, nil); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if got := m.PTYMaster("inst-2"); got != nil {
		t.Fatalf("PTYMaster is non-nil for a driver without PTYOwner: %v", got)
	}
}

// TestManagerPTYMaster_UnknownInstance: no session for the instance → nil.
func TestManagerPTYMaster_UnknownInstance(t *testing.T) {
	m := NewManager()
	if got := m.PTYMaster("no-such-instance"); got != nil {
		t.Fatalf("PTYMaster is non-nil for an unknown instance: %v", got)
	}
}

// TestManagerPTYMaster_DriverWithoutActivePTY: a PTYOwner driver whose
// endpoint is live but has no active PTY (launched without one) yields nil.
func TestManagerPTYMaster_DriverWithoutActivePTY(t *testing.T) {
	m := NewManager()
	d := &ptyOwnerDriver{ptyTestDriver: &ptyTestDriver{name: "test-pty-off"}} // master nil
	m.RegisterDriver(d)
	sess := m.Session("inst-3", d.name, t.TempDir())

	ctx := context.Background()
	if _, err := d.Activate(ctx, sess, nil); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if got := m.PTYMaster("inst-3"); got != nil {
		t.Fatalf("PTYMaster is non-nil for a live endpoint with no active PTY: %v", got)
	}
}
