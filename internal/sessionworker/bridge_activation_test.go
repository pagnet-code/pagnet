//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

type bridgeActivationDriver struct {
	session.Driver
	entered chan struct{}
	release chan struct{}
	live    atomic.Bool
}

func (d *bridgeActivationDriver) Name() domain.RuntimeName           { return domain.RuntimeFakePersistent }
func (d *bridgeActivationDriver) Capabilities() session.Capabilities { return session.Capabilities{} }
func (d *bridgeActivationDriver) Live(string) bool                   { return d.live.Load() }
func (d *bridgeActivationDriver) Activate(ctx context.Context, s *session.RuntimeSession, _ chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
	s.NativeID = "genuine-original-session"
	d.live.Store(true)
	close(d.entered)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.release:
	}
	return &session.RuntimeEndpoint{Ownership: session.OwnershipPagnet}, nil
}
func bridgeActivationFixture(t *testing.T) (*SessionOwner, *bridgeActivationDriver, <-chan error) {
	t.Helper()
	j, _ := testJournal(t)
	d := &bridgeActivationDriver{entered: make(chan struct{}), release: make(chan struct{})}
	m := session.NewManager()
	m.RegisterDriver(d)
	s := m.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	o := &SessionOwner{ctx: t.Context(), captureKey: bytes.Repeat([]byte{42}, 32), origin: json.RawMessage(`{"id":"original-origin"}`), journal: j, manager: m, driver: d, generation: "original-generation", nonce: "original-nonce"}
	done := make(chan error, 1)
	go func() { _, err := m.EnsureActive(t.Context(), s, nil); done <- err }()
	<-d.entered
	t.Cleanup(func() {
		select {
		case <-d.release:
		default:
			close(d.release)
		}
		<-done
	})
	return o, d, done
}
func TestBridgeWaitsForOriginalActivationSession(t *testing.T) {
	o, d, _ := bridgeActivationFixture(t)
	if _, known := o.manager.TryNativeID(o.journal.scope.InstanceID); known {
		t.Fatal("activation must still own the session lock")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	type answer struct {
		sid string
		err error
	}
	result := make(chan answer, 1)
	go func() { sid, err := o.awaitBridgeNativeSession(ctx, o.generation, o.nonce); result <- answer{sid, err} }()
	select {
	case a := <-result:
		t.Fatalf("forwarded before genuine activation completed: %v", a.err)
	case <-time.After(20 * time.Millisecond):
	}
	close(d.release)
	a := <-result
	if a.err != nil || a.sid != "genuine-original-session" {
		t.Fatal("lost original activation session", a.sid, a.err)
	}
}
func TestBridgeActivationWaitCannotChangeAuthority(t *testing.T) {
	for _, mode := range []string{"cancelled", "deadline", "generation", "nonce", "closing", "dead"} {
		t.Run(mode, func(t *testing.T) {
			o, d, _ := bridgeActivationFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			generation, nonce := o.generation, o.nonce
			switch mode {
			case "cancelled":
				cancel()
			case "generation":
				o.generation = "replacement"
			case "nonce":
				o.nonce = "replacement"
			case "closing":
				o.closing = true
			case "dead":
				d.live.Store(false)
			}
			sid, err := o.awaitBridgeNativeSession(ctx, generation, nonce)
			if sid != "" || err == nil {
				t.Fatal("unready or foreign activation obtained authority")
			}
			if mode == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			if mode != "cancelled" && mode != "deadline" && !errors.Is(err, ErrFenced) {
				t.Fatal(err)
			}
		})
	}
}

func TestBridgeCapturedSessionBreaksActivationDependency(t *testing.T) {
	o, d, _ := bridgeActivationFixture(t)
	observer := o.nativeEventObserver(o.journal.scope.InstanceID)
	if err := observer(session.SessionEvent{Type: session.EventSessionStarted, SessionID: "genuine-original-session"}); err != nil {
		t.Fatal(err)
	}
	if _, known := o.manager.TryNativeID(o.journal.scope.InstanceID); known {
		t.Fatal("vendor activation unexpectedly finished before its MCP call")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	sid, err := o.awaitBridgeNativeSession(ctx, o.generation, o.nonce)
	if err != nil || sid != "genuine-original-session" {
		t.Fatal("genuine captured startup could not make MCP call", err)
	}
	// The vendor may now finish Activate after its tool request is serviced.
	close(d.release)
}

func TestBridgeDoesNotPublishUncommittedOrOldSessionIdentity(t *testing.T) {
	o, _, _ := bridgeActivationFixture(t)
	if _, err := o.journal.db.Exec(`CREATE TRIGGER reject_start BEFORE INSERT ON worker_observations BEGIN SELECT RAISE(ABORT,'capture unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	o.ctx = ctx
	observer := o.nativeEventObserver(o.journal.scope.InstanceID)
	if err := observer(session.SessionEvent{Type: session.EventSessionStarted, SessionID: "uncommitted-session"}); err == nil {
		t.Fatal("capture unexpectedly committed")
	}
	if o.bridgeSessionID != "" {
		t.Fatal("uncommitted identity published")
	}
	o.bridgeSessionID = "old-session"
	o.bridgeSessionGeneration = "old-generation"
	wait, stop := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer stop()
	if sid, err := o.awaitBridgeNativeSession(wait, o.generation, o.nonce); sid != "" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("old source identity obtained authority", err)
	}
}
