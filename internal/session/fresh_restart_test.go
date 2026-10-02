package session

import (
	"context"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func TestExplicitFreshRestartPreservesOrdinaryResumeGates(t *testing.T) {
	for _, mode := range []string{"unmaterialised", "materialised", "lost", "pending"} {
		t.Run(mode, func(t *testing.T) {
			d := newMemDriver()
			m := newTestManager(t, d)
			s := m.Session("original", domain.RuntimeFake, "/original-workspace")
			if _, err := m.EnsureActive(context.Background(), s, nil); err != nil {
				t.Fatal(err)
			}
			originalID := s.NativeID
			if err := m.Stop(s.InstanceID); err != nil {
				t.Fatal(err)
			}
			m.mu.Lock()
			s.State = StateInactive
			if mode != "unmaterialised" {
				s.Materialised = true
			}
			if mode == "lost" {
				s.State = StateLost
			}
			if mode == "pending" {
				s.PendingInteractions = map[string]bool{"original-choice": true}
				s.NativeBusy = true
			}
			m.mu.Unlock()
			d.mu.Lock()
			d.minted = "genuinely-new-native-id"
			d.stored[originalID] = mode != "lost"
			d.mu.Unlock()
			if mode == "unmaterialised" {
				if _, err := m.EnsureActive(context.Background(), s, nil); !errors.Is(err, ErrNotMaterialised) {
					t.Fatalf("ordinary resume must refuse: %v", err)
				}
			}
			if mode == "lost" {
				if _, err := m.EnsureActive(context.Background(), s, nil); !errors.Is(err, ErrSessionLost) {
					t.Fatalf("ordinary missing resume must refuse: %v", err)
				}
			}
			events := make(chan SessionEvent, 16)
			ep, err := m.StartFresh(context.Background(), s, events)
			if err != nil {
				t.Fatal(err)
			}
			if s.NativeID == originalID || s.NativeID != "genuinely-new-native-id" || ep == nil || !d.Live(s.InstanceID) {
				t.Fatal("fresh restart reused old conversation")
			}
			if s.Materialised || s.NativeBusy || len(s.PendingInteractions) != 0 || s.State != StateIdle {
				t.Fatal("fresh endpoint inherited old conversation activity")
			}
			if d.submittedCount() != 0 {
				t.Fatal("restart replayed original effects")
			}
			select {
			case event := <-events:
				if event.Type != EventSessionStarted {
					t.Fatalf("fresh restart claimed resume: %s", event.Type)
				}
			default:
				t.Fatal("missing genuine session-start event")
			}
			if mode == "materialised" || mode == "pending" {
				if !d.stored[originalID] {
					t.Fatal("original historical conversation erased")
				}
			}
		})
	}
}

func TestExplicitFreshRestartRefusesLivePendingOrForeignOwnership(t *testing.T) {
	for _, mode := range []string{"live", "pending-submit", "external", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			d := newMemDriver()
			m := newTestManager(t, d)
			s := m.Session("original", domain.RuntimeFake, "/workspace")
			if _, err := m.EnsureActive(context.Background(), s, nil); err != nil {
				t.Fatal(err)
			}
			original := s.NativeID
			count := d.activatedCount()
			if mode != "live" {
				if err := m.Stop(s.InstanceID); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "pending-submit" {
				lock := m.promptLock(s.InstanceID)
				lock.Lock()
				defer lock.Unlock()
			}
			if mode == "external" {
				s.Ownership = OwnershipExternal
			}
			ctx := context.Background()
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := m.StartFresh(ctx, s, nil); err == nil {
				t.Fatal("unsafe fresh accepted")
			}
			if s.NativeID != original || d.activatedCount() != count {
				t.Fatal("refusal mutated original conversation")
			}
		})
	}
}

// The old process may still report a materialised conversation in its native
// state files. That fact belongs to its old SID, never the new fresh endpoint.
type freshMaterialisationDriver struct{ *memDriver }

func (d *freshMaterialisationDriver) Materialised(string) bool { return true }
func TestExplicitFreshRestartDoesNotReuseOldMaterialisationReport(t *testing.T) {
	d := &freshMaterialisationDriver{newMemDriver()}
	m := newTestManager(t, d)
	s := m.Session("original", domain.RuntimeFake, "/workspace")
	if _, err := m.EnsureActive(context.Background(), s, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(s.InstanceID); err != nil {
		t.Fatal(err)
	}
	d.minted = "new-conversation"
	if _, err := m.StartFresh(context.Background(), s, nil); err != nil {
		t.Fatal(err)
	}
	if s.Materialised {
		t.Fatal("new conversation inherited historical materialisation")
	}
}
