package session

import (
	"context"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

type configurationWorkDriver struct {
	*gatedActivityDriver
	turnStarted chan struct{}
	turnRelease chan struct{}
}

func (d *configurationWorkDriver) Submit(ctx context.Context, s *RuntimeSession, req SubmitRequest, events chan<- SessionEvent) error {
	close(d.turnStarted)
	select {
	case <-d.turnRelease:
	case <-ctx.Done():
		return ctx.Err()
	}
	return d.memDriver.Submit(ctx, s, req, events)
}

func TestLaunchConfigurationChangeDefersActiveWork(t *testing.T) {
	for _, native := range []bool{false, true} {
		name := "managed-prompt"
		if native {
			name = "native-terminal"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			defer cancel()
			d := &configurationWorkDriver{gatedActivityDriver: &gatedActivityDriver{memDriver: newMemDriver()}, turnStarted: make(chan struct{}), turnRelease: make(chan struct{})}
			m := newTestManager(t, d)
			s := m.Session(name, domain.RuntimeFake, t.TempDir())
			m.SetModel(s, "old-model")
			old, err := m.EnsureActive(ctx, s, nil)
			if err != nil {
				t.Fatal(err)
			}
			var done chan error
			if native {
				d.active.Store(true)
			} else {
				done = make(chan error, 1)
				events := make(chan SessionEvent, 32)
				go func() {
					_, err := m.Submit(ctx, s, SubmitRequest{Kind: SubmitPrompt, TurnID: "actual-turn", Input: "work"}, events)
					done <- err
				}()
				select {
				case <-d.turnStarted:
				case <-ctx.Done():
					t.Fatal("prompt did not start")
				}
			}
			m.SetModel(s, "new-model")
			kept, err := m.EnsureActive(ctx, s, nil)
			if err != nil || kept != old {
				t.Fatalf("active endpoint replaced: %v", err)
			}
			d.mu.Lock()
			stops := d.hibernated
			starts := d.activated
			d.mu.Unlock()
			if stops != 0 || starts != 1 {
				t.Fatalf("active work restarted: stop%d start%d", stops, starts)
			}
			if native {
				d.active.Store(false)
			} else {
				close(d.turnRelease)
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
			next, err := m.EnsureActive(ctx, s, nil)
			if err != nil {
				t.Fatal(err)
			}
			if next.PID == old.PID || next.LaunchModel != "new-model" {
				t.Fatal("deferred configuration never applied")
			}
		})
	}
}

// The prompt admission lock must protect the gap before StateBusy is written.
// TryLock is essential: blocking here would invert prompt→activation ordering.
func TestLaunchConfigurationChangeDefersAdmittedPrompt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d := newMemDriver()
	m := newTestManager(t, d)
	s := m.Session("admitted", domain.RuntimeFake, t.TempDir())
	m.SetModel(s, "old")
	old, err := m.EnsureActive(ctx, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	prompt := m.promptLock(s.InstanceID)
	prompt.Lock()
	m.SetModel(s, "new")
	done := make(chan error, 1)
	go func() {
		kept, err := m.EnsureActive(ctx, s, nil)
		if err == nil && kept != old {
			err = ErrSessionLost
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			prompt.Unlock()
			t.Fatal(err)
		}
	case <-ctx.Done():
		prompt.Unlock()
		t.Fatal("configuration replacement waited on admitted prompt")
	}
	prompt.Unlock()
	next, err := m.EnsureActive(ctx, s, nil)
	if err != nil || next.PID == old.PID {
		t.Fatalf("configuration not applied after admission released: %v", err)
	}
}

// Native activity can become visible between the manager's check and the
// driver's own final stop check. A refusal retains attachment and config.
type configurationStopRaceDriver struct {
	*memDriver
	refuse bool
}

func (d *configurationStopRaceDriver) Hibernate(ctx context.Context, s *RuntimeSession) error {
	if d.refuse {
		return ErrBusy
	}
	return d.memDriver.Hibernate(ctx, s)
}
func TestLaunchConfigurationNativeStopRefusalRetainsEndpoint(t *testing.T) {
	d := &configurationStopRaceDriver{memDriver: newMemDriver(), refuse: true}
	m := newTestManager(t, d)
	s := m.Session("native-stop-race", domain.RuntimeFake, t.TempDir())
	m.SetModel(s, "old")
	old, err := m.EnsureActive(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.SetModel(s, "new")
	kept, err := m.EnsureActive(context.Background(), s, nil)
	if err != nil || kept != old {
		t.Fatalf("native work refusal broke attachment: %v", err)
	}
	d.refuse = false
	next, err := m.EnsureActive(context.Background(), s, nil)
	if err != nil || next.PID == old.PID || next.LaunchModel != "new" {
		t.Fatalf("deferred config lost: %v", err)
	}
}
