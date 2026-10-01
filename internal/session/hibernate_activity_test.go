package session

import (
	"context"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"sync/atomic"
	"testing"
	"time"
)

type gatedActivityDriver struct {
	*memDriver
	started      chan struct{}
	release      chan struct{}
	active       atomic.Bool
	materialised atomic.Bool
}

func (d *gatedActivityDriver) Activate(ctx context.Context, s *RuntimeSession, events chan<- SessionEvent) (*RuntimeEndpoint, error) {
	if d.started != nil {
		close(d.started)
		select {
		case <-d.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return d.memDriver.Activate(ctx, s, events)
}
func (d *gatedActivityDriver) ActiveWork(string) bool   { return d.active.Load() }
func (d *gatedActivityDriver) Materialised(string) bool { return d.materialised.Load() }

func TestManagerHibernateRejectsPromptBeforeBusyState(t *testing.T) {
	d := &gatedActivityDriver{memDriver: newMemDriver(), started: make(chan struct{}), release: make(chan struct{})}
	m := newTestManager(t, d)
	s := m.Session("prompt-start", domain.RuntimeFake, t.TempDir())
	events := make(chan SessionEvent, 32)
	done := make(chan error, 1)
	go func() {
		_, err := m.Submit(context.Background(), s, SubmitRequest{Kind: SubmitPrompt, TurnID: "turn", Input: "actual work"}, events)
		done <- err
	}()
	<-d.started
	result := make(chan error, 1)
	go func() { result <- m.Hibernate(context.Background(), s) }()
	select {
	case err := <-result:
		if !errors.Is(err, ErrBusy) {
			t.Fatalf("activation-before-busy was hibernatable: %v", err)
		}
	case <-time.After(time.Second):
		close(d.release)
		t.Fatal("hibernate waited for activation instead of refusing active prompt")
	}
	close(d.release)
	for range events {
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := m.Hibernate(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

func TestManagerHibernatePreservesCompletedNativeExchange(t *testing.T) {
	d := &gatedActivityDriver{memDriver: newMemDriver()}
	m := newTestManager(t, d)
	s := m.Session("human", domain.RuntimeFake, t.TempDir())
	if _, err := m.EnsureActive(context.Background(), s, nil); err != nil {
		t.Fatal(err)
	}
	d.active.Store(true)
	if !m.ActiveWork(s.InstanceID) {
		t.Fatal("native active work not observed")
	}
	if err := m.Hibernate(context.Background(), s); !errors.Is(err, ErrBusy) {
		t.Fatalf("native work hibernated: %v", err)
	}
	d.active.Store(false)
	d.materialised.Store(true)
	d.mu.Lock()
	d.stored[s.NativeID] = true
	d.mu.Unlock()
	original := s.NativeID
	if err := m.Hibernate(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if !s.Materialised {
		t.Fatal("completed native exchange lost materialisation")
	}
	if _, err := m.EnsureActive(context.Background(), s, nil); err != nil {
		t.Fatal(err)
	}
	if s.NativeID != original {
		t.Fatal("human conversation was cold-started")
	}
}
