package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func TestManagerLifecycleFinalizationSerializesTransitions(t *testing.T) {
	for _, hibernateFirst := range []bool{false, true} {
		name := "activation"
		if hibernateFirst {
			name = "hibernation"
		}
		t.Run(name, func(t *testing.T) {
			driver := newMemDriver()
			m := newTestManager(t, driver)
			s := m.Session("finalize", domain.RuntimeFake, t.TempDir())
			if hibernateFirst {
				if _, err := m.EnsureActive(context.Background(), s, nil); err != nil {
					t.Fatal(err)
				}
			}
			if hibernateFirst {
				m.mu.Lock()
				s.Materialised = true
				m.mu.Unlock()
				driver.stored[s.NativeID] = true
			}
			entered, release := make(chan struct{}), make(chan struct{})
			first, second := make(chan error, 1), make(chan error, 1)
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			pause := func(snapshot LifecycleSnapshot) error {
				// State takes m.mu: callbacks must be able to use ordinary queries.
				if _, ok := m.State(s.InstanceID); !ok {
					return errors.New("missing session")
				}
				if snapshot.NativeID != "native-abc" {
					return errors.New("missing settled native identity")
				}
				close(entered)
				<-release
				return nil
			}
			go func() {
				if hibernateFirst {
					first <- m.HibernateAndFinalize(context.Background(), s, pause)
					return
				}
				first <- m.EnsureActiveAndFinalize(context.Background(), s, nil, func(_ *RuntimeEndpoint, snapshot LifecycleSnapshot, err error) error {
					if err != nil {
						return err
					}
					return pause(snapshot)
				})
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("finalizer did not start")
			}
			started := make(chan struct{})
			go func() {
				close(started)
				if hibernateFirst {
					second <- m.EnsureActiveAndFinalize(context.Background(), s, nil, func(_ *RuntimeEndpoint, _ LifecycleSnapshot, err error) error { return err })
					return
				}
				second <- m.HibernateAndFinalize(context.Background(), s, func(LifecycleSnapshot) error { return nil })
			}()
			<-started
			select {
			case err := <-second:
				t.Fatalf("transition passed unfinished finalizer: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			driver.mu.Lock()
			activated, hibernated := driver.activated, driver.hibernated
			driver.mu.Unlock()
			if activated != 1 || hibernated != map[bool]int{false: 0, true: 1}[hibernateFirst] {
				t.Fatalf("driver ran during finalization: activated=%d hibernated=%d", activated, hibernated)
			}
			close(release)
			for _, done := range []chan error{first, second} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("transition did not finish")
				}
			}
			state, _ := m.State(s.InstanceID)
			want := StateInactive
			if hibernateFirst {
				want = StateIdle
			}
			if state != want {
				t.Fatalf("state=%s, want %s", state, want)
			}
		})
	}
}

func TestManagerActivationFinalizesError(t *testing.T) {
	m := newTestManager(t, newMemDriver())
	s := m.Session("finalize-error", "missing-runtime", t.TempDir())
	ctx := context.Background()
	finalized := false
	want := errors.New("finalized error")
	err := m.EnsureActiveAndFinalize(ctx, s, nil, func(_ *RuntimeEndpoint, _ LifecycleSnapshot, err error) error {
		finalized = true
		if err == nil {
			t.Errorf("activation error=%v", err)
		}
		return want
	})
	if !finalized || !errors.Is(err, want) {
		t.Fatalf("finalized=%v err=%v", finalized, err)
	}
}
