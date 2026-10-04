package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

func TestPersistentFakeAuthenticAcceptedCaptureFailureStopsWithoutPaidReplay(t *testing.T) {
	for _, failType := range []string{session.EventTurnStarted, session.EventTurnOutput} {
		t.Run(failType, func(t *testing.T) {
			sup, m, driver, _ := newPersistentFixture(t)
			rejected := errors.New("original durable source rejected")
			retired, stopped := make(chan struct{}), make(chan struct{})
			starts, completed := 0, 0
			driver.NativeEventObserverRegistrationFactory = func(string) session.NativeEventObserverRegistration {
				return session.NativeEventObserverRegistration{Observe: func(e session.SessionEvent) error {
					if e.Type == session.EventTurnStarted {
						starts++
					}
					if e.Type == session.EventTurnCompleted {
						completed++
					}
					if e.Type == session.EventSessionStopped {
						close(stopped)
					}
					if e.Type == failType {
						return rejected
					}
					return nil
				}, Retire: func() { close(retired) }}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			sess := m.Session("actual-capture-rejection", domain.RuntimeFakePersistent, t.TempDir())
			events := make(chan session.SessionEvent, 64)
			_, err := m.Submit(ctx, sess, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: "original-turn", InputKind: "task", Input: "genuine paid-effect analogue"}, events)
			if !errors.Is(err, session.ErrTurnInterrupted) || !errors.Is(err, rejected) {
				t.Fatal("capture failure replayable or cause discarded", err)
			}
			select {
			case <-retired:
			case <-ctx.Done():
				t.Fatal("actual native reader not retired")
			}
			select {
			case <-stopped:
			default:
				t.Fatal("no genuine reaped EOF evidence")
			}
			if starts != 1 || completed != 0 || sup.Stats().ActiveEndpoints != 0 || driver.Live(sess.InstanceID) {
				t.Fatal("failed original source replayed/completed or remained live", starts, completed)
			}
		})
	}
}
