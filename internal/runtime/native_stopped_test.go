//go:build linux || darwin

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/session"
)

func TestPersistentNativeStoppedPrecedesProducerRetirementAfterReap(t *testing.T) {
	for _, runtime := range []string{"fake", "qwen", "codex"} {
		t.Run(runtime, func(t *testing.T) {
			var sup *proc.Supervisor
			var driver session.Driver
			var sess *session.RuntimeSession
			var setRegistration func(session.NativeEventObserverRegistrationFactory)
			switch runtime {
			case "fake":
				var fake *PersistentFake
				var manager *session.Manager
				sup, manager, fake, _ = newPersistentFixture(t)
				sess = manager.Session("inst-stopped", domain.RuntimeFakePersistent, t.TempDir())
				driver = fake
				setRegistration = func(f session.NativeEventObserverRegistrationFactory) {
					fake.NativeEventObserverRegistrationFactory = f
				}
			case "qwen":
				var q *QwenPersistent
				var workspace string
				var env []string
				sup, q, workspace, env = newQwenLifecycleFixture(t)
				sess = newLifecycleSession(workspace, env)
				driver = q
				setRegistration = func(f session.NativeEventObserverRegistrationFactory) { q.NativeEventObserverRegistrationFactory = f }
			case "codex":
				var c *CodexPersistent
				var workspace string
				var env []string
				sup, c, workspace, env = newCodexLifecycleFixture(t)
				sess = newCodexLifecycleSession(workspace, env)
				driver = c
				setRegistration = func(f session.NativeEventObserverRegistrationFactory) { c.NativeEventObserverRegistrationFactory = f }
			}
			observed := make(chan session.SessionEvent, 64)
			retired := make(chan struct{})
			setRegistration(func(id string) session.NativeEventObserverRegistration {
				return session.NativeEventObserverRegistration{Observe: func(event session.SessionEvent) error {
					if event.Type == session.EventSessionStopped && sup.EndpointPID(id) != nil {
						t.Error("stopped source emitted before supervised reap")
					}
					observed <- event
					return nil
				}, Retire: func() { close(retired) }}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := driver.Activate(ctx, sess, make(chan session.SessionEvent, 64)); err != nil {
				t.Fatal(err)
			}
			originalSID := sess.NativeID
			if originalSID == "" {
				t.Fatal("test process never established native session")
			}
			if err := driver.Stop(sess.InstanceID); err != nil {
				t.Fatal(err)
			}
			select {
			case <-retired:
			case <-ctx.Done():
				t.Fatal("producer retirement did not complete")
			}
			close(observed)
			stopped := 0
			for event := range observed {
				if event.Type == session.EventSessionStopped {
					stopped++
					if event.SessionID != originalSID || event.TurnID != "" || event.Error != "" {
						t.Fatal("EOF source invented session, turn or error", event)
					}
				}
			}
			if stopped != 1 {
				t.Fatalf("expected one actual stopped source before Retire, got %d", stopped)
			}
		})
	}
}
