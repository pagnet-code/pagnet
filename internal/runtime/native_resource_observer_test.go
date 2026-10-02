//go:build linux || darwin

package runtime

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/session"
)

func TestStructuredNativeResourceLimitStopsOriginalProcessBeforeRetirement(t *testing.T) {
	for _, runtime := range []string{"claude", "opencode", "grok"} {
		t.Run(runtime, func(t *testing.T) {
			var driver session.Driver
			var sess *session.RuntimeSession
			var register func(session.NativeEventObserverRegistrationFactory)
			switch runtime {
			case "claude":
				d, s := claudeFixture(t)
				driver, sess = d, s
				register = func(f session.NativeEventObserverRegistrationFactory) { d.NativeEventObserverRegistrationFactory = f }
			case "grok":
				d, s := grokFixture(t, "")
				driver, sess = d, s
				register = func(f session.NativeEventObserverRegistrationFactory) { d.NativeEventObserverRegistrationFactory = f }
			case "opencode":
				binary, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				d := NewOpenCodePersistent(binary)
				d.PrefixArgs = []string{"opencode-acp-fixture"}
				d.StateDir = t.TempDir()
				d.StartupTimeout = 3 * time.Second
				sess = &session.RuntimeSession{InstanceID: domain.NewID().String(), Runtime: domain.RuntimeOpenCode, Workspace: t.TempDir()}
				driver = d
				register = func(f session.NativeEventObserverRegistrationFactory) { d.NativeEventObserverRegistrationFactory = f }
				t.Cleanup(func() { _ = d.Stop(sess.InstanceID) })
			}
			var mu sync.Mutex
			var observed []session.SessionEvent
			retired := make(chan struct{})
			register(func(string) session.NativeEventObserverRegistration {
				return session.NativeEventObserverRegistration{Observe: func(event session.SessionEvent) error {
					mu.Lock()
					defer mu.Unlock()
					observed = append(observed, event)
					if event.Type == session.EventTurnOutput {
						return fmt.Errorf("original durable marker: %w", session.ErrNativeResourceLimit)
					}
					return nil
				}, Retire: func() { close(retired) }}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			endpoint, err := driver.Activate(ctx, sess, nil)
			if err != nil {
				t.Fatal(err)
			}
			if endpoint.PID <= 0 || !proc.ProcessAlive(endpoint.PID) {
				t.Fatal("fixture did not launch actual original process")
			}
			// The observer rejects a genuine native text event. It must close only
			// that captured supervisor handle and report actual EOF, not a vendor result.
			_ = driver.Submit(ctx, sess, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: "resource-original", Input: "original output"}, make(chan session.SessionEvent, 32))
			select {
			case <-retired:
			case <-ctx.Done():
				t.Fatal("native reader did not retire after original resource limit")
			}
			if proc.ProcessAlive(endpoint.PID) {
				t.Fatal("resource retirement happened before original supervised process exit")
			}
			mu.Lock()
			defer mu.Unlock()
			stopped, output := 0, 0
			for _, event := range observed {
				switch event.Type {
				case session.EventTurnOutput:
					output++
				case session.EventSessionStopped:
					stopped++
					if event.SessionID != sess.NativeID {
						t.Fatal("EOF misattributed to another native session")
					}
				case session.EventTurnCompleted, session.EventTurnFailed:
					t.Fatal("resource limit invented a vendor terminal event", event.Type)
				}
			}
			if stopped != 1 || output != 1 {
				t.Fatal("genuine output/EOF evidence missing", stopped, output)
			}
		})
	}
}
