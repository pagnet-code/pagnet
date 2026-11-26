package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectEndpointWakeAttachmentTerminalResult(t *testing.T) {
	for _, reason := range []string{"callback", "writer-error", "writer-timeout", "server-closed", "handle-disabled", "lane-disabled"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, handle := wakeAttachmentFixture(t, true)
			callbackErr := errors.New("private callback error")
			writeErr := errors.New("private writer error")
			callback := func(context.Context) error { return callbackErr }
			want := error(context.Canceled)
			if reason == "writer-timeout" {
				d.writeTimeout = 20 * time.Millisecond
				d.writeMu.Lock()
				defer d.writeMu.Unlock()
				want = context.DeadlineExceeded
			} else if reason == "writer-error" {
				lane.write = func(time.Time, []byte) error { return writeErr }
				lane.writeFailed = func() {}
				want = writeErr
			} else if reason == "callback" {
				want = callbackErr
			} else if reason == "server-closed" {
				want = ErrNativeOriginAdmissionRejected
			}
			result, err := lane.attach(handle, callback)
			if err != nil || result == nil {
				t.Fatalf("attach result: %v, %v", result, err)
			}
			if reason != "writer-timeout" && reason != "writer-error" && result.TerminalError() != nil {
				t.Fatal("live attachment reported terminal error")
			}
			// Observers race exact removal and wait on the returned result,
			// without retaining or polling the connection's registration maps.
			const observers = 16
			observed := make(chan error, observers)
			for i := 0; i < observers; i++ {
				go func() {
					<-result.Done()
					observed <- result.TerminalError()
				}()
			}
			switch reason {
			case "callback":
				wakeProtocolAccept(t, lane, wakeProtocolOffer(result))
			case "server-closed":
				closed := transport.DirectEndpointWakeClosedV1{Protocol: transport.DirectEndpointWakeProtocolV1, SubscriptionID: result.subscription.SubscriptionID, Reason: transport.DirectEndpointWakeClosedRetryExhausted}
				if handled, err := lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeClosed, closed)); !handled || err != nil {
					t.Fatal("server close rejected", err)
				}
			case "handle-disabled":
				handle.Remove()
			case "lane-disabled":
				lane.close()
			}
			for i := 0; i < observers; i++ {
				select {
				case got := <-observed:
					if got != want {
						t.Fatalf("terminal outcome: got %v, want %v", got, want)
					}
				case <-time.After(time.Second):
					t.Fatal("terminal observer was not notified")
				}
			}
			// Later competing removals cannot overwrite the first outcome.
			lane.close()
			handle.Remove()
			if result.TerminalError() != want {
				t.Fatal("terminal outcome changed after later removal")
			}
			// Reading the immutable outcome must not acquire c.mu or invoke
			// controller code under that lock.
			lane.mu.Lock()
			read := make(chan error, 1)
			go func() { read <- result.TerminalError() }()
			select {
			case got := <-read:
				lane.mu.Unlock()
				if got != want {
					t.Fatal("terminal read lost outcome")
				}
			case <-time.After(time.Second):
				lane.mu.Unlock()
				t.Fatal("terminal read blocked on registration lock")
			}
		})
	}
}

func TestDirectEndpointWakeRejectedAttachHasNoResult(t *testing.T) {
	_, lane, handle := wakeAttachmentFixture(t, true)
	handle.Remove()
	result, err := lane.attach(handle, func(context.Context) error { return nil })
	if result != nil || err != ErrNativeObservationConflict {
		t.Fatalf("rejected attachment returned result: %v, %v", result, err)
	}
}
