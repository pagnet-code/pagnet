//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// pumpWorker serves the real controller protocol, retaining its source until
// the daemon returns the exact committed backend receipt.
type pumpWorker struct {
	scope       sessionworker.Scope
	key         []byte
	snapshot    sessionworker.NativeSnapshot
	observation sessionworker.NativeObservation
	live        atomic.Bool
	confirmed   atomic.Bool
	verified    atomic.Bool
	acked       atomic.Bool
	ack         chan sessionworker.Request
	errors      chan error
}

func (w *pumpWorker) fail(err error) {
	select {
	case w.errors <- err:
	default:
	}
}

func (w *pumpWorker) serve(t *testing.T, dir string) {
	t.Helper()
	sock, err := sessionworker.SocketPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var connections []net.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, c)
			mu.Unlock()
			wg.Add(1)
			go func() { defer wg.Done(); w.handle(c) }()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for _, c := range connections {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
}

func (w *pumpWorker) handle(c net.Conn) {
	defer c.Close()
	if _, _, err := localpeer.Owner(c); err != nil {
		w.fail(err)
		return
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	nonce, err := swFreshNonce()
	if err != nil {
		w.fail(err)
		return
	}
	hello := swHandshake{Protocol: sessionworker.Protocol, Scope: w.scope, ServerNonce: nonce, Ownership: sessionworker.NativeOwnershipProtocol, WorkerBuild: "pump-worker"}
	if err = swWriteFrame(c, hello); err != nil {
		w.fail(err)
		return
	}
	var auth swHandshake
	if err = swReadFrame(c, &auth); err != nil {
		w.fail(err)
		return
	}
	if auth.Protocol != hello.Protocol || auth.Scope != hello.Scope || auth.ServerNonce != nonce || auth.Ownership != hello.Ownership || auth.WorkerBuild != hello.WorkerBuild || auth.Mode != "" || auth.NativeGeneration != "" || auth.Error != "" || auth.Lease != 0 || auth.ControllerID == "" || !swValidNonce(auth.ClientNonce) || !hmac.Equal([]byte(auth.Proof), []byte(swProof(w.key, "controller", auth))) {
		w.fail(fmt.Errorf("invalid controller authentication"))
		return
	}
	auth.Lease = 1
	auth.Proof = swProof(w.key, "worker", auth)
	if err = swWriteFrame(c, auth); err != nil {
		w.fail(err)
		return
	}
	_ = c.SetDeadline(time.Time{})
	for {
		var req sessionworker.Request
		if swReadFrame(c, &req) != nil {
			return
		}
		resp := sessionworker.Response{}
		switch req.Type {
		case "admission", "activation_poll", "bridge_poll", "dispatches":
		case "snapshot":
			snapshot := w.snapshot
			if !w.live.Load() {
				snapshot.PID = 0
			}
			resp.Snapshot = &snapshot
			if w.confirmed.Load() && snapshot.PID > 0 {
				w.verified.Store(true)
			}
		case "observations":
			if !w.acked.Load() {
				resp.Observations = []sessionworker.NativeObservation{w.observation}
			}
		case "observation_ack":
			wire, err := NativeWorkerWireObservation(w.observation)
			want := transport.NativeObservationReceiptPayload{ObservationID: wire.ObservationID, OriginID: wire.OriginID, Digest: wire.Digest, Disposition: "committed"}
			if err != nil || req.ObservationID != w.observation.ID || req.SourceDigest != w.observation.SourceDigest || req.SourceReceipt == nil || !reflect.DeepEqual(*req.SourceReceipt, want) {
				w.fail(fmt.Errorf("worker ACK changed source identity or committed receipt: %+v (%v)", req, err))
				resp.Error = "invalid observation acknowledgement"
			} else {
				w.acked.Store(true)
				select {
				case w.ack <- req:
				default:
				}
			}
		default:
			resp.Error = "unsupported pump worker request: " + req.Type
			w.fail(fmt.Errorf("%s", resp.Error))
		}
		if swWriteFrame(c, resp) != nil {
			return
		}
	}
}

func TestNativeWorkerPumpReceiptProgress(t *testing.T) {
	for _, mode := range []string{"live_confirmation_replays_pending", "disconnect_pending", "historical_stopped_source"} {
		t.Run(mode, func(t *testing.T) {
			w := &pumpWorker{key: []byte(strings.Repeat("k", 32)), ack: make(chan sessionworker.Request, 1), errors: make(chan error, 8)}
			first := make(chan struct{})
			replayed := make(chan struct{}, 1)
			var c *NativeObservationConnection
			var initial transport.NativeObservationPayload
			var deadline time.Time
			var sends, confirmations atomic.Int32
			var o sessionworker.NativeObservation
			c, o = deliveryFixture(t, func(ctx context.Context, typ string, value any) error {
				switch typ {
				case transport.MsgNativeObservation:
					payload := value.(transport.NativeObservationPayload)
					n := sends.Add(1)
					if n == 1 {
						initial = payload
						var ok bool
						deadline, ok = ctx.Deadline()
						if !ok || time.Until(deadline) > 30*time.Second {
							w.fail(fmt.Errorf("source delivery lost bounded deadline"))
						}
						if mode == "live_confirmation_replays_pending" {
							w.live.Store(true)
						}
						close(first)
						if mode != "historical_stopped_source" {
							return nil
						}
					} else {
						freshDeadline, _ := ctx.Deadline()
						if n != 2 || !reflect.DeepEqual(initial, payload) || !freshDeadline.Equal(deadline) || !w.verified.Load() {
							w.fail(fmt.Errorf("pending replay changed payload/deadline or preceded verified confirmation"))
							return nil
						}
						replayed <- struct{}{}
					}
					c.NativeWorkerObservationDisposition(transport.MsgNativeObservationReceipt, transport.NativeObservationReceiptPayload{ObservationID: payload.ObservationID, OriginID: payload.OriginID, Digest: payload.Digest, Disposition: "committed"})
				case transport.MsgNativeOriginSession:
					p := value.(transport.NativeOriginSessionPayload)
					a, err := c.AuthenticatedNativeHostSession()
					if err != nil || p.RunnerID != a.RunnerID || !p.RunnerEpoch.Equal(a.RunnerEpoch) || p.BootID != a.BootID {
						w.fail(fmt.Errorf("session confirmation lost authenticated admission"))
					}
					confirmations.Add(1)
					w.confirmed.Store(true)
					c.SessionConfirmed(transport.NativeOriginSessionConfirmedPayload{RequestID: p.RequestID, OriginID: p.OriginID, NativeGeneration: p.NativeGeneration, SessionID: p.SessionID, RunnerID: a.RunnerID, RunnerEpoch: a.RunnerEpoch})
				default:
					w.fail(fmt.Errorf("unexpected backend frame %s", typ))
				}
				return nil
			})
			t.Cleanup(c.Close)
			admission, err := c.AuthenticatedNativeHostSession()
			if err != nil {
				t.Fatal(err)
			}
			var origin transport.NativeObservationOrigin
			if err = json.Unmarshal(o.Origin, &origin); err != nil {
				t.Fatal(err)
			}
			w.scope = sessionworker.Scope{ServerURL: c.serverURL, TenantID: admission.TenantID, AccountID: admission.AccountID, HostID: c.hostID, InstanceID: origin.InstanceID, Generation: domain.NewID().String()}
			spec := sessionworker.NativeSpec{Runtime: domain.RuntimeName(origin.Runtime), Kind: "representative"}
			profile := sessionworker.NativeProfileFingerprint(spec)
			if mode == "historical_stopped_source" {
				o.Event.Type = session.EventSessionStopped
			}
			w.observation = o
			w.snapshot = sessionworker.NativeSnapshot{Scope: w.scope, ActualRuntime: spec.Runtime, ProfileFingerprint: profile, NativeGeneration: o.NativeGeneration, NativeSessionID: o.NativeSessionID, NativeStartIdentity: "original-start", Origin: o.Origin, PID: 1234}
			dir := t.TempDir()
			w.serve(t, dir)
			controller, err := sessionworker.DialOwnerController(t.Context(), dir, w.scope, w.key, "pump-test")
			if err != nil {
				t.Fatal(err)
			}
			proxy := &NativeWorkerProxy{connection: c, controller: controller, scope: w.scope, profile: profile, bootstrap: sessionworker.Bootstrap{Scope: w.scope, Native: spec}, done: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			d := &Daemon{turnCtx: ctx}
			done := make(chan struct{})
			go func() { defer close(done); d.pumpNativeWorker(&nativeWorkerLink{proxy: proxy}) }()
			t.Cleanup(func() {
				cancel()
				_ = proxy.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("pump did not stop")
				}
			})
			select {
			case <-first:
			case err := <-w.errors:
				t.Fatal(err)
			case <-time.After(2 * time.Second):
				t.Fatal("pump did not publish source")
			}
			if mode == "disconnect_pending" {
				c.Close()
				_ = proxy.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("disconnect retained pending pump")
				}
				if w.acked.Load() {
					t.Fatal("disconnect retired uncommitted source")
				}
				c.mu.Lock()
				pending := len(c.pendingObservations) + len(c.pendingObservationRetries)
				c.mu.Unlock()
				if pending != 0 {
					t.Fatal("disconnect retained receipt waiter")
				}
			} else {
				if mode == "live_confirmation_replays_pending" {
					select {
					case <-replayed:
					case err := <-w.errors:
						t.Fatal(err)
					case <-time.After(2 * time.Second):
						t.Fatal("live confirmation did not replay pending source promptly")
					}
				}
				select {
				case <-w.ack:
				case err := <-w.errors:
					t.Fatal(err)
				case <-time.After(2 * time.Second):
					t.Fatal("committed source was not acknowledged")
				}
				if mode == "historical_stopped_source" && (confirmations.Load() != 0 || sends.Load() != 1) {
					t.Fatal("historical stopped source required live confirmation")
				}
			}
			select {
			case err := <-w.errors:
				t.Fatal(err)
			default:
			}
		})
	}
}
