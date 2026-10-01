package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func TestInvocationFailedAdmissionWriteNeverRunsHandler(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	pid, cred := fs.createPrincipal("service", "target", net)
	c := mustConnect(t, fs, cred, t.TempDir())
	waitForCryptoReady(t, fs, pid)
	var calls atomic.Int32
	c.Service("svc").Handle("paid", func(context.Context, *Invocation) (any, error) { calls.Add(1); return nil, nil })
	encrypted, aad, err := c.encryptObject(net, "invocation_input", "inv", "caller", pid, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	env, err := transport.NewEnvelope(transport.MsgEndpointInvocationDispatch, transport.EndpointInvocationDispatchPayload{InvocationID: "inv", DispatchID: "dispatch", NetworkID: net, CapabilityID: "paid", CapabilityVersion: 1, Envelope: &encrypted, AAD: &aad})
	if err != nil {
		t.Fatal(err)
	}
	// Stop reconnect/heartbeat loops before removing the connection, so the
	// failed-write precondition cannot race a registration frame.
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c.connMu.Lock()
	c.cur = nil
	c.connMu.Unlock()
	c.handleInvocationDispatch(env)
	c.invMu.Lock()
	inflight := len(c.inflightInvocations)
	c.invMu.Unlock()
	if calls.Load() != 0 || inflight != 0 {
		t.Fatal("failed admission write started provider work or leaked inflight slot")
	}
}
func TestInvocationMissingDispatchIDNeverRunsHandler(t *testing.T) {
	c := &Client{inflightInvocations: map[string]*asyncInvocation{}, completedInvocations: newLRUMap(8)}
	env, _ := transport.NewEnvelope(transport.MsgEndpointInvocationDispatch, transport.EndpointInvocationDispatchPayload{InvocationID: "inv", CapabilityID: "paid"})
	c.handleInvocationDispatch(env)
	if len(c.inflightInvocations) != 0 {
		t.Fatal("missing dispatch identity accepted")
	}
}
func TestInvocationResultWaitsForExactDurableReceipt(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	callerID, callerCred := fs.createPrincipal("agent", "caller", net)
	targetID, targetCred := fs.createPrincipal("service", "target", net)
	target := mustConnect(t, fs, targetCred, t.TempDir())
	waitForCryptoReady(t, fs, targetID)
	var calls atomic.Int32
	target.Service("svc").Handle("receipt", func(context.Context, *Invocation) (any, error) { calls.Add(1); return map[string]any{"ok": true}, nil })
	caller := mustConnect(t, fs, callerCred, t.TempDir())
	waitForCryptoReady(t, fs, callerID)
	fs.mu.Lock()
	fs.dropResultReceipts = true
	fs.mu.Unlock()
	res, err := caller.Invoke(testCtx(t), Invocation{NetworkID: net, TargetPrincipalID: targetID, CapabilityID: "receipt", Input: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	target.pendingMu.Lock()
	pending, ok := target.pendingResults[res.ID]
	target.pendingMu.Unlock()
	if !ok || pending.result.DispatchID == "" {
		t.Fatal("socket write erased outcome before durable receipt")
	}
	original, _ := json.Marshal(pending.result)
	wrong, _ := transport.NewEnvelope(transport.MsgEndpointInvocationResultAck, transport.EndpointInvocationResultAckPayload{InvocationID: res.ID, DispatchID: "wrong", Recorded: true})
	target.handleInvocationResultAck(wrong)
	target.pendingMu.Lock()
	_, ok = target.pendingResults[res.ID]
	target.pendingMu.Unlock()
	if !ok {
		t.Fatal("foreign generation receipt erased result")
	}
	// Re-send only the saved output. No handler replay, no re-encryption.
	target.retryPendingResults(true)
	target.pendingMu.Lock()
	again := target.pendingResults[res.ID]
	target.pendingMu.Unlock()
	replay, _ := json.Marshal(again.result)
	if string(original) != string(replay) {
		t.Fatal("outcome retry changed ciphertext/AAD")
	}
	fs.mu.Lock()
	fs.dropResultReceipts = false
	fs.mu.Unlock()
	target.retryPendingResults(true)
	waitFor(t, 5*time.Second, "durable result receipt", func() bool {
		target.pendingMu.Lock()
		defer target.pendingMu.Unlock()
		_, pending := target.pendingResults[res.ID]
		return !pending
	})
	if calls.Load() != 1 {
		t.Fatal("result retry repeated provider handler")
	}
}

func TestInvocationAcknowledgedCacheHasByteBudget(t *testing.T) {
	cache := newLRUMap(4096)
	cache.maxBytes = 1024
	for i := 0; i < 100; i++ {
		cache.set(string(rune(i+1)), completedInvocation{encodedBytes: 256})
	}
	if cache.bytes > 1024 || len(cache.items) > 4 {
		t.Fatalf("acknowledged cache grew beyond byte budget: %d %d", cache.bytes, len(cache.items))
	}
}
func TestInvocationOversizedOutputBecomesBoundedProtectedError(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	callerID, callerCred := fs.createPrincipal("agent", "caller", net)
	targetID, targetCred := fs.createPrincipal("service", "target", net)
	target := mustConnect(t, fs, targetCred, t.TempDir())
	waitForCryptoReady(t, fs, targetID)
	target.Service("svc").Handle("oversized", func(context.Context, *Invocation) (any, error) {
		return string(make([]byte, MaxInvocationResultBytes+1)), nil
	})
	caller := mustConnect(t, fs, callerCred, t.TempDir())
	waitForCryptoReady(t, fs, callerID)
	res, err := caller.Invoke(testCtx(t), Invocation{NetworkID: net, TargetPrincipalID: targetID, CapabilityID: "oversized", Input: map[string]any{}})
	if err == nil {
		t.Fatal("oversized result returned success")
	}
	if res == nil || res.State != "failed" || res.PublicResultCode != "output_too_large" {
		t.Fatalf("oversize result not rejected explicitly: %+v", res)
	}
}

func TestInvocationFullResultReservationDefersBeforeAdmission(t *testing.T) {
	frames := make(chan transport.Envelope, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		var frame transport.Envelope
		if ws.ReadJSON(&frame) == nil {
			frames <- frame
		}
	}))
	defer server.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	c := &Client{cur: &conn{ws: ws}, inflightInvocations: map[string]*asyncInvocation{}, completedInvocations: newLRUMap(8)}
	for i := 0; i < MaxActiveInvocations; i++ {
		c.inflightInvocations[fmt.Sprint(i)] = &asyncInvocation{}
	}
	envelope := e2ee.EncryptedPayloadV1{}
	aad := e2ee.AAD{}
	frame, _ := transport.NewEnvelope(transport.MsgEndpointInvocationDispatch, transport.EndpointInvocationDispatchPayload{InvocationID: "blocked", DispatchID: "exact", Envelope: &envelope, AAD: &aad})
	c.handleInvocationDispatch(frame)
	select {
	case got := <-frames:
		var p transport.EndpointInvocationDeferPayload
		if got.Type != transport.MsgEndpointInvocationDefer || got.DecodePayload(&p) != nil || p.InvocationID != "blocked" || p.DispatchID != "exact" {
			t.Fatalf("not an explicit pre-admission decline: %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing pre-admission decline")
	}
	if len(c.inflightInvocations) != MaxActiveInvocations {
		t.Fatal("full result reservation admitted more work")
	}
}

func TestInvocationProtocolMismatchFailsBeforeSDKReady(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", false)
	_, cred := fs.createPrincipal("service", "target", net)
	fs.mu.Lock()
	fs.omitDispatchProtocol = true
	fs.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	c, err := Connect(ctx, Config{Server: fs.ts.URL, Credential: cred, StateDir: t.TempDir()})
	if c != nil {
		defer c.Close()
		t.Fatal("unsupported server made SDK ready")
	}
	if err == nil || !strings.Contains(err.Error(), "dispatch-id-v1") || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("protocol mismatch not actionable: %v", err)
	}
}
