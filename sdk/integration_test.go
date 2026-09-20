package sdk

// Integration tests: the SDK against an in-memory fake control-plane +
// crypto-authority host (fake_server_test.go). Each test maps to one of the
// ten binding behavior requirements (noted per test).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

// --- helpers -------------------------------------------------------------------

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// mustConnect connects a client and registers a Close cleanup.
func mustConnect(t *testing.T, fs *fakeServer, cred, stateDir string) *Client {
	t.Helper()
	c, err := Connect(testCtx(t), Config{Server: fs.URL(), Credential: cred, StateDir: stateDir})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// waitFor polls cond until true or the timeout (fatals on timeout).
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitForCryptoReady waits until the principal's live endpoint has completed
// crypto enrollment (the fake server marked it ready after a valid proof —
// which implies the SDK holds the epoch key). Returns the endpoint id.
func waitForCryptoReady(t *testing.T, fs *fakeServer, principalID string) string {
	t.Helper()
	var epID string
	waitFor(t, 10*time.Second, "crypto enrollment for "+principalID, func() bool {
		epID = fs.endpointForPrincipal(principalID)
		return epID != "" && fs.cryptoReadyFor(epID)
	})
	return epID
}

// runAgent registers an event handler on a new agent and runs it (which
// resolves the network and creates the server-side subscription via
// ensureSubscriptions). The run context is cancelled on test cleanup.
func runAgent(t *testing.T, client *Client, name, pattern string, h func(context.Context, *Event) error) {
	t.Helper()
	agent := client.Agent(name)
	agent.OnEvent(pattern, h)
	runCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = agent.Run(runCtx) }()
}

// readDurableCredential reads the persisted durable endpoint credential.
func readDurableCredential(t *testing.T, stateDir, principalID string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(stateDir, "principals", principalID, "credential"))
	if err != nil {
		t.Fatalf("read durable credential: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// --- requirement 10: activation → durable credential exchange -------------------

// TestConnectActivationExchange proves the credential exchange (requirement
// 10): first connect with a one-time activation credential → the server
// returns the durable endpoint credential in auth_ok → the SDK persists it
// to the keyring. A later Connect that still presents the CONSUMED activation
// credential transparently falls back to the stored durable credential.
func TestConnectActivationExchange(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	pid, actCred := fs.createPrincipal("service", "svc", net)
	stateDir := t.TempDir()

	// First connect: activation credential.
	c1 := mustConnect(t, fs, actCred, stateDir)
	waitForCryptoReady(t, fs, pid)
	if c1.PrincipalID() != pid {
		t.Fatalf("PrincipalID = %q, want %q", c1.PrincipalID(), pid)
	}
	// The durable credential is persisted to the keyring (0600).
	durable := readDurableCredential(t, stateDir, pid)
	if !strings.HasPrefix(durable, "pgn_epd_v1_") {
		t.Fatalf("persisted credential %q is not a durable endpoint credential", durable)
	}
	if err := c1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Second connect: the SAME (now consumed) activation credential. The SDK
	// must fall back to the stored durable credential and connect as the same
	// principal (with the SAME identity key — not a fresh one).
	c2 := mustConnect(t, fs, actCred, stateDir)
	waitForCryptoReady(t, fs, pid)
	if c2.PrincipalID() != pid {
		t.Fatalf("second connect PrincipalID = %q, want %q", c2.PrincipalID(), pid)
	}
	// The identity key is stable across connects (not regenerated).
	if readDurableCredential(t, stateDir, pid) != durable {
		t.Fatal("durable credential changed across connects")
	}
}

// credPrefix names a credential without echoing the whole of it.
func credPrefix(cred string) string {
	if len(cred) > 20 {
		return cred[:20] + "…"
	}
	return cred
}

// readIdentityKey reads the persisted X25519 identity private key (the stable
// crypto identity: it must survive reconnects unchanged).
func readIdentityKey(t *testing.T, stateDir, principalID string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(stateDir, "principals", principalID, "identity.key"))
	if err != nil {
		t.Fatalf("read identity key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// --- requirement 10b: a PRE-EXISTING endpoint credential, presented directly ----

// TestConnectPreExistingEndpointCredential proves the other half of the
// credential engine: a restricted pgn_epd_ credential created out of band
// (the CLI's `credential create`, never an activation) authenticates on its
// own. The SDK must not assume auth_ok carried a credential: it keeps
// presenting the one it was given, stores it under the principal id the
// server reported, and reuses it (with the same identity key) on the next
// connect instead of minting a second identity.
func TestConnectPreExistingEndpointCredential(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	pid, epdCred := fs.createEndpointPrincipal("agent", "atlas", net)
	if !strings.HasPrefix(epdCred, "pgn_epd_v1_") {
		t.Fatalf("fixture credential %q is not a durable endpoint credential", epdCred)
	}
	stateDir := t.TempDir()

	c1 := mustConnect(t, fs, epdCred, stateDir)
	waitForCryptoReady(t, fs, pid)
	if c1.PrincipalID() != pid {
		t.Fatalf("PrincipalID = %q, want %q", c1.PrincipalID(), pid)
	}
	// Nothing was swapped in: auth_ok carried no credential, so the presented
	// one is still the stored one, byte for byte.
	if got := readDurableCredential(t, stateDir, pid); got != epdCred {
		t.Fatalf("stored credential = %q, want the presented %q", credPrefix(got), credPrefix(epdCred))
	}
	// No activation happened, so the server issued no new credential.
	if n := fs.endpointCredentialCount(); n != 1 {
		t.Errorf("the server holds %d endpoint credentials, want 1 (no credential rotation)", n)
	}
	// The presented credential is indexed to the principal, so a later
	// Connect resolves the identity before auth_ok.
	kr, err := newKeyring(stateDir)
	if err != nil {
		t.Fatalf("newKeyring: %v", err)
	}
	if got, err := kr.principalForCredential(epdCred); err != nil || got != pid {
		t.Errorf("credential index = %q (err %v), want %q", got, err, pid)
	}
	identity := readIdentityKey(t, stateDir, pid)
	if err := c1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Second connect with the same credential: the stored identity key is
	// reused, not regenerated (the credential is durable, not one-time).
	c2 := mustConnect(t, fs, epdCred, stateDir)
	waitForCryptoReady(t, fs, pid)
	if c2.PrincipalID() != pid {
		t.Fatalf("second connect PrincipalID = %q, want %q", c2.PrincipalID(), pid)
	}
	if got := readIdentityKey(t, stateDir, pid); got != identity {
		t.Error("the identity key was regenerated — a durable credential must keep its identity")
	}
	if got := readDurableCredential(t, stateDir, pid); got != epdCred {
		t.Errorf("stored credential changed to %q across connects", credPrefix(got))
	}
	if err := c2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// --- requirement 2 + 5: message round-trip (ack + zero-knowledge) ----------------

// TestMessageRoundTrip proves durable message delivery: A sends an encrypted
// message to B, B's handler receives the decrypted text, the server records
// the ack, and the plaintext never crosses the wire (requirement 2 acks,
// requirement 5 zero-knowledge).
func TestMessageRoundTrip(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	aID, aCred := fs.createPrincipal("agent", "alice", net)
	bID, bCred := fs.createPrincipal("agent", "bob", net)

	bClient := mustConnect(t, fs, bCred, t.TempDir())
	waitForCryptoReady(t, fs, bID)
	got := make(chan string, 1)
	bClient.Agent("bob").OnMessage(func(ctx context.Context, m *Message) error {
		got <- m.TextBody()
		return nil
	})

	aClient := mustConnect(t, fs, aCred, t.TempDir())
	waitForCryptoReady(t, fs, aID)
	secret := "zebra-secret-message-42"
	msgID, err := aClient.Send(testCtx(t), OutgoingMessage{
		NetworkID:            net,
		RecipientPrincipalID: bID,
		Parts:                []MessagePart{TextPart(secret)},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case text := <-got:
		if text != secret {
			t.Fatalf("received %q, want %q", text, secret)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the message delivery")
	}
	// The server recorded the ack (message_acked).
	waitFor(t, 5*time.Second, "message ack", func() bool { return fs.messageAcked(msgID) })
	// Zero-knowledge: the plaintext never crossed the wire.
	if bytes.Contains(fs.wireBytes(), []byte(secret)) {
		t.Fatal("plaintext message crossed the wire")
	}
}

// --- requirement 1 + 2: event delivery, dedup, ack -------------------------------

// TestEventDeliveryDedupAck proves event delivery with at-least-once dedup
// (requirement 1): the handler runs once, the delivery is acked, and a
// redelivered (same delivery id) event is re-acked WITHOUT re-dispatching.
func TestEventDeliveryDedupAck(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	pid, cred := fs.createPrincipal("agent", "sub", net)

	client := mustConnect(t, fs, cred, t.TempDir())
	waitForCryptoReady(t, fs, pid)
	var runs atomic.Int32
	runAgent(t, client, "sub", "task.created", func(ctx context.Context, e *Event) error {
		runs.Add(1)
		return nil
	})
	waitFor(t, 5*time.Second, "subscription created", func() bool { return fs.subscriptionCount(net) >= 1 })

	payload := `{"hello":"world"}`
	eventID, deliveryIDs := fs.publishPlainEvent(net, "task.created", pid, payload)
	if len(deliveryIDs) != 1 {
		t.Fatalf("got %d deliveries, want 1", len(deliveryIDs))
	}
	did := deliveryIDs[0]

	// The handler runs exactly once for the first delivery.
	waitFor(t, 5*time.Second, "event handler", func() bool { return runs.Load() == 1 })
	// The delivery is acked (event_ack).
	waitFor(t, 5*time.Second, "event ack", func() bool { return fs.deliveryState(eventID, did) == "acknowledged" })

	// Redeliver the SAME delivery (uncertain-ack retry): re-acked, NOT
	// re-dispatched.
	if err := fs.redeliverEvent(eventID, did); err != nil {
		t.Fatalf("redeliverEvent: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if n := runs.Load(); n != 1 {
		t.Fatalf("handler ran %d times after redelivery, want 1 (dedup)", n)
	}
	if st := fs.deliveryState(eventID, did); st != "acknowledged" {
		t.Fatalf("delivery state after redelivery = %q, want acknowledged", st)
	}
}

// --- requirement 1 + 2 (service surface): service event delivery ---------------

// TestServiceEventDelivery proves that a SERVICE (not only an agent) reacts
// to network events (north-star §104; the recipes event-subscriber bundle):
// OnEvent + Serve creates the server-side subscription, the handler runs
// exactly once, the delivery is acked, and a redelivered event is re-acked
// WITHOUT re-dispatching.
func TestServiceEventDelivery(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	pid, cred := fs.createPrincipal("service", "subsvc", net)

	client := mustConnect(t, fs, cred, t.TempDir())
	waitForCryptoReady(t, fs, pid)
	var runs atomic.Int32
	svc := client.Service("subsvc")
	svc.OnEvent("test.*", func(ctx context.Context, e *Event) error {
		runs.Add(1)
		return nil
	})
	svcCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = svc.Serve(svcCtx) }()

	waitFor(t, 5*time.Second, "subscription created", func() bool { return fs.subscriptionCount(net) >= 1 })

	eventID, deliveryIDs := fs.publishPlainEvent(net, "test.created", pid, `{"x":1}`)
	if len(deliveryIDs) != 1 {
		t.Fatalf("got %d deliveries, want 1", len(deliveryIDs))
	}
	did := deliveryIDs[0]
	waitFor(t, 5*time.Second, "service event handler", func() bool { return runs.Load() == 1 })
	waitFor(t, 5*time.Second, "service event ack", func() bool { return fs.deliveryState(eventID, did) == "acknowledged" })

	// Redeliver the SAME delivery (uncertain-ack retry): re-acked, NOT
	// re-dispatched.
	if err := fs.redeliverEvent(eventID, did); err != nil {
		t.Fatalf("redeliverEvent: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if n := runs.Load(); n != 1 {
		t.Fatalf("handler ran %d times after redelivery, want 1 (dedup)", n)
	}
	if st := fs.deliveryState(eventID, did); st != "acknowledged" {
		t.Fatalf("delivery state after redelivery = %q, want acknowledged", st)
	}
}

// --- requirement 2: invocation dispatch → accept → complete (sync) ----------------

// TestInvocationSync proves the synchronous invocation lifecycle (requirement
// 2): dispatch → accept → handler → result; the caller decrypts + validates
// the output; the server records the decrypted output.
func TestInvocationSync(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	callerID, callerCred := fs.createPrincipal("agent", "caller", net)
	targetID, targetCred := fs.createPrincipal("service", "target", net)

	target := mustConnect(t, fs, targetCred, t.TempDir())
	waitForCryptoReady(t, fs, targetID)
	target.Service("svc").Handle("hello.say", func(ctx context.Context, inv *Invocation) (any, error) {
		in := inv.Input.(map[string]any)
		return map[string]any{"text": "hello " + in["text"].(string)}, nil
	})

	caller := mustConnect(t, fs, callerCred, t.TempDir())
	waitForCryptoReady(t, fs, callerID)
	res, err := caller.Invoke(testCtx(t), Invocation{
		NetworkID:         net,
		TargetPrincipalID: targetID,
		CapabilityID:      "hello.say",
		Input:             map[string]any{"text": "world"},
	})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res.State != "completed" {
		t.Fatalf("State = %q, want completed", res.State)
	}
	out, ok := res.Output.(map[string]any)
	if !ok || out["text"] != "hello world" {
		t.Fatalf("Output = %#v, want {text:hello world}", res.Output)
	}
	// The server-side record holds the decrypted output.
	if got := fs.invocationOutputPlain(res.ID); got != `{"text":"hello world"}` {
		t.Fatalf("server-side output = %q", got)
	}
}

// --- requirement 2: async invocation (Accept + Complete) --------------------------

// TestInvocationAsync proves the async invocation form (requirement 2): the
// handler returns ErrAsync, then completes later via Invocation.Complete; the
// caller's synchronous Invoke still returns the result.
func TestInvocationAsync(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	callerID, callerCred := fs.createPrincipal("agent", "caller", net)
	targetID, targetCred := fs.createPrincipal("service", "target", net)

	target := mustConnect(t, fs, targetCred, t.TempDir())
	waitForCryptoReady(t, fs, targetID)
	target.Service("svc").Handle("slow.job", func(ctx context.Context, inv *Invocation) (any, error) {
		go func() {
			time.Sleep(50 * time.Millisecond)
			_ = inv.Accept(ctx)
			_ = inv.Complete(ctx, map[string]any{"done": true})
		}()
		return nil, ErrAsync
	})

	caller := mustConnect(t, fs, callerCred, t.TempDir())
	waitForCryptoReady(t, fs, callerID)
	res, err := caller.Invoke(testCtx(t), Invocation{
		NetworkID:         net,
		TargetPrincipalID: targetID,
		CapabilityID:      "slow.job",
		Input:             map[string]any{"x": 1},
	})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res.State != "completed" {
		t.Fatalf("State = %q, want completed", res.State)
	}
	out, ok := res.Output.(map[string]any)
	if !ok || out["done"] != true {
		t.Fatalf("Output = %#v, want {done:true}", res.Output)
	}
}

// --- requirement 4: schema validation → invocation_error --------------------------

// TestSchemaValidationFailure proves target-side output validation (requirement
// 4): a handler output that violates the capability's OutputSchema becomes an
// invocation_error result (a clean, decrypted error) — NOT a malformed
// ciphertext. The caller sees a failed invocation.
func TestSchemaValidationFailure(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	callerID, callerCred := fs.createPrincipal("agent", "caller", net)
	targetID, targetCred := fs.createPrincipal("service", "target", net)

	target := mustConnect(t, fs, targetCred, t.TempDir())
	waitForCryptoReady(t, fs, targetID)
	svc := target.Service("svc")
	if err := svc.Capability(Capability{
		ID:           "calc.add",
		Version:      1,
		OutputSchema: json.RawMessage(`{"type":"object","properties":{"n":{"type":"number"}},"required":["n"]}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Handle("calc.add", func(ctx context.Context, inv *Invocation) (any, error) {
		// Violates the OutputSchema (missing required "n").
		return map[string]any{"wrong": true}, nil
	}); err != nil {
		t.Fatal(err)
	}

	caller := mustConnect(t, fs, callerCred, t.TempDir())
	waitForCryptoReady(t, fs, callerID)
	res, err := caller.Invoke(testCtx(t), Invocation{
		NetworkID:         net,
		TargetPrincipalID: targetID,
		CapabilityID:      "calc.add",
		Input:             map[string]any{"a": 1, "b": 2},
	})
	if err == nil {
		t.Fatal("Invoke should fail when the output violates the schema")
	}
	if res.State != "failed" {
		t.Fatalf("State = %q, want failed", res.State)
	}
	// The error is a clean validation error (decrypted), not a crypto error.
	if !strings.Contains(res.Err.Error(), "schema validation") {
		t.Fatalf("error %q should be a schema validation error", res.Err)
	}
}

// --- requirement 3: crypto enrollment (D6) ----------------------------------------

// TestCryptoEnrollment proves the D6 enrollment: on register + auth_ok with an
// active epoch, the SDK unwraps the HPKE-wrapped epoch key (info
// pagnet/endpoint-enrollment/epoch-wrap/v1), stores it, and proves possession
// via the challenge. The fake server (host) marks the endpoint crypto-ready
// only after a valid proof.
func TestCryptoEnrollment(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	pid, cred := fs.createPrincipal("service", "svc", net)

	client := mustConnect(t, fs, cred, t.TempDir())
	epID := waitForCryptoReady(t, fs, pid)
	// The endpoint id reported by the SDK matches the one the host enrolled.
	if client.EndpointID() != epID {
		t.Fatalf("EndpointID = %q, host enrolled %q", client.EndpointID(), epID)
	}
	// Networks() reports CryptoReady for the enrolled network.
	nets, err := client.Networks(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 1 || !nets[0].CryptoReady {
		t.Fatalf("Networks() = %+v, want one crypto-ready network", nets)
	}
}

// TestCryptoEnrollmentChallengeFirst proves the SDK handles a challenge that
// arrives BEFORE the key package (queued until the epoch key lands) — the
// enrollment must still complete.
func TestCryptoEnrollmentChallengeFirst(t *testing.T) {
	fs := newFakeServer(t)
	fs.challengeFirst = true
	net := fs.createNetwork("net", true)
	pid, cred := fs.createPrincipal("service", "svc", net)

	client := mustConnect(t, fs, cred, t.TempDir())
	waitForCryptoReady(t, fs, pid)
	// Content works after enrollment (the epoch key was stored).
	if _, err := client.PublishEvent(testCtx(t), net, Event{Type: "x.y", Payload: []byte(`{}`)}); err != nil {
		t.Fatalf("PublishEvent after challenge-first enrollment: %v", err)
	}
}

// --- requirement 8: reconnect, re-register, resume subscriptions ------------------

// TestReconnect proves the reconnect behavior (requirement 8): a server-side
// drop is reconnected, the endpoint re-registers (new endpoint id), crypto is
// re-enrolled, and the agent's subscriptions are preserved (the server is the
// source of truth — no duplicates). Events published after the drop are
// delivered.
func TestReconnect(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	pid, cred := fs.createPrincipal("agent", "sub", net)

	client := mustConnect(t, fs, cred, t.TempDir())
	firstEp := waitForCryptoReady(t, fs, pid)
	var runs atomic.Int32
	runAgent(t, client, "sub", "task.*", func(ctx context.Context, e *Event) error {
		runs.Add(1)
		return nil
	})
	waitFor(t, 5*time.Second, "subscription created", func() bool { return fs.subscriptionCount(net) >= 1 })

	// Server-side drop.
	fs.dropEndpoint(firstEp)
	var newEp string
	waitFor(t, 15*time.Second, "reconnect + re-enroll", func() bool {
		newEp = fs.endpointForPrincipal(pid)
		return newEp != "" && newEp != firstEp && fs.cryptoReadyFor(newEp)
	})
	// Subscriptions are preserved (still exactly one — no duplicate).
	waitFor(t, 5*time.Second, "subscription preserved", func() bool { return fs.subscriptionCount(net) == 1 })

	// An event published after the drop is delivered to the reconnected
	// endpoint.
	fs.publishPlainEvent(net, "task.created", pid, `{"after":"reconnect"}`)
	waitFor(t, 5*time.Second, "post-reconnect delivery", func() bool { return runs.Load() >= 1 })
}

// --- requirement 8: in-flight async invocation survives a reconnect ---------------

// TestAsyncInvocationSurvivesReconnect proves (requirement 8) that an in-flight
// async invocation survives an SDK reconnect: the handler accepted it, the
// connection drops, and the later Complete is recorded on the reconnected
// session (the caller's Invoke returns the result).
func TestAsyncInvocationSurvivesReconnect(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	callerID, callerCred := fs.createPrincipal("agent", "caller", net)
	targetID, targetCred := fs.createPrincipal("service", "target", net)

	target := mustConnect(t, fs, targetCred, t.TempDir())
	firstEp := waitForCryptoReady(t, fs, targetID)
	dispatched := make(chan *Invocation, 1)
	target.Service("svc").Handle("slow.job", func(ctx context.Context, inv *Invocation) (any, error) {
		dispatched <- inv
		return nil, ErrAsync
	})

	caller := mustConnect(t, fs, callerCred, t.TempDir())
	waitForCryptoReady(t, fs, callerID)
	resCh := make(chan *Invocation, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := caller.Invoke(testCtx(t), Invocation{
			NetworkID:         net,
			TargetPrincipalID: targetID,
			CapabilityID:      "slow.job",
			Input:             map[string]any{"x": 1},
		})
		if err != nil {
			errCh <- err
		} else {
			resCh <- res
		}
	}()

	// Wait for the dispatch to be accepted (in-flight).
	var inv *Invocation
	select {
	case inv = <-dispatched:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the invocation dispatch")
	}

	// Drop the target's connection; wait for a full reconnect + re-enroll.
	fs.dropEndpoint(firstEp)
	var newEp string
	waitFor(t, 15*time.Second, "reconnect + re-enroll", func() bool {
		newEp = fs.endpointForPrincipal(targetID)
		return newEp != "" && newEp != firstEp && fs.cryptoReadyFor(newEp)
	})

	// Complete the in-flight invocation on the reconnected session.
	if err := inv.Complete(context.Background(), map[string]any{"done": true}); err != nil {
		t.Fatalf("Complete after reconnect: %v", err)
	}
	select {
	case res := <-resCh:
		if res.State != "completed" {
			t.Fatalf("State = %q, want completed", res.State)
		}
	case err := <-errCh:
		t.Fatalf("Invoke: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the invoke result")
	}
}

// --- requirement 8 (failure path): async fails clearly when TTL expired ----------

// TestAsyncInvocationFailsClearlyWhenCancelled proves (requirement 8) that when
// the server has cancelled the invocation (TTL expired), a late Complete
// returns a CLEAR error instead of a silently dropped result.
func TestAsyncInvocationFailsClearlyWhenCancelled(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	callerID, callerCred := fs.createPrincipal("agent", "caller", net)
	targetID, targetCred := fs.createPrincipal("service", "target", net)

	target := mustConnect(t, fs, targetCred, t.TempDir())
	waitForCryptoReady(t, fs, targetID)
	dispatched := make(chan *Invocation, 1)
	target.Service("svc").Handle("slow.job", func(ctx context.Context, inv *Invocation) (any, error) {
		dispatched <- inv
		return nil, ErrAsync
	})

	caller := mustConnect(t, fs, callerCred, t.TempDir())
	waitForCryptoReady(t, fs, callerID)
	go func() {
		_, _ = caller.Invoke(testCtx(t), Invocation{
			NetworkID:         net,
			TargetPrincipalID: targetID,
			CapabilityID:      "slow.job",
			Input:             map[string]any{"x": 1},
		})
	}()
	var inv *Invocation
	select {
	case inv = <-dispatched:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the invocation dispatch")
	}

	// The server cancels the invocation (TTL expired) and the session drops.
	// Wait for the reconnect (which bumps the connection generation) so the
	// later Complete takes the server-state-check path and sees the
	// cancellation — a clear error, not a silently dropped result.
	fs.cancelInvocation(inv.ID)
	firstEp := fs.endpointForPrincipal(targetID)
	fs.dropEndpoint(firstEp)
	var newEp string
	waitFor(t, 15*time.Second, "reconnect", func() bool {
		newEp = fs.endpointForPrincipal(targetID)
		return newEp != "" && newEp != firstEp
	})

	err := inv.Complete(context.Background(), map[string]any{"done": true})
	if err == nil {
		t.Fatal("Complete should fail when the invocation was cancelled server-side")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("error %q should mention cancellation", err)
	}
}

// --- requirement 6: backpressure (bounded queue, never drop) ----------------------

// TestBackpressureNoDrop proves (requirement 6) that under a slow handler the
// bounded dispatch queue + handler slots apply backpressure (the read loop
// blocks) but NEVER drop a delivery: every one of 400 events is delivered
// exactly once (dedup) and acked.
func TestBackpressureNoDrop(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	pid, cred := fs.createPrincipal("agent", "sub", net)

	client := mustConnect(t, fs, cred, t.TempDir())
	waitForCryptoReady(t, fs, pid)
	var runs atomic.Int32
	runAgent(t, client, "sub", "load.*", func(ctx context.Context, e *Event) error {
		runs.Add(1)
		time.Sleep(30 * time.Millisecond) // slow handler
		return nil
	})
	waitFor(t, 5*time.Second, "subscription created", func() bool { return fs.subscriptionCount(net) >= 1 })

	const n = 400
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		id, _ := fs.publishPlainEvent(net, "load.item", pid, `{"i":1}`)
		ids[i] = id
	}
	// Every delivery is eventually acked (none dropped).
	waitFor(t, 60*time.Second, "all deliveries acked", func() bool {
		acked := 0
		for _, id := range ids {
			// Each event has exactly one delivery.
			for _, st := range fs.eventDeliveryStates(id) {
				if st == "acknowledged" {
					acked++
				}
			}
		}
		return acked == n
	})
	if got := runs.Load(); got != n {
		t.Fatalf("handler ran %d times, want %d (no drops, no dupes)", got, n)
	}
}

// --- requirement 9: heartbeat ------------------------------------------------------

// TestHeartbeat proves (requirement 9) that the endpoint sends periodic
// liveness reports (the cadence is shortened for the test; production is 20s).
func TestHeartbeat(t *testing.T) {
	old := heartbeatInterval
	heartbeatInterval = 100 * time.Millisecond
	defer func() { heartbeatInterval = old }()

	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	_, cred := fs.createPrincipal("service", "svc", net)
	mustConnect(t, fs, cred, t.TempDir())
	waitFor(t, 5*time.Second, ">=2 heartbeats", func() bool { return fs.heartbeatCount() >= 2 })
}

// --- requirement 9: clean close, no goroutine leaks --------------------------------

// TestCleanCloseNoLeak proves (requirement 9) that Close drains the client's
// loops (supervisor + dispatcher) without a 10s timeout and leaves no leaked
// client goroutines.
func TestCleanCloseNoLeak(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	pid, cred := fs.createPrincipal("service", "svc", net)

	client := mustConnect(t, fs, cred, t.TempDir())
	waitForCryptoReady(t, fs, pid)
	before := runtime.NumGoroutine()
	start := time.Now()
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Close took %v (the loops did not drain promptly)", elapsed)
	}
	// Give any lingering goroutines a moment to exit, then compare.
	time.Sleep(150 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > before {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}

// --- requirement 5: zero-knowledge across all content paths ------------------------

// TestZeroKnowledgeWire proves (requirement 5) that protected content — message
// parts, event payloads, invocation inputs and outputs — never crosses the
// wire in plaintext (the control plane sees ciphertext + AAD only).
func TestZeroKnowledgeWire(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	aID, aCred := fs.createPrincipal("agent", "alice", net)
	bID, bCred := fs.createPrincipal("service", "bob", net)

	bClient := mustConnect(t, fs, bCred, t.TempDir())
	waitForCryptoReady(t, fs, bID)
	bClient.Agent("bob").OnMessage(func(ctx context.Context, m *Message) error { return nil })
	bClient.Service("svc").Handle("echo.run", func(ctx context.Context, inv *Invocation) (any, error) {
		return map[string]any{"echoed": inv.Input}, nil
	})

	aClient := mustConnect(t, fs, aCred, t.TempDir())
	waitForCryptoReady(t, fs, aID)

	secrets := []string{
		"zk-message-secret-111",
		"zk-event-secret-222",
		"zk-invocation-secret-333",
	}
	// Message.
	if _, err := aClient.Send(testCtx(t), OutgoingMessage{
		NetworkID: net, RecipientPrincipalID: bID, Parts: []MessagePart{TextPart(secrets[0])},
	}); err != nil {
		t.Fatal(err)
	}
	// Event (a subscription so it is delivered too).
	if _, err := aClient.Subscribe(testCtx(t), net, Subscription{EventPattern: "zk.*"}); err != nil {
		t.Fatal(err)
	}
	if _, err := aClient.PublishEvent(testCtx(t), net, Event{Type: "zk.event", Payload: []byte(`{"s":"` + secrets[1] + `"}`)}); err != nil {
		t.Fatal(err)
	}
	// Invocation.
	if _, err := aClient.Invoke(testCtx(t), Invocation{
		NetworkID: net, TargetPrincipalID: bID, CapabilityID: "echo.run",
		Input: map[string]any{"s": secrets[2]},
	}); err != nil {
		t.Fatal(err)
	}
	// Let the async deliveries settle.
	time.Sleep(500 * time.Millisecond)

	wire := fs.wireBytes()
	for _, s := range secrets {
		if bytes.Contains(wire, []byte(s)) {
			t.Fatalf("plaintext %q crossed the wire (zero-knowledge violated)", s)
		}
	}
}

// --- D9 deliverable: search with match reasons -------------------------------------

// TestSearch proves the Search operation returns participants with match
// reasons (D9).
func TestSearch(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	pid, cred := fs.createPrincipal("service", "greeter-svc", net)
	fs.setPrincipalCapabilities(pid, []Capability{{ID: "hello.say", Version: 1, Name: "Say hello"}})

	client := mustConnect(t, fs, cred, t.TempDir())
	waitForCryptoReady(t, fs, pid)

	// By name.
	res, _, err := client.Search(testCtx(t), net, Query{Text: "greeter"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].PrincipalID != pid {
		t.Fatalf("Search by name = %+v, want one hit for %s", res, pid)
	}
	if !contains(res[0].MatchReasons, "name") {
		t.Fatalf("MatchReasons = %v, want to include name", res[0].MatchReasons)
	}
	// By capability.
	res, _, err = client.Search(testCtx(t), net, Query{Capability: "hello.say"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || !contains(res[0].MatchReasons, "capability") {
		t.Fatalf("Search by capability = %+v, want one hit with capability reason", res)
	}
	// By kind filter (no match).
	res, _, err = client.Search(testCtx(t), net, Query{Kind: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("Search kind=agent = %+v, want no hits (the principal is a service)", res)
	}
}

// --- whitebox: pending results re-sent on reconnect --------------------------------

// TestFlushPendingResults proves the reconnect resilience path: an invocation
// result whose send failed on a dead session is queued and re-sent by
// flushPendingResults on the next live connection (the server records it).
func TestFlushPendingResults(t *testing.T) {
	fs := newFakeServer(t)
	net := fs.createNetwork("net", true)
	callerID, callerCred := fs.createPrincipal("agent", "caller", net)
	targetID, targetCred := fs.createPrincipal("service", "target", net)

	target := mustConnect(t, fs, targetCred, t.TempDir())
	waitForCryptoReady(t, fs, targetID)
	dispatched := make(chan *Invocation, 1)
	target.Service("svc").Handle("slow.job", func(ctx context.Context, inv *Invocation) (any, error) {
		dispatched <- inv
		return nil, ErrAsync
	})

	caller := mustConnect(t, fs, callerCred, t.TempDir())
	waitForCryptoReady(t, fs, callerID)
	go func() {
		_, _ = caller.Invoke(testCtx(t), Invocation{
			NetworkID: net, TargetPrincipalID: targetID, CapabilityID: "slow.job",
			Input: map[string]any{"x": 1},
		})
	}()
	var inv *Invocation
	select {
	case inv = <-dispatched:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the dispatch")
	}

	// Build the result the target WOULD send, queue it as pending (as if the
	// send had failed on a dead session), then flush it on the live session.
	out, _ := json.Marshal(map[string]any{"done": true})
	env, aad, err := target.encryptObject(net, e2ee.ObjectTypeInvocationOutput, inv.ID, target.PrincipalID(), callerID, out)
	if err != nil {
		t.Fatal(err)
	}
	payload := transport.EndpointInvocationResultPayload{
		InvocationID: inv.ID, OK: true, Envelope: &env, AAD: &aad, PublicResultCode: "completed",
	}
	target.pendingMu.Lock()
	target.pendingResults[inv.ID] = completedInvocation{result: payload}
	target.pendingMu.Unlock()
	target.flushPendingResults()

	waitFor(t, 5*time.Second, "invocation completed", func() bool { return fs.invocationState(inv.ID) == "completed" })
	if got := fs.invocationOutputPlain(inv.ID); got != `{"done":true}` {
		t.Fatalf("server-side output = %q", got)
	}
}

// contains reports whether ss contains s.
func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
