package daemon

// V2 cutover (W5) daemon-level tests:
//
//   - host.endpoint_status on instance transitions (online/offline)
//   - V2 event delivery: the deterministic TRIGGER TURN (plan §46) — the turn
//     input carries the event type + ids + network + the network_event_get
//     fetch instruction, NEVER the raw payload; one wake per event (redelivery
//     with the same delivery id is a no-op)
//   - host.crypto_share_endpoint: the daemon wraps the current epoch key for
//     an SDK endpoint; the SDK-side unwrap (e2ee.HPKEUnwrap with EnrollmentInfo)
//     recovers the exact 32-byte epoch key (D6 endpoint crypto enrollment)
//   - the protocol v2 gate: a newer protocol version / explicit
//     protocol.upgrade_required stops the connection with ErrOutdated
//   - always-encrypted (D6): a provisioning network refuses content
//     (tool args + legacy deliveries) — no plaintext fallback

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
)

// setFakeBinary points the daemon's fake adapter at a freshly built
// pagnet-fake-runtime (launch validates runtime availability).
func setFakeBinary(t *testing.T, d *Daemon) {
	t.Helper()
	f, ok := d.adapters[domain.RuntimeFake].(*agentruntime.Fake)
	if !ok {
		t.Fatal("fake adapter not registered (debug mode)")
	}
	f.Binary = p0FakeBinary(t)
}

// --- host.endpoint_status ----------------------------------------------------

// endpointStatusFor finds the endpoint-status report for instanceID in an
// envelope stream.
func endpointStatusFor(t *testing.T, envs []transport.Envelope, instanceID string) map[string]any {
	t.Helper()
	for _, env := range envs {
		if env.Type != transport.MsgEndpointStatus {
			continue
		}
		p := envelopePayload(t, env)
		if p["instanceId"] == instanceID {
			return p
		}
	}
	t.Fatalf("no %s for %s in %d envelopes", transport.MsgEndpointStatus, instanceID, len(envs))
	return nil
}

// readEndpointStatuses reads envelopes from the server side until n
// endpoint-status reports have been collected (other types are skipped).
func readEndpointStatuses(t *testing.T, server *websocket.Conn, n int) []map[string]any {
	t.Helper()
	var out []map[string]any
	deadline := time.Now().Add(30 * time.Second)
	for len(out) < n && time.Now().Before(deadline) {
		_ = server.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, raw, err := server.ReadMessage()
		if err != nil {
			t.Fatalf("read envelope: %v (have %d/%d)", err, len(out), n)
		}
		var env transport.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		if env.Type == transport.MsgEndpointStatus {
			out = append(out, envelopePayload(t, env))
		}
	}
	if len(out) < n {
		t.Fatalf("saw %d endpoint-status reports, want %d", len(out), n)
	}
	return out
}

// The daemon reports endpoint liveness (host.endpoint_status) carrying the
// AGENT PRINCIPAL on every instance transition: online when the instance is
// idle/working/starting, offline when it is hibernated/stopped/blocked/failed.
func TestDaemon_EndpointStatusOnTransitions(t *testing.T) {
	d := newTestDaemon(t)
	setFakeBinary(t, d)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	envs := driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-es-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFake), Kind: "representative",
		AgentName: "es-agent", AgentPrincipalID: "principal-1", NetworkID: "net-1",
	})
	// Launch → the instance is idle → ONLINE, with the principal + instance.
	st := endpointStatusFor(t, envs, instanceID)
	if online, _ := st["online"].(bool); !online {
		t.Fatalf("launch endpoint status online = %v, want true: %v", st["online"], st)
	}
	if st["agentPrincipalId"] != "principal-1" {
		t.Fatalf("endpoint status agentPrincipalId = %v, want principal-1", st["agentPrincipalId"])
	}

	// Hibernate → OFFLINE (session preserved, endpoint stopped).
	if err := d.hibernateInstance(nil, instanceID, "test-cycle"); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	st = readEndpointStatuses(t, server, 1)[0]
	if online, _ := st["online"].(bool); online {
		t.Fatalf("hibernated instance reported online: %v", st)
	}

	// Restart → back ONLINE (idle, fresh start).
	envs = driveCommand(t, d, server, transport.MsgRestartAgent,
		transport.RestartAgentPayload{CommandID: "cmd-es-restart", InstanceID: instanceID}, "cmd-es-restart")
	st = endpointStatusFor(t, envs, instanceID)
	if online, _ := st["online"].(bool); !online {
		t.Fatalf("restarted instance not online: %v", st)
	}

	// Stop → OFFLINE.
	envs = driveCommand(t, d, server, transport.MsgStopAgent,
		transport.StopAgentPayload{CommandID: "cmd-es-stop", InstanceID: instanceID}, "cmd-es-stop")
	st = endpointStatusFor(t, envs, instanceID)
	if online, _ := st["online"].(bool); online {
		t.Fatalf("stopped instance reported online: %v", st)
	}

	// Reconnect re-sync: a second instance + reportAllEndpointStatuses
	// reports every tracked instance (the at-most-once reports are lost
	// across a daemon restart; this is the convergence path).
	instanceID2 := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-es-launch-2", InstanceID: instanceID2,
		Runtime: string(domain.RuntimeFake), Kind: "representative",
		AgentName: "es-agent-2", AgentPrincipalID: "principal-2", NetworkID: "net-1",
	})
	d.reportAllEndpointStatuses(client)
	sts := readEndpointStatuses(t, server, 2)
	seen := map[string]bool{}
	for _, p := range sts {
		if id, _ := p["instanceId"].(string); id != "" {
			seen[id] = true
		}
	}
	if !seen[instanceID] || !seen[instanceID2] {
		t.Fatalf("reportAllEndpointStatuses missed an instance: %v", seen)
	}
}

// --- V2 event trigger turn (plan §46) ----------------------------------------

// The trigger-turn input is a pure, deterministic function of the delivery:
// it carries the event type + trusted routing metadata (event/delivery ids,
// network) + the network_event_get fetch instruction + the untrusted-data
// warning — and NEVER the raw payload (it is DATA to fetch, never inlined).
func TestDaemon_EventTriggerInputDeterministic(t *testing.T) {
	d := newTestDaemon(t)
	row := &InstanceRow{InstanceID: "i1", NetworkID: "net-1"}
	payloadMarker := "RAW-PAYLOAD-MUST-NEVER-BE-INLINED"
	p := transport.NetworkEventPayload{
		EventID: "evt-1", DeliveryID: "del-1", EventType: "build.completed",
		NetworkID: "net-1", Body: payloadMarker, // even if set, it must not leak
	}
	in1 := d.eventTriggerInput(row, p)
	in2 := d.eventTriggerInput(row, p)
	if in1 != in2 {
		t.Fatalf("trigger input is not deterministic:\n--- 1 ---\n%s\n--- 2 ---\n%s", in1, in2)
	}
	for _, want := range []string{
		"Event type: build.completed",
		"Event ID: evt-1",
		"Delivery ID: del-1",
		"Network: net-1",
		`network_event_get(eventId="evt-1")`,
		"UNTRUSTED DATA",
	} {
		if !strings.Contains(in1, want) {
			t.Errorf("trigger input missing %q:\n%s", want, in1)
		}
	}
	if strings.Contains(in1, payloadMarker) {
		t.Fatalf("trigger input inlines the raw payload (prompt-injection path):\n%s", in1)
	}
	// Without a delivery id the line is omitted (shape stays deterministic).
	p.DeliveryID = ""
	if got := d.eventTriggerInput(row, p); strings.Contains(got, "Delivery ID:") {
		t.Fatalf("trigger input carries a Delivery ID line without a delivery id:\n%s", got)
	}
	// The row's network wins over the payload's (the instance is scoped).
	row.NetworkID = "net-row"
	if got := d.eventTriggerInput(row, p); !strings.Contains(got, "Network: net-row") {
		t.Fatalf("trigger input did not use the instance's network:\n%s", got)
	}
}

// deliverUntilTurnCompleted reads envelopes until the instance's
// runtime.turn.completed arrives (the queued trigger turn ran to the end).
func deliverUntilTurnCompleted(t *testing.T, server *websocket.Conn, instanceID string) []transport.Envelope {
	t.Helper()
	var envs []transport.Envelope
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_ = server.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, raw, err := server.ReadMessage()
		if err != nil {
			t.Fatalf("read envelope: %v", err)
		}
		var env transport.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		envs = append(envs, env)
		if env.Type == transport.MsgRuntimeTurnCompleted {
			if p := envelopePayload(t, env); p["instanceId"] == instanceID {
				return envs
			}
		}
	}
	t.Fatalf("did not see turn.completed for %s", instanceID)
	return nil
}

// waitInstanceStatus polls the instance row until it reaches want (or fails
// the test) — status transitions land right after the turn event stream.
func waitInstanceStatus(t *testing.T, d *Daemon, instanceID, want string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		row, ok, err := d.state.GetInstance(instanceID)
		if err != nil || !ok {
			t.Fatalf("instance missing: ok=%v err=%v", ok, err)
		}
		if row.Status == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	row, _, _ := d.state.GetInstance(instanceID)
	t.Fatalf("instance status = %q, want %q", row.Status, want)
}

// countTurnCompleted counts turn.completed envelopes for the instance.
func countTurnCompleted(envs []transport.Envelope, instanceID string) int {
	n := 0
	for _, env := range envs {
		if env.Type != transport.MsgRuntimeTurnCompleted {
			continue
		}
		var p map[string]any
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			continue
		}
		if p["instanceId"] == instanceID {
			n++
		}
	}
	return n
}

// End-to-end event delivery (real command flow, real fake runtime): the v2
// delivery fires exactly ONE trigger turn whose input is the deterministic
// trigger text (NOT the payload), and a redelivery carrying the same
// delivery id is a clean no-op (one wake per event).
func TestDaemon_EventDeliveryOneTurnPerEvent(t *testing.T) {
	d := newTestDaemon(t)
	setFakeBinary(t, d)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	repo := t.TempDir()
	gitInitRepo(t, repo)
	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-ev-launch", InstanceID: instanceID,
		Runtime:       string(domain.RuntimeFake),
		WorkspacePath: repo, AgentName: "ev-agent",
		AgentPrincipalID: "principal-ev",
	})

	// Deliver the v2 event (metadata only — the payload is fetched by the
	// agent via network_event_get, it never crosses here).
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-ev-1", InstanceID: instanceID,
		Kind: "event", EventID: "evt-1", DeliveryID: "del-1",
		EventType: "build.completed", NetworkID: "net-ev",
	})

	// The queued trigger turn runs to completion on the instance's FIFO.
	turnEnv := deliverUntilTurnCompleted(t, server, instanceID)

	// The turn's output is the fake runtime's deterministic echo of the
	// trigger input's first line — proof the trigger text (not a payload)
	// reached the agent.
	sawTriggerOutput := false
	for _, env := range turnEnv {
		if env.Type != transport.MsgRuntimeOutput {
			continue
		}
		p := envelopePayload(t, env)
		if out, _ := p["output"].(string); out != "" && strings.Contains(out, "You received a network event") {
			sawTriggerOutput = true
		}
	}
	if !sawTriggerOutput {
		t.Fatalf("the trigger turn did not run the trigger input:\n%+v", turnEnv)
	}
	// A process-per-turn worker HIBERNATES after its turn (endpoint stopped,
	// session preserved) — the instance accepts work again via a wake. The
	// hibernate lands right after turn.completed, so poll for it.
	waitInstanceStatus(t, d, instanceID, "hibernated")

	// REDIVELIVERY with the same delivery id: a clean ack, and NO second
	// turn (one wake per event).
	env, err := transport.NewEnvelope(transport.MsgDeliverNetworkEvent, transport.NetworkEventPayload{
		CommandID: "cmd-ev-1-redeliver", InstanceID: instanceID,
		Kind: "event", EventID: "evt-1", DeliveryID: "del-1",
		EventType: "build.completed", NetworkID: "net-ev",
	})
	if err != nil {
		t.Fatalf("build redelivery envelope: %v", err)
	}
	d.handleCommand(nil, env)
	_, ack := readUntilAck(t, server, "cmd-ev-1-redeliver")
	if errMsg, _ := ack["error"].(string); errMsg != "" {
		t.Fatalf("redelivery ack error: %s", errMsg)
	}
	// Give a spurious second turn a chance to appear (the fake turn is far
	// faster than the wait window).
	time.Sleep(1500 * time.Millisecond)
	var late []transport.Envelope
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, raw, err := server.ReadMessage()
		if err != nil {
			break
		}
		var e transport.Envelope
		if json.Unmarshal(raw, &e) == nil {
			late = append(late, e)
		}
	}
	total := countTurnCompleted(append(turnEnv, late...), instanceID)
	if total != 1 {
		t.Fatalf("event fired %d turns, want exactly 1 (one wake per event)", total)
	}
	t.Logf("event delivery: 1 trigger turn, redelivery no-op")
}

// --- host.crypto_share_endpoint (D6 endpoint enrollment) -----------------------

// TestDaemon_CryptoShareEndpoint wraps the network's current epoch key for an
// SDK endpoint (daemon side) and proves the SDK-side unwrap is the EXACT
// inverse: HPKEUnwrap(priv, enc, EnrollmentInfo, nil, ct) recovers the 32-byte
// epoch key byte-for-byte.
func TestDaemon_CryptoShareEndpoint(t *testing.T) {
	tenantID := "tenant-1"
	networkID := string(domain.NewID())

	d := newCryptoDaemon(t)
	act, err := d.doCryptoActivate(transport.CryptoActivatePayload{
		TenantID: tenantID, NetworkID: networkID,
	})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	epochID := act.(*transport.CryptoActivateResult).EpochID

	// The enrolling SDK endpoint's X25519 identity.
	pkR, skR, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("endpoint keypair: %v", err)
	}
	pub, _ := pkR.MarshalBinary()
	priv, _ := skR.MarshalBinary()

	res, err := d.doCryptoShareEndpoint(transport.CryptoShareEndpointPayload{
		TenantID: tenantID, NetworkID: networkID,
		EndpointPublicKey: base64.StdEncoding.EncodeToString(pub),
		EpochID:           epochID,
	})
	if err != nil {
		t.Fatalf("doCryptoShareEndpoint: %v", err)
	}
	wrap := res.(*transport.CryptoShareEndpointResult)
	if wrap.EpochID != epochID {
		t.Fatalf("result epoch = %q, want %q", wrap.EpochID, epochID)
	}
	if len(wrap.WrappedKey.Enc) == 0 || len(wrap.WrappedKey.Ciphertext) == 0 {
		t.Fatalf("empty wrap: %+v", wrap.WrappedKey)
	}

	// The SDK side unwraps with its private key + the binding info context.
	kr, err := crypto.LoadKeyring(d.StateDir, networkID)
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}
	epoch, ok := kr.EpochByID(epochID)
	if !ok {
		t.Fatalf("epoch %s missing from keyring", epochID)
	}
	key, err := epoch.KeyArray()
	if err != nil {
		t.Fatalf("epoch key: %v", err)
	}
	recovered, err := e2ee.HPKEUnwrap(priv, wrap.WrappedKey.Enc, []byte(e2ee.EnrollmentInfo), nil, wrap.WrappedKey.Ciphertext)
	if err != nil {
		t.Fatalf("SDK-side unwrap: %v", err)
	}
	if len(recovered) != 32 {
		t.Fatalf("recovered key is %d bytes, want 32", len(recovered))
	}
	if !bytes.Equal(recovered, key[:]) {
		t.Fatal("recovered key != epoch key (wrap/unwrap not inverses)")
	}

	// A different private key cannot open the wrap.
	_, otherPriv, _ := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	otherPrivBytes, _ := otherPriv.MarshalBinary()
	if _, err := e2ee.HPKEUnwrap(otherPrivBytes, wrap.WrappedKey.Enc, []byte(e2ee.EnrollmentInfo), nil, wrap.WrappedKey.Ciphertext); err == nil {
		t.Fatal("a foreign key unwrapped the epoch key; want auth failure")
	}

	// An epoch this host does not hold fails clean.
	if _, err := d.doCryptoShareEndpoint(transport.CryptoShareEndpointPayload{
		TenantID: tenantID, NetworkID: networkID,
		EndpointPublicKey: base64.StdEncoding.EncodeToString(pub),
		EpochID:           "epoch-does-not-exist",
	}); err == nil || !strings.Contains(err.Error(), "not in local keyring") {
		t.Fatalf("unknown epoch: err = %v, want a clean 'not in local keyring' refusal", err)
	}

	// A non-authority host (no keyring for the network) fails clean too.
	other := newCryptoDaemon(t)
	if _, err := other.doCryptoShareEndpoint(transport.CryptoShareEndpointPayload{
		TenantID: tenantID, NetworkID: networkID,
		EndpointPublicKey: base64.StdEncoding.EncodeToString(pub),
		EpochID:           epochID,
	}); err == nil {
		t.Fatal("non-authority host shared the epoch key; want a refusal")
	}
}

// --- protocol v2 gate ---------------------------------------------------------

// A control plane speaking a NEWER protocol (or sending the explicit
// protocol.upgrade_required notice) must stop the connection with ErrOutdated
// (the daemon surfaces "Pagnet client is outdated. Please update." and does
// NOT reconnect-loop).
func TestDaemon_UpgradeRequiredStopsConnection(t *testing.T) {
	run := func(t *testing.T, send func(conn *websocket.Conn)) {
		t.Helper()
		upg := websocket.Upgrader{}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upg.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			send(conn)
			// Consume the client's frames (inventory etc.) until close.
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}))
		t.Cleanup(ts.Close)

		d := newTestDaemon(t)
		d.ServerURL = ts.URL
		d.Credential = "test-cred"
		d.Heartbeat = time.Hour // never fires during the test

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := d.connectAndRun(ctx)
		if !errors.Is(err, ErrOutdated) {
			t.Fatalf("connectAndRun = %v, want ErrOutdated", err)
		}
		if !d.outdated {
			t.Fatal("d.outdated was not set (Run would reconnect-loop instead of stopping)")
		}
	}

	t.Run("explicit upgrade_required", func(t *testing.T) {
		run(t, func(conn *websocket.Conn) {
			env, err := transport.NewEnvelope(transport.MsgUpgradeRequired, transport.UpgradeRequiredPayload{
				Required: transport.ProtocolVersion + 1, Message: transport.UpgradeRequiredMessage,
			})
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(env)
			_ = conn.WriteMessage(websocket.TextMessage, b)
		})
	})

	t.Run("newer envelope protocol version", func(t *testing.T) {
		run(t, func(conn *websocket.Conn) {
			env, err := transport.NewEnvelope(transport.MsgHeartbeat, map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			env.ProtocolVersion = transport.ProtocolVersion + 1
			b, _ := json.Marshal(env)
			_ = conn.WriteMessage(websocket.TextMessage, b)
		})
	})
}

// --- always-encrypted (D6) -----------------------------------------------------

// A provisioning network (crypto not active yet) refuses CONTENT operations
// with the clear not-ready state — there is no plaintext fallback.
// Metadata-only tools are unaffected.
func TestDaemon_ProvisioningNetworkRefusesContent(t *testing.T) {
	d := newTestDaemon(t)

	// contentCryptoReady: unannounced + announced-but-not-active states.
	if _, err := d.contentCryptoReady("net-unannounced"); !errors.Is(err, ErrNetworkCryptoNotReady) ||
		!strings.Contains(err.Error(), "not yet announced") {
		t.Fatalf("unannounced network: err = %v, want ErrNetworkCryptoNotReady (not yet announced)", err)
	}
	d.cryptoManager().SetNetworkCrypto("net-activating", NetworkCryptoState{
		NetworkID: "net-activating", TenantID: "tenant-t", Status: "activating",
	})
	if _, err := d.contentCryptoReady("net-activating"); !errors.Is(err, ErrNetworkCryptoNotReady) ||
		!strings.Contains(err.Error(), `status "activating"`) {
		t.Fatalf("activating network: err = %v, want ErrNetworkCryptoNotReady (status activating)", err)
	}

	// A content tool on a provisioning network is refused (clear error, no
	// plaintext rewrite).
	row := &InstanceRow{InstanceID: "i1", NetworkID: "net-unannounced", AgentName: "agent-1"}
	out, errMsg := d.encryptToolArgs(row, "network_ask", []byte(`{"body":"secret hello","toAgent":"atlas"}`))
	if errMsg == "" {
		t.Fatalf("content tool on a provisioning network was not refused; out = %s", out)
	}
	if !strings.Contains(errMsg, "being secured") || !strings.Contains(errMsg, "no plaintext mode") {
		t.Fatalf("refusal message lacks the clear not-ready state: %q", errMsg)
	}

	// network_event_publish / network_invoke carry protected content too.
	if _, errMsg := d.encryptToolArgs(row, "network_event_publish", []byte(`{"type":"build.completed","payload":{"x":1}}`)); errMsg == "" {
		t.Fatal("event publish on a provisioning network was not refused")
	}
	if _, errMsg := d.encryptToolArgs(row, "network_invoke", []byte(`{"capability":"documents.extract","input":{"uri":"u"}}`)); errMsg == "" {
		t.Fatal("invoke on a provisioning network was not refused")
	}

	// Metadata-only tools run on any network state (nothing to protect).
	meta := []byte(`{"query":"pdf","kind":"service"}`)
	outMeta, errMsg := d.encryptToolArgs(row, "network_search", meta)
	if errMsg != "" {
		t.Fatalf("metadata-only tool refused on a provisioning network: %q", errMsg)
	}
	if string(outMeta) != string(meta) {
		t.Fatalf("metadata-only args were modified: %s", outMeta)
	}
}

// With crypto ACTIVE, the same content tools encrypt: the plaintext field is
// replaced by the envelope + AAD (+ object id), and the daemon can decrypt
// the envelope back to the exact plaintext.
func TestDaemon_ActiveNetworkEncryptsContent(t *testing.T) {
	d := newTestDaemon(t)
	networkID := domain.NewID().String()
	setupActiveNetCrypto(t, d, "tenant-t", networkID)
	row := &InstanceRow{InstanceID: "i1", NetworkID: networkID, AgentName: "agent-1"}

	// network_ask: body -> message envelope.
	out, errMsg := d.encryptToolArgs(row, "network_ask", []byte(`{"body":"secret hello","toAgent":"atlas"}`))
	if errMsg != "" {
		t.Fatalf("active network: network_ask refused: %q", errMsg)
	}
	var ask struct {
		MessageID string                  `json:"messageId"`
		Envelope  e2ee.EncryptedPayloadV1 `json:"envelope"`
		AAD       e2ee.AAD                `json:"aad"`
	}
	if err := json.Unmarshal(out, &ask); err != nil {
		t.Fatalf("unmarshal rewritten args: %v", err)
	}
	if ask.MessageID == "" || ask.Envelope.KeyEpochID == "" {
		t.Fatalf("rewritten args missing messageId/envelope: %s", out)
	}
	var askMap map[string]any
	_ = json.Unmarshal(out, &askMap)
	if _, ok := askMap["body"]; ok {
		t.Fatal("plaintext body survived the rewrite")
	}
	plain, err := d.decryptProtected(networkID, ask.Envelope, ask.AAD)
	if err != nil || plain != "secret hello" {
		t.Fatalf("round-trip = %q (err %v), want \"secret hello\"", plain, err)
	}

	// network_event_publish: payload -> event_payload envelope (recipient = target).
	out, errMsg = d.encryptToolArgs(row, "network_event_publish", []byte(`{"type":"build.completed","payload":{"buildId":"b1","ok":true},"target":"atlas"}`))
	if errMsg != "" {
		t.Fatalf("active network: event publish refused: %q", errMsg)
	}
	var pub struct {
		EventID  string                  `json:"eventId"`
		Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
		AAD      e2ee.AAD                `json:"aad"`
	}
	if err := json.Unmarshal(out, &pub); err != nil {
		t.Fatal(err)
	}
	if pub.AAD.Recipient != "atlas" || pub.AAD.ObjectType != e2ee.ObjectTypeEventPayload {
		t.Fatalf("event AAD = %+v, want recipient atlas / type %s", pub.AAD, e2ee.ObjectTypeEventPayload)
	}
	plain, err = d.decryptProtected(networkID, pub.Envelope, pub.AAD)
	if err != nil {
		t.Fatal(err)
	}
	var gotPayload, wantPayload map[string]any
	if err := json.Unmarshal([]byte(plain), &gotPayload); err != nil {
		t.Fatalf("payload plaintext is not the payload JSON: %q", plain)
	}
	if err := json.Unmarshal([]byte(`{"buildId":"b1","ok":true}`), &wantPayload); err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, gotPayload, wantPayload) {
		t.Fatalf("payload round-trip = %v, want %v", gotPayload, wantPayload)
	}

	// network_invoke: input -> invocation_input envelope (recipient = capability).
	out, errMsg = d.encryptToolArgs(row, "network_invoke", []byte(`{"capability":"documents.extract","input":{"uri":"https://example.com/a.pdf"}}`))
	if errMsg != "" {
		t.Fatalf("active network: invoke refused: %q", errMsg)
	}
	var inv struct {
		InvocationID string                  `json:"invocationId"`
		Envelope     e2ee.EncryptedPayloadV1 `json:"envelope"`
		AAD          e2ee.AAD                `json:"aad"`
	}
	if err := json.Unmarshal(out, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.AAD.Recipient != "documents.extract" || inv.AAD.ObjectType != e2ee.ObjectTypeInvocationInput {
		t.Fatalf("invoke AAD = %+v, want recipient documents.extract / type %s", inv.AAD, e2ee.ObjectTypeInvocationInput)
	}
	// The client-minted object id travels under the name the control plane
	// decodes, and it is the id the AAD binds (the two must agree or the
	// target decrypts against a different object id than the one protected).
	if inv.InvocationID == "" {
		t.Fatalf("invoke args carry no invocationId (the field the control plane decodes): %s", out)
	}
	if inv.AAD.ObjectID != inv.InvocationID {
		t.Fatalf("invoke AAD.ObjectID = %q, want the invocationId %q", inv.AAD.ObjectID, inv.InvocationID)
	}
	var invMap map[string]any
	_ = json.Unmarshal(out, &invMap)
	if _, ok := invMap["inputObjectID"]; ok {
		t.Error(`the invoke args still emit "inputObjectID" — the control plane drops unknown fields and mints its own invocation id`)
	}
	if _, ok := invMap["input"]; ok {
		t.Error("the plaintext input survived the rewrite")
	}
	plain, err = d.decryptProtected(networkID, inv.Envelope, inv.AAD)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain, "https://example.com/a.pdf") {
		t.Fatalf("invoke input round-trip = %q", plain)
	}
}

// A network-NULL instance (a representative) names a TARGET network it may or
// may not hold an active membership in — the daemon cannot see the
// membership, so it must NOT fail closed on the target's crypto state (that
// would mask the control plane's "no active membership" rejection, which the
// server evaluates before its content gate). Instead: encrypt when it can,
// otherwise pass the args through unchanged and let the control plane return
// the correct error. A worker (network-scoped) keeps the fail-closed refusal.
func TestDaemon_RepDefersCryptoDecisionToControlPlane(t *testing.T) {
	d := newTestDaemon(t)

	// rep = network-NULL instance; the target network's crypto is NOT ready
	// (unannounced). The content tool must PASS THROUGH (no refusal) so the
	// control plane can answer with the membership rejection, not a
	// "being secured" mask.
	rep := &InstanceRow{InstanceID: "rep-1", NetworkID: "", AgentName: "relay-rep"}
	in := []byte(`{"networkId":"net-b","toAgent":"relay-a","body":"relay 84: the attempt"}`)
	out, errMsg := d.encryptToolArgs(rep, "control_ask", in)
	if errMsg != "" {
		t.Fatalf("rep content tool on a not-ready target network was refused: %q", errMsg)
	}
	var outMap map[string]any
	if err := json.Unmarshal(out, &outMap); err != nil {
		t.Fatal(err)
	}
	if outMap["body"] != "relay 84: the attempt" {
		t.Fatalf("rep args were rewritten without encryption: %s", out)
	}
	if _, ok := outMap["envelope"]; ok {
		t.Fatalf("rep args carry an envelope though the target crypto is not ready: %s", out)
	}

	// Same call, but the target network's crypto IS active (and the keyring
	// is loaded): the rep encrypts, so the control plane accepts it.
	networkID := domain.NewID().String()
	setupActiveNetCrypto(t, d, "tenant-t", networkID)
	inActive := []byte(`{"networkId":"` + networkID + `","toAgent":"relay-a","body":"relay 84: ok"}`)
	outActive, errMsg := d.encryptToolArgs(rep, "control_ask", inActive)
	if errMsg != "" {
		t.Fatalf("rep content tool on an active target network was refused: %q", errMsg)
	}
	var ask struct {
		MessageID string                  `json:"messageId"`
		Envelope  e2ee.EncryptedPayloadV1 `json:"envelope"`
		AAD       e2ee.AAD                `json:"aad"`
	}
	if err := json.Unmarshal(outActive, &ask); err != nil {
		t.Fatal(err)
	}
	if ask.MessageID == "" || ask.Envelope.KeyEpochID == "" {
		t.Fatalf("active target: rep args missing messageId/envelope: %s", outActive)
	}
	plain, err := d.decryptProtected(networkID, ask.Envelope, ask.AAD)
	if err != nil || plain != "relay 84: ok" {
		t.Fatalf("rep round-trip = %q (err %v), want \"relay 84: ok\"", plain, err)
	}

	// Contrast: a WORKER (network-scoped) on a not-ready network is still
	// refused (the pinned fail-closed behavior is unchanged).
	worker := &InstanceRow{InstanceID: "w-1", NetworkID: "net-notready", AgentName: "worker"}
	if _, errMsg := d.encryptToolArgs(worker, "network_ask",
		[]byte(`{"toAgent":"x","body":"hi"}`)); errMsg == "" {
		t.Fatal("worker content tool on a not-ready network was not refused")
	}
}

// A LEGACY (v1-style) delivery that carries content without an envelope is
// REFUSED on a network-scoped instance — there is no plaintext path (the v1
// delivery shape is rejected; the work stays durable server-side).
func TestDaemon_LegacyPlaintextDeliveryRefused(t *testing.T) {
	d := newTestDaemon(t)
	setFakeBinary(t, d)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	networkID := domain.NewID().String()
	repo := t.TempDir()
	gitInitRepo(t, repo)
	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-le-launch", InstanceID: instanceID,
		Runtime:       string(domain.RuntimeFake),
		WorkspacePath: repo, AgentName: "le-agent",
		NetworkID: networkID,
	})

	// A plaintext task body with no envelope: refused, clean ack error.
	env, err := transport.NewEnvelope(transport.MsgDeliverNetworkEvent, transport.NetworkEventPayload{
		CommandID: "cmd-le-1", InstanceID: instanceID,
		Kind: "task", Body: "secret plaintext task", TaskID: domain.NewID().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	d.handleCommand(nil, env)
	_, ack := readUntilAck(t, server, "cmd-le-1")
	errMsg, _ := ack["error"].(string)
	if errMsg == "" || !strings.Contains(errMsg, "always encrypted") || !strings.Contains(errMsg, "no plaintext path") {
		t.Fatalf("plaintext delivery ack error = %q, want the always-encrypted refusal", errMsg)
	}
	// The instance is untouched (no turn ran).
	row, _, _ := d.state.GetInstance(instanceID)
	if row.Status != "idle" {
		t.Fatalf("status after the refusal = %q, want idle", row.Status)
	}

	// Content-FREE delivery on a network (a bare notice) still works:
	// nothing to protect, so the always-encrypted rule does not apply.
	env, err = transport.NewEnvelope(transport.MsgDeliverNetworkEvent, transport.NetworkEventPayload{
		CommandID: "cmd-le-2", InstanceID: instanceID, Kind: "notice",
	})
	if err != nil {
		t.Fatal(err)
	}
	d.handleCommand(nil, env)
	_, ack = readUntilAck(t, server, "cmd-le-2")
	// The notice runs a (contentless) turn; it must NOT be the refusal.
	if errMsg, _ := ack["error"].(string); strings.Contains(errMsg, "always encrypted") {
		t.Fatalf("content-free notice was refused: %s", errMsg)
	}
}

// jsonEqual compares two already-unmarshaled JSON values.
func jsonEqual(t *testing.T, a, b any) bool {
	t.Helper()
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}
