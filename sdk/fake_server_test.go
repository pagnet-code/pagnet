package sdk

// fakeServer is an in-memory control-plane + crypto-authority-host double
// for the SDK integration tests. It implements the D2 endpoint protocol
// (WS /api/v1/endpoints/ws) and the REST v2 surface, and plays the
// crypto-authority host for endpoint enrollment (it holds the network
// epoch key, wraps it to endpoint public keys with the binding enrollment
// info, and issues/verifies challenges — the same constructions the real
// host NKA runs).
//
// It is a test fixture, not a shipped component: it is deliberately
// simple (single tenant, in-memory state) and captures every wire byte so
// tests can assert the zero-knowledge property (no plaintext on the wire).

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

const (
	fakeTenantID = "01900000-0000-7000-8000-0000000000f0"
	fakeHostID   = "fake-host"
)

// fakePrincipal is one registered principal (agent or service).
type fakePrincipal struct {
	id           string
	kind         string // agent | service
	name         string
	memberships  map[string]bool // networkID → member
	capabilities []domain.Capability
}

type fakeNetwork struct {
	id           string
	name         string
	cryptoActive bool
}

// fakeEncField is one protected field on the REST wire (envelope + AAD).
type fakeEncField struct {
	Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD      e2ee.AAD                `json:"aad"`
}

type fakeMessage struct {
	id        string
	networkID string
	threadID  string
	kind      string
	sender    string
	recipient string
	envelope  e2ee.EncryptedPayloadV1
	aad       e2ee.AAD
	acked     bool
}

type fakeDelivery struct {
	id         string
	eventID    string
	subscriber string // principalID
	state      string // pending | dispatched | acknowledged
	attempts   int
}

type fakeEvent struct {
	id         string
	networkID  string
	eventType  string
	producer   string
	envelope   e2ee.EncryptedPayloadV1
	aad        e2ee.AAD
	deliveries map[string]*fakeDelivery
}

type fakeSub struct {
	id         string
	networkID  string
	subscriber string // principalID
	pattern    string
	enabled    bool
}

type fakeInvocation struct {
	id               string
	networkID        string
	caller           string
	target           string
	capability       string
	version          int
	state            string // pending|dispatched|running|completed|failed|cancelled
	idempotencyKey   string
	input            *fakeEncField
	output           *fakeEncField
	errDetail        *fakeEncField
	outputPlain      string // decrypted by the fake server (test assertion)
	errPlain         string
	publicResultCode string
	createdAt        string
	completedAt      string
}

type fakeEndpoint struct {
	id           string
	principalID  string
	publicKey    []byte
	capabilities []domain.Capability
	conn         *websocket.Conn
	sendMu       *sync.Mutex
}

type fakeServer struct {
	t  *testing.T
	ts *httptest.Server

	mu sync.Mutex

	principals map[string]*fakePrincipal
	networks   map[string]*fakeNetwork
	// credentials
	activationCreds map[string]string // cred → principalID
	endpointCreds   map[string]string // cred → principalID
	consumed        map[string]bool   // activation cred → consumed
	// crypto (the fake server is the crypto-authority host)
	epochKey [32]byte
	epochID  string
	// when true, the challenge is sent BEFORE the key package (exercises
	// the SDK's queued-challenge path).
	challengeFirst bool
	// when set, the WS upgrade is delayed (exercises the SDK's
	// disconnected window: pending results, reconnect).
	pauseDials time.Duration
	// endpoints
	endpoints map[string]*fakeEndpoint
	// content
	messages      map[string]*fakeMessage
	events        map[string]*fakeEvent
	subscriptions map[string]*fakeSub // subID
	invocations   map[string]*fakeInvocation
	// enrollment
	expectedProofs map[string]e2ee.Proof // networkID → expected
	cryptoReady    map[string]bool       // endpointID → ready
	// counters
	heartbeats int
	// wire capture (zero-knowledge assertions)
	wireMu sync.Mutex
	wire   []byte
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{
		t:               t,
		principals:      map[string]*fakePrincipal{},
		networks:        map[string]*fakeNetwork{},
		activationCreds: map[string]string{},
		endpointCreds:   map[string]string{},
		consumed:        map[string]bool{},
		endpoints:       map[string]*fakeEndpoint{},
		messages:        map[string]*fakeMessage{},
		events:          map[string]*fakeEvent{},
		subscriptions:   map[string]*fakeSub{},
		invocations:     map[string]*fakeInvocation{},
		expectedProofs:  map[string]e2ee.Proof{},
		cryptoReady:     map[string]bool{},
	}
	fs.epochID = uuid.New().String()
	for i := range fs.epochKey {
		fs.epochKey[i] = byte(i)
	}
	mux := http.NewServeMux()
	// The endpoint WS is registered OUTSIDE /api/v1 (it authenticates with
	// the principal credential, not the user token) — the real server's path.
	mux.HandleFunc("/wss/endpoints", fs.wsHandler)
	mux.HandleFunc("/api/v1/", fs.restHandler)
	fs.ts = httptest.NewServer(mux)
	t.Cleanup(fs.ts.Close)
	return fs
}

// URL returns the control-plane base URL for Config.Server.
func (fs *fakeServer) URL() string { return fs.ts.URL }

// --- fixtures ------------------------------------------------------------------

// createPrincipal registers a principal in the given networks and returns
// its id + a fresh one-time activation credential.
func (fs *fakeServer) createPrincipal(kind, name string, networkIDs ...string) (string, string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	id := uuid.New().String()
	p := &fakePrincipal{id: id, kind: kind, name: name, memberships: map[string]bool{}}
	for _, n := range networkIDs {
		p.memberships[n] = true
	}
	fs.principals[id] = p
	cred := "pgn_act_v1_" + id
	fs.activationCreds[cred] = id
	return id, cred
}

// createNetwork registers a network and returns its id.
func (fs *fakeServer) createNetwork(name string, cryptoActive bool) string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	id := uuid.New().String()
	fs.networks[id] = &fakeNetwork{id: id, name: name, cryptoActive: cryptoActive}
	return id
}

// setPrincipalCapabilities sets the principal's advertised capabilities
// (for search).
func (fs *fakeServer) setPrincipalCapabilities(principalID string, caps []domain.Capability) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if p, ok := fs.principals[principalID]; ok {
		p.capabilities = caps
	}
}

// dropEndpoint simulates a server-side connection drop for an endpoint.
func (fs *fakeServer) dropEndpoint(endpointID string) {
	fs.mu.Lock()
	ep := fs.endpoints[endpointID]
	conn := (*websocket.Conn)(nil)
	if ep != nil {
		conn = ep.conn
	}
	fs.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

// endpointForPrincipal returns the principal's live endpoint id ("" when
// none / not connected).
func (fs *fakeServer) endpointForPrincipal(principalID string) string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.endpointOfPrincipalLocked(principalID)
}

func (fs *fakeServer) endpointOfPrincipalLocked(principalID string) string {
	for id, ep := range fs.endpoints {
		if ep.principalID == principalID && ep.conn != nil {
			return id
		}
	}
	return ""
}

// redeliverEvent re-sends an existing event delivery to its subscriber
// (simulates the server's retry after an uncertain ack).
func (fs *fakeServer) redeliverEvent(eventID, deliveryID string) error {
	fs.mu.Lock()
	ev := fs.events[eventID]
	if ev == nil {
		fs.mu.Unlock()
		return fmt.Errorf("unknown event %s", eventID)
	}
	d := ev.deliveries[deliveryID]
	if d == nil {
		fs.mu.Unlock()
		return fmt.Errorf("unknown delivery %s", deliveryID)
	}
	epID := fs.endpointOfPrincipalLocked(d.subscriber)
	fs.mu.Unlock()
	if epID == "" {
		return fmt.Errorf("no live endpoint for the delivery's subscriber")
	}
	return fs.pushEventDelivery(epID, ev, d)
}

// wireBytes returns everything that crossed the wire (WS payloads + REST
// bodies), for zero-knowledge assertions.
func (fs *fakeServer) wireBytes() []byte {
	fs.wireMu.Lock()
	defer fs.wireMu.Unlock()
	out := make([]byte, len(fs.wire))
	copy(out, fs.wire)
	return out
}

func (fs *fakeServer) capture(b []byte) {
	if len(b) == 0 {
		return
	}
	fs.wireMu.Lock()
	fs.wire = append(fs.wire, b...)
	fs.wireMu.Unlock()
}

// heartbeatCount returns the number of endpoint.heartbeat frames seen.
func (fs *fakeServer) heartbeatCount() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.heartbeats
}

// messageAcked reports whether a message was acked.
func (fs *fakeServer) messageAcked(messageID string) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	m, ok := fs.messages[messageID]
	return ok && m.acked
}

// deliveryState returns the state of an event delivery ("" when unknown).
func (fs *fakeServer) deliveryState(eventID, deliveryID string) string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	ev := fs.events[eventID]
	if ev == nil {
		return ""
	}
	if d, ok := ev.deliveries[deliveryID]; ok {
		return d.state
	}
	return ""
}

// eventDeliveryStates returns the states of all deliveries of an event.
func (fs *fakeServer) eventDeliveryStates(eventID string) []string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	ev := fs.events[eventID]
	if ev == nil {
		return nil
	}
	out := make([]string, 0, len(ev.deliveries))
	for _, d := range ev.deliveries {
		out = append(out, d.state)
	}
	return out
}

// subscriptionCount returns the number of subscriptions in a network.
func (fs *fakeServer) subscriptionCount(networkID string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := 0
	for _, s := range fs.subscriptions {
		if s.networkID == networkID {
			n++
		}
	}
	return n
}

// invocationState returns the state of an invocation ("" when unknown).
func (fs *fakeServer) invocationState(invocationID string) string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	inv, ok := fs.invocations[invocationID]
	if !ok {
		return ""
	}
	return inv.state
}

// invocationOutputPlain returns the fake-server-decrypted invocation
// output (for assertions that the server-side record is correct).
func (fs *fakeServer) invocationOutputPlain(invocationID string) string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	inv, ok := fs.invocations[invocationID]
	if !ok {
		return ""
	}
	return inv.outputPlain
}

// cancelInvocation forces an invocation to the cancelled state (simulates
// the server's TTL expiry).
func (fs *fakeServer) cancelInvocation(invocationID string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if inv, ok := fs.invocations[invocationID]; ok {
		inv.state = "cancelled"
		inv.completedAt = time.Now().UTC().Format(time.RFC3339)
	}
}

// cryptoReadyFor reports the enrollment state of an endpoint.
func (fs *fakeServer) cryptoReadyFor(endpointID string) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.cryptoReady[endpointID]
}

// --- crypto host (enrollment) ----------------------------------------------------

// buildAAD builds the AAD for a protected object (the same conventions the
// SDK uses: ProtocolVersion 2, principal ids as sender/recipient).
func (fs *fakeServer) buildAAD(networkID, objectType, objectID, sender, recipient string) e2ee.AAD {
	return e2ee.AAD{
		ProtocolVersion: transport.ProtocolVersion,
		TenantID:        fakeTenantID,
		NetworkID:       networkID,
		ObjectType:      objectType,
		ObjectID:        objectID,
		Sender:          sender,
		Recipient:       recipient,
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		KeyEpochID:      fs.epochID,
	}
}

// enrollEndpoint runs the crypto enrollment for (endpoint, network):
// key package (HPKE wrap of the epoch key) then challenge (+ expected
// proof) — or the reverse when challengeFirst is set. Mirrors the host
// NKA's constructions (the SDK's own challengeMAC computes the proof).
func (fs *fakeServer) enrollEndpoint(ep *fakeEndpoint, networkID string) {
	fs.mu.Lock()
	net := fs.networks[networkID]
	if net == nil || !net.cryptoActive {
		fs.mu.Unlock()
		return
	}
	epochKey := fs.epochKey
	epochID := fs.epochID
	pub := ep.publicKey
	challengeFirst := fs.challengeFirst
	fs.mu.Unlock()
	if len(pub) != 32 {
		return
	}

	sendKeyPackage := func() {
		enc, ct, err := e2ee.HPKEWrap(pub, []byte(enrollmentInfo), nil, epochKey[:])
		if err != nil {
			fs.t.Errorf("fake server: HPKEWrap: %v", err)
			return
		}
		kp := EndpointCryptoKeyPackagePayload{
			NetworkID:  networkID,
			EpochID:    epochID,
			WrappedKey: transport.CryptoHPKEWrap{Enc: enc, Ciphertext: ct},
		}
		_ = fs.sendTo(ep, MsgEndpointCryptoKeyPackage, kp)
	}
	sendChallenge := func() {
		plaintext := make([]byte, 32)
		for i := range plaintext {
			plaintext[i] = byte(i * 7)
		}
		objectID := uuid.New().String()
		aad := e2ee.AAD{
			ProtocolVersion: transport.ProtocolVersion,
			TenantID:        fakeTenantID,
			NetworkID:       networkID,
			ObjectType:      "e2ee_challenge",
			ObjectID:        objectID,
			Sender:          fakeHostID,
			Recipient:       ep.id,
			CreatedAt:       time.Now().UTC().Format(time.RFC3339),
			KeyEpochID:      epochID,
		}
		env, err := e2ee.Encrypt(plaintext, epochKey, aad)
		if err != nil {
			fs.t.Errorf("fake server: encrypt challenge: %v", err)
			return
		}
		nonce := make([]byte, 16)
		for i := range nonce {
			nonce[i] = byte(i * 13)
		}
		expected := e2ee.Proof{MAC: challengeMAC(plaintext, nonce)}
		ch := EndpointCryptoChallengePayload{
			NetworkID:     networkID,
			Challenge:     e2ee.Challenge{Envelope: env, AAD: aad, Nonce: nonce},
			ExpectedProof: expected,
		}
		fs.mu.Lock()
		fs.expectedProofs[networkID] = expected
		fs.mu.Unlock()
		_ = fs.sendTo(ep, MsgEndpointCryptoChallenge, ch)
	}
	if challengeFirst {
		sendChallenge()
		sendKeyPackage()
	} else {
		sendKeyPackage()
		sendChallenge()
	}
}

// --- content producers (the fake server acting as another principal) ------------

// publishPlainEvent publishes an event (encrypted by the fake server, which
// holds the epoch key) and fans it out to matching subscriptions. Returns
// the event id + the delivery ids.
func (fs *fakeServer) publishPlainEvent(networkID, eventType, producer, payloadJSON string) (string, []string) {
	fs.mu.Lock()
	id := uuid.New().String()
	aad := fs.buildAAD(networkID, e2ee.ObjectTypeEventPayload, id, producer, "")
	env, err := e2ee.Encrypt([]byte(payloadJSON), fs.epochKey, aad)
	if err != nil {
		fs.mu.Unlock()
		fs.t.Fatalf("fake server: encrypt event: %v", err)
	}
	ev := &fakeEvent{
		id: id, networkID: networkID, eventType: eventType, producer: producer,
		envelope: env, aad: aad, deliveries: map[string]*fakeDelivery{},
	}
	fs.events[id] = ev
	var deliveryIDs []string
	for _, sub := range fs.subscriptions {
		if sub.networkID != networkID || !sub.enabled {
			continue
		}
		if !matchEventPattern(sub.pattern, eventType) {
			continue
		}
		did := uuid.New().String()
		d := &fakeDelivery{id: did, eventID: id, subscriber: sub.subscriber, state: "pending"}
		ev.deliveries[did] = d
		deliveryIDs = append(deliveryIDs, did)
	}
	fs.mu.Unlock()
	for _, did := range deliveryIDs {
		epID := fs.endpointForPrincipal(ev.deliveries[did].subscriber)
		if epID == "" {
			continue // subscriber offline: the delivery stays pending (durable)
		}
		_ = fs.pushEventDelivery(epID, ev, ev.deliveries[did])
	}
	return id, deliveryIDs
}

// sendPlainMessage sends a message (encrypted by the fake server) to a
// recipient principal, delivering it live when the recipient's endpoint is
// connected. Returns the message id.
func (fs *fakeServer) sendPlainMessage(networkID, sender, recipient, threadID, kind, text string) string {
	fs.mu.Lock()
	id := uuid.New().String()
	parts, _ := json.Marshal([]domain.MessagePart{domain.TextPart(text)})
	aad := fs.buildAAD(networkID, e2ee.ObjectTypeMessage, id, sender, recipient)
	env, err := e2ee.Encrypt(parts, fs.epochKey, aad)
	if err != nil {
		fs.mu.Unlock()
		fs.t.Fatalf("fake server: encrypt message: %v", err)
	}
	m := &fakeMessage{
		id: id, networkID: networkID, threadID: threadID, kind: kind,
		sender: sender, recipient: recipient, envelope: env, aad: aad,
	}
	fs.messages[id] = m
	fs.mu.Unlock()
	if epID := fs.endpointForPrincipal(recipient); epID != "" {
		_ = fs.pushMessageDelivery(epID, m)
	}
	return id
}

// createPlainInvocation creates an invocation (input encrypted by the fake
// server) from caller to target, dispatching it live when the target's
// endpoint is connected. Returns the invocation id.
func (fs *fakeServer) createPlainInvocation(networkID, caller, target, capability string, version int, inputJSON string) string {
	fs.mu.Lock()
	id := uuid.New().String()
	aad := fs.buildAAD(networkID, e2ee.ObjectTypeInvocationInput, id, caller, target)
	env, err := e2ee.Encrypt([]byte(inputJSON), fs.epochKey, aad)
	if err != nil {
		fs.mu.Unlock()
		fs.t.Fatalf("fake server: encrypt invocation input: %v", err)
	}
	inv := &fakeInvocation{
		id: id, networkID: networkID, caller: caller, target: target,
		capability: capability, version: version, state: "pending",
		input:     &fakeEncField{Envelope: env, AAD: aad},
		createdAt: time.Now().UTC().Format(time.RFC3339),
	}
	fs.invocations[id] = inv
	fs.mu.Unlock()
	if epID := fs.endpointForPrincipal(target); epID != "" {
		_ = fs.pushInvocationDispatch(epID, inv)
	}
	return id
}

// --- WebSocket -------------------------------------------------------------------

func (fs *fakeServer) wsHandler(w http.ResponseWriter, r *http.Request) {
	cred := bearerToken(r)
	fs.mu.Lock()
	principalID, isActivation := fs.activationCreds[cred]
	if principalID == "" {
		principalID, _ = fs.endpointCreds[cred]
	}
	consumed := fs.consumed[cred]
	var durableCred string
	if isActivation && !consumed {
		// Activation exchange: consume the one-time credential and issue
		// the durable endpoint credential (returned ONCE, in auth_ok).
		fs.consumed[cred] = true
		durableCred = "pgn_epd_v1_" + cred[len("pgn_act_v1_"):]
		fs.endpointCreds[durableCred] = principalID
	}
	var netIDs []string
	if p, ok := fs.principals[principalID]; ok {
		for n := range p.memberships {
			netIDs = append(netIDs, n)
		}
	}
	pause := fs.pauseDials
	fs.mu.Unlock()
	if principalID == "" || (isActivation && consumed) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if pause > 0 {
		time.Sleep(pause)
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	fs.mu.Lock()
	epID := uuid.New().String()
	ep := &fakeEndpoint{id: epID, principalID: principalID, conn: ws, sendMu: &sync.Mutex{}}
	fs.endpoints[epID] = ep
	fs.mu.Unlock()
	go fs.wsReadLoop(ep, principalID, netIDs, durableCred)
}

func (fs *fakeServer) wsReadLoop(ep *fakeEndpoint, principalID string, netIDs []string, durableCred string) {
	defer func() {
		fs.mu.Lock()
		if cur, ok := fs.endpoints[ep.id]; ok && cur.conn == ep.conn {
			cur.conn = nil // keep the record; the endpoint is offline
		}
		fs.mu.Unlock()
	}()
	for {
		var env transport.Envelope
		if err := ep.conn.ReadJSON(&env); err != nil {
			return
		}
		fs.capture(env.Payload)
		switch env.Type {
		case transport.MsgEndpointRegister:
			var p transport.EndpointRegisterPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			pub, _ := base64.StdEncoding.DecodeString(p.PublicKey)
			fs.mu.Lock()
			ep.publicKey = pub
			ep.capabilities = p.Capabilities
			fs.mu.Unlock()
			ok := transport.EndpointAuthOKPayload{
				PrincipalID:     principalID,
				EndpointID:      ep.id,
				NetworkIDs:      netIDs,
				Credential:      durableCred,
				ProtocolVersion: transport.ProtocolVersion,
			}
			if err := fs.sendTo(ep, transport.MsgEndpointAuthOK, ok); err != nil {
				return
			}
			// Crypto enrollment for crypto-active networks.
			for _, n := range netIDs {
				fs.enrollEndpoint(ep, n)
			}
		case transport.MsgEndpointHeartbeat:
			fs.mu.Lock()
			fs.heartbeats++
			fs.mu.Unlock()
			_ = fs.sendTo(ep, transport.MsgEndpointHeartbeatAck, transport.EndpointHeartbeatAckPayload{})
		case transport.MsgEndpointEventAck:
			var p transport.EndpointEventAckPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			fs.mu.Lock()
			for _, ev := range fs.events {
				if d, ok := ev.deliveries[p.DeliveryID]; ok {
					d.state = "acknowledged"
				}
			}
			fs.mu.Unlock()
		case transport.MsgEndpointMessageAcked:
			var p transport.EndpointMessageAckedPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			fs.mu.Lock()
			if m, ok := fs.messages[p.MessageID]; ok {
				m.acked = true
			}
			fs.mu.Unlock()
		case transport.MsgEndpointInvocationAccept:
			var p transport.EndpointInvocationAcceptPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			fs.mu.Lock()
			if inv, ok := fs.invocations[p.InvocationID]; ok && inv.state == "dispatched" {
				inv.state = "running"
			}
			fs.mu.Unlock()
		case transport.MsgEndpointInvocationResult:
			var p transport.EndpointInvocationResultPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			fs.handleInvocationResult(p)
		case MsgEndpointCryptoProve:
			var p EndpointCryptoProvePayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			fs.mu.Lock()
			expected, ok := fs.expectedProofs[p.NetworkID]
			if ok && hmac.Equal(p.Proof.MAC, expected.MAC) {
				fs.cryptoReady[ep.id] = true
			}
			fs.mu.Unlock()
		case transport.MsgEndpointDisconnect:
			return
		}
	}
}

func (fs *fakeServer) sendTo(ep *fakeEndpoint, msgType string, payload any) error {
	env, err := transport.NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(env)
	fs.capture(b)
	ep.sendMu.Lock()
	defer ep.sendMu.Unlock()
	return ep.conn.WriteJSON(env)
}

// handleInvocationResult decrypts the result (the fake server holds the
// epoch key) and records the invocation's terminal state.
func (fs *fakeServer) handleInvocationResult(p transport.EndpointInvocationResultPayload) {
	fs.mu.Lock()
	inv, ok := fs.invocations[p.InvocationID]
	if !ok {
		fs.mu.Unlock()
		return
	}
	if p.Envelope != nil && p.AAD != nil {
		plain, err := e2ee.Decrypt(*p.Envelope, fs.epochKey, *p.AAD)
		if err == nil {
			if p.OK {
				inv.outputPlain = string(plain)
			} else {
				inv.errPlain = string(plain)
			}
		}
	}
	if p.OK {
		inv.state = "completed"
		inv.output = &fakeEncField{Envelope: *p.Envelope, AAD: *p.AAD}
	} else {
		inv.state = "failed"
		inv.errDetail = &fakeEncField{Envelope: *p.Envelope, AAD: *p.AAD}
	}
	inv.publicResultCode = p.PublicResultCode
	inv.completedAt = time.Now().UTC().Format(time.RFC3339)
	fs.mu.Unlock()
}

// pushEventDelivery sends one event delivery to an endpoint.
func (fs *fakeServer) pushEventDelivery(epID string, ev *fakeEvent, d *fakeDelivery) error {
	fs.mu.Lock()
	ep := fs.endpoints[epID]
	d.state = "dispatched"
	d.attempts++
	fs.mu.Unlock()
	if ep == nil || ep.conn == nil {
		return fmt.Errorf("endpoint %s not connected", epID)
	}
	payload := transport.EndpointEventDeliverPayload{
		EventID:             ev.id,
		DeliveryID:          d.id,
		NetworkID:           ev.networkID,
		EventType:           ev.eventType,
		ProducerPrincipalID: ev.producer,
		Envelope:            &ev.envelope,
		AAD:                 &ev.aad,
	}
	return fs.sendTo(ep, transport.MsgEndpointEventDeliver, payload)
}

// pushMessageDelivery sends one message delivery to an endpoint.
func (fs *fakeServer) pushMessageDelivery(epID string, m *fakeMessage) error {
	fs.mu.Lock()
	ep := fs.endpoints[epID]
	fs.mu.Unlock()
	if ep == nil || ep.conn == nil {
		return fmt.Errorf("endpoint %s not connected", epID)
	}
	payload := transport.EndpointMessageDeliverPayload{
		MessageID:         m.id,
		NetworkID:         m.networkID,
		ThreadID:          m.threadID,
		Kind:              m.kind,
		SenderPrincipalID: m.sender,
		Envelope:          &m.envelope,
		AAD:               &m.aad,
	}
	return fs.sendTo(ep, transport.MsgEndpointMessageDeliver, payload)
}

// pushInvocationDispatch sends one invocation dispatch to an endpoint.
func (fs *fakeServer) pushInvocationDispatch(epID string, inv *fakeInvocation) error {
	fs.mu.Lock()
	ep := fs.endpoints[epID]
	inv.state = "dispatched"
	fs.mu.Unlock()
	if ep == nil || ep.conn == nil {
		return fmt.Errorf("endpoint %s not connected", epID)
	}
	payload := transport.EndpointInvocationDispatchPayload{
		InvocationID:      inv.id,
		NetworkID:         inv.networkID,
		CapabilityID:      inv.capability,
		CapabilityVersion: inv.version,
		Envelope:          &inv.input.Envelope,
		AAD:               &inv.input.AAD,
	}
	return fs.sendTo(ep, transport.MsgEndpointInvocationDispatch, payload)
}

// --- REST --------------------------------------------------------------------------

func (fs *fakeServer) restHandler(w http.ResponseWriter, r *http.Request) {
	cred := bearerToken(r)
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	fs.capture(body)
	fs.mu.Lock()
	principalID, isActivation := fs.activationCreds[cred]
	if principalID == "" {
		principalID, _ = fs.endpointCreds[cred]
	}
	dead := principalID == "" || (isActivation && fs.consumed[cred])
	fs.mu.Unlock()
	if dead {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	writeJSON := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		b, _ := json.Marshal(v)
		fs.capture(b)
		_, _ = w.Write(b)
	}
	switch {
	case path == "/auth/principal/me" && r.Method == http.MethodGet:
		fs.handleWhoAmI(w, principalID, writeJSON)
	case path == "/networks" && r.Method == http.MethodGet:
		fs.handleNetworks(w, principalID, writeJSON)
	case strings.HasSuffix(path, "/messages") && r.Method == http.MethodPost:
		fs.handleCreateMessage(w, principalID, strings.TrimSuffix(path, "/messages"), body, writeJSON)
	case strings.HasSuffix(path, "/events") && r.Method == http.MethodPost:
		fs.handleCreateEvent(w, principalID, strings.TrimSuffix(path, "/events"), body, writeJSON)
	case strings.HasSuffix(path, "/subscriptions") && r.Method == http.MethodPost:
		fs.handleCreateSubscription(w, principalID, strings.TrimSuffix(path, "/subscriptions"), body, writeJSON)
	case strings.HasSuffix(path, "/subscriptions") && r.Method == http.MethodGet:
		fs.handleListSubscriptions(w, principalID, strings.TrimSuffix(path, "/subscriptions"), writeJSON)
	case strings.Contains(path, "/subscriptions/") && r.Method == http.MethodDelete:
		fs.handleDeleteSubscription(w, principalID, path, writeJSON)
	case strings.HasSuffix(path, "/invocations") && r.Method == http.MethodPost:
		fs.handleCreateInvocation(w, principalID, strings.TrimSuffix(path, "/invocations"), body, writeJSON)
	case strings.Contains(path, "/invocations/") && r.Method == http.MethodGet:
		fs.handleGetInvocation(w, principalID, path, writeJSON)
	case strings.HasSuffix(path, "/search") && r.Method == http.MethodGet:
		fs.handleSearch(w, principalID, strings.TrimSuffix(path, "/search"), r.URL.Query(), writeJSON)
	default:
		http.Error(w, "not found: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}
}

// handleWhoAmI mirrors the real server: {"principal": Principal,
// "memberships": [NetworkMembership], "endpoints": [...]} — the domain types
// marshal with PascalCase field names (no json tags).
func (fs *fakeServer) handleWhoAmI(w http.ResponseWriter, principalID string, writeJSON func(int, any)) {
	fs.mu.Lock()
	p := fs.principals[principalID]
	memberships := []map[string]any{}
	if p != nil {
		for n := range p.memberships {
			memberships = append(memberships, map[string]any{
				"NetworkID":   n,
				"State":       "active",
				"Permissions": []string{"discover", "communicate", "invoke", "event_publish", "event_subscribe"},
			})
		}
	}
	kind, name := "agent", ""
	if p != nil {
		kind, name = p.kind, p.name
	}
	fs.mu.Unlock()
	writeJSON(http.StatusOK, map[string]any{
		"principal": map[string]any{
			"ID":             principalID,
			"OwningTenantID": fakeTenantID,
			"Kind":           kind,
			"Name":           name,
			"Visibility":     "private",
		},
		"memberships": memberships,
		"endpoints":   []map[string]any{},
	})
}

// handleNetworks mirrors the real server: a BARE ARRAY of networkResponse
// (domain.Network PascalCase + a camelCase "crypto" block).
func (fs *fakeServer) handleNetworks(w http.ResponseWriter, principalID string, writeJSON func(int, any)) {
	fs.mu.Lock()
	p := fs.principals[principalID]
	nets := []map[string]any{}
	if p != nil {
		for n := range p.memberships {
			if net, ok := fs.networks[n]; ok {
				entry := map[string]any{"ID": net.id, "Name": net.name, "Slug": net.name, "Description": ""}
				if net.cryptoActive {
					entry["crypto"] = map[string]any{"status": "active", "epochId": fs.epochID}
				} else {
					entry["crypto"] = map[string]any{"status": "provisioning"}
				}
				nets = append(nets, entry)
			}
		}
	}
	fs.mu.Unlock()
	writeJSON(http.StatusOK, nets)
}

// handleCreateMessage mirrors the real server: the protected content crosses
// as a top-level "envelope" + "aad" pair; the response is the full
// domain.Message (PascalCase ID).
func (fs *fakeServer) handleCreateMessage(w http.ResponseWriter, principalID, networkPath string, body []byte, writeJSON func(int, any)) {
	var req struct {
		ID                   string                  `json:"id"`
		ThreadID             string                  `json:"threadId"`
		RecipientPrincipalID string                  `json:"recipientPrincipalId"`
		RecipientGroup       string                  `json:"recipientGroup"`
		Kind                 string                  `json:"kind"`
		Envelope             e2ee.EncryptedPayloadV1 `json:"envelope"`
		AAD                  e2ee.AAD                `json:"aad"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	networkID := networkIDFromPath(networkPath)
	fs.mu.Lock()
	m := &fakeMessage{
		id: req.ID, networkID: networkID, threadID: req.ThreadID, kind: req.Kind,
		sender: principalID, recipient: req.RecipientPrincipalID,
		envelope: req.Envelope, aad: req.AAD,
	}
	fs.messages[m.id] = m
	fs.mu.Unlock()
	if epID := fs.endpointForPrincipal(req.RecipientPrincipalID); epID != "" {
		_ = fs.pushMessageDelivery(epID, m)
	}
	writeJSON(http.StatusCreated, map[string]any{"ID": m.id})
}

// handleCreateEvent mirrors the real server: the payload crosses as a
// top-level "envelope" + "aad" pair; the client object id rides in "eventId"
// (adopted by the server). The response is {"event": Event, "deliveries": n}.
func (fs *fakeServer) handleCreateEvent(w http.ResponseWriter, principalID, networkPath string, body []byte, writeJSON func(int, any)) {
	var req struct {
		Type     string                  `json:"type"`
		EventID  string                  `json:"eventId"`
		Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
		AAD      e2ee.AAD                `json:"aad"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	networkID := networkIDFromPath(networkPath)
	fs.mu.Lock()
	ev := &fakeEvent{
		id: req.EventID, networkID: networkID, eventType: req.Type, producer: principalID,
		envelope: req.Envelope, aad: req.AAD,
		deliveries: map[string]*fakeDelivery{},
	}
	fs.events[ev.id] = ev
	var deliveryIDs []string
	for _, sub := range fs.subscriptions {
		if sub.networkID != networkID || !sub.enabled {
			continue
		}
		if !matchEventPattern(sub.pattern, req.Type) {
			continue
		}
		did := uuid.New().String()
		d := &fakeDelivery{id: did, eventID: ev.id, subscriber: sub.subscriber, state: "pending"}
		ev.deliveries[did] = d
		deliveryIDs = append(deliveryIDs, did)
	}
	fs.mu.Unlock()
	for _, did := range deliveryIDs {
		epID := fs.endpointForPrincipal(ev.deliveries[did].subscriber)
		if epID == "" {
			continue
		}
		_ = fs.pushEventDelivery(epID, ev, ev.deliveries[did])
	}
	writeJSON(http.StatusCreated, map[string]any{
		"event":      map[string]any{"ID": ev.id},
		"deliveries": len(deliveryIDs),
	})
}

func (fs *fakeServer) handleCreateSubscription(w http.ResponseWriter, principalID, networkPath string, body []byte, writeJSON func(int, any)) {
	var req struct {
		EventPattern string `json:"eventPattern"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	networkID := networkIDFromPath(networkPath)
	fs.mu.Lock()
	id := uuid.New().String()
	fs.subscriptions[id] = &fakeSub{
		id: id, networkID: networkID, subscriber: principalID, pattern: req.EventPattern, enabled: true,
	}
	fs.mu.Unlock()
	// The real server returns the bare domain.EventSubscription (PascalCase).
	writeJSON(http.StatusCreated, map[string]any{"ID": id, "EventPattern": req.EventPattern, "Enabled": true})
}

// handleListSubscriptions mirrors the real server: a BARE ARRAY of
// domain.EventSubscription (PascalCase).
func (fs *fakeServer) handleListSubscriptions(w http.ResponseWriter, principalID, networkPath string, writeJSON func(int, any)) {
	networkID := networkIDFromPath(networkPath)
	fs.mu.Lock()
	subs := []map[string]any{}
	for _, s := range fs.subscriptions {
		if s.networkID == networkID && s.subscriber == principalID {
			subs = append(subs, map[string]any{"ID": s.id, "EventPattern": s.pattern, "Enabled": s.enabled})
		}
	}
	fs.mu.Unlock()
	writeJSON(http.StatusOK, subs)
}

func (fs *fakeServer) handleDeleteSubscription(w http.ResponseWriter, principalID, path string, writeJSON func(int, any)) {
	// path: /networks/{networkID}/subscriptions/{subID}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 4 {
		writeJSON(http.StatusNotFound, map[string]any{"error": "bad path"})
		return
	}
	subID := parts[3]
	fs.mu.Lock()
	if s, ok := fs.subscriptions[subID]; ok && s.subscriber == principalID {
		delete(fs.subscriptions, subID)
	}
	fs.mu.Unlock()
	// The real server returns 204 No Content.
	w.WriteHeader(http.StatusNoContent)
}

// handleCreateInvocation mirrors the real server: the input crosses as a
// top-level "envelope" + "aad" pair; the client object id rides in
// "invocationId" (adopted by the server). The response is the invocationView.
func (fs *fakeServer) handleCreateInvocation(w http.ResponseWriter, principalID, networkPath string, body []byte, writeJSON func(int, any)) {
	var req struct {
		TargetPrincipalID string                  `json:"targetPrincipalId"`
		CapabilityID      string                  `json:"capabilityId"`
		CapabilityVersion int                     `json:"capabilityVersion"`
		Envelope          e2ee.EncryptedPayloadV1 `json:"envelope"`
		AAD               e2ee.AAD                `json:"aad"`
		InvocationID      string                  `json:"invocationId"`
		IdempotencyKey    string                  `json:"idempotencyKey"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	networkID := networkIDFromPath(networkPath)
	fs.mu.Lock()
	inv := &fakeInvocation{
		id: req.InvocationID, networkID: networkID, caller: principalID, target: req.TargetPrincipalID,
		capability: req.CapabilityID, version: req.CapabilityVersion, state: "pending",
		idempotencyKey: req.IdempotencyKey,
		input:          &fakeEncField{Envelope: req.Envelope, AAD: req.AAD},
		createdAt:      time.Now().UTC().Format(time.RFC3339),
	}
	fs.invocations[inv.id] = inv
	fs.mu.Unlock()
	if epID := fs.endpointForPrincipal(req.TargetPrincipalID); epID != "" {
		_ = fs.pushInvocationDispatch(epID, inv)
	}
	writeJSON(http.StatusCreated, fs.invocationView(inv))
}

func (fs *fakeServer) handleGetInvocation(w http.ResponseWriter, principalID, path string, writeJSON func(int, any)) {
	// path: /networks/{networkID}/invocations/{invocationID}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 4 {
		writeJSON(http.StatusNotFound, map[string]any{"error": "bad path"})
		return
	}
	invID := parts[3]
	fs.mu.Lock()
	inv, ok := fs.invocations[invID]
	fs.mu.Unlock()
	if !ok {
		writeJSON(http.StatusNotFound, map[string]any{"error": "unknown invocation"})
		return
	}
	writeJSON(http.StatusOK, fs.invocationView(inv))
}

// invocationView builds the invocationView wire shape (the real server's
// response): {"invocation": CapabilityInvocation (PascalCase), "input"/
// "output"/"error": {envelope, aad}}. It acquires fs.mu (callers must NOT
// hold it) so the record is a consistent snapshot — invocations are mutated
// concurrently by the WS result handler and cancelInvocation.
func (fs *fakeServer) invocationView(inv *fakeInvocation) map[string]any {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	invocation := map[string]any{
		"ID":                inv.id,
		"NetworkID":         inv.networkID,
		"CallerPrincipalID": inv.caller,
		"TargetPrincipalID": inv.target,
		"CapabilityID":      inv.capability,
		"CapabilityVersion": inv.version,
		"State":             inv.state,
		"CreatedAt":         inv.createdAt,
	}
	if inv.idempotencyKey != "" {
		invocation["IdempotencyKey"] = inv.idempotencyKey
	}
	if inv.publicResultCode != "" {
		invocation["PublicResultCode"] = inv.publicResultCode
	}
	if inv.completedAt != "" {
		invocation["CompletedAt"] = inv.completedAt
	}
	out := map[string]any{"invocation": invocation}
	if inv.input != nil {
		out["input"] = inv.input
	}
	if inv.output != nil {
		out["output"] = inv.output
	}
	if inv.errDetail != nil {
		out["error"] = inv.errDetail
	}
	return out
}

func (fs *fakeServer) handleSearch(w http.ResponseWriter, principalID, networkPath string, q url.Values, writeJSON func(int, any)) {
	networkID := networkIDFromPath(networkPath)
	query := q.Get("query")
	kind := q.Get("kind")
	capability := q.Get("capability")
	fs.mu.Lock()
	results := []map[string]any{}
	for _, p := range fs.principals {
		if !p.memberships[networkID] {
			continue
		}
		if kind != "" && p.kind != kind {
			continue
		}
		if capability != "" && !hasCapability(p.capabilities, capability) {
			continue
		}
		reasons := []string{}
		if query != "" && strings.Contains(strings.ToLower(p.name), strings.ToLower(query)) {
			reasons = append(reasons, "name")
		}
		if capability != "" {
			reasons = append(reasons, "capability")
		}
		if query == "" && kind == "" && capability == "" {
			reasons = append(reasons, "network_member")
		}
		online := fs.endpointOfPrincipalLocked(p.id) != ""
		results = append(results, map[string]any{
			// The real server returns the embedded domain.Principal
			// (PascalCase) + MatchReasons + HasOnlineEndpoint. It does NOT
			// return the principal's capabilities in a search hit.
			"ID":                p.id,
			"Kind":              p.kind,
			"Name":              p.name,
			"Description":       "",
			"Visibility":        "private",
			"ProviderName":      "",
			"ProviderURL":       "",
			"MatchReasons":      reasons,
			"HasOnlineEndpoint": online,
		})
	}
	fs.mu.Unlock()
	writeJSON(http.StatusOK, map[string]any{"results": results, "cursor": ""})
}

func hasCapability(caps []domain.Capability, id string) bool {
	for _, c := range caps {
		if c.ID == id {
			return true
		}
	}
	return false
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	return strings.TrimPrefix(h, "Bearer ")
}

// networkIDFromPath extracts the network id from a /networks/{id}/... path.
func networkIDFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "networks" {
		return parts[1]
	}
	return ""
}
