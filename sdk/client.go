package sdk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

// hpkeKEM is the fixed X25519 KEM scheme (the same suite the host crypto
// identity and e2ee use).
func hpkeKEM() kem.Scheme { return hpke.KEM_X25519_HKDF_SHA256.Scheme() }

// heartbeatInterval is the endpoint liveness report cadence (plan D2:
// ~20s, carries the inflight count). It is a var (not a const) so tests
// can shorten the cadence; production always runs at 20s.
var heartbeatInterval = 20 * time.Second

// handlerSlotCap bounds concurrent handler goroutines (backpressure,
// north-star §119): when the cap is reached the dispatcher stops
// consuming, the WebSocket buffer fills, and the control plane stops live
// dispatch while the delivery stays pending in the DB (at-least-once,
// never dropped).
const handlerSlotCap = 128

// dispatchQueueCap bounds the in-memory delivery queue between the read
// loop and the dispatcher.
const dispatchQueueCap = 256

// Client is a connected pagnet endpoint: one principal's live presence on
// the control plane. It owns the WebSocket (register/heartbeat/reconnect/
// acks), the per-principal keyring (identity + epoch keys), and the
// handler registry (capabilities, messages, events).
//
// A Client is created by Connect and used by Services and Agents built
// from it. Close shuts it down gracefully (endpoint.disconnect, drain, no
// goroutine leaks).
type Client struct {
	cfg     Config
	kr      *keyring
	rest    *restClient
	schemas *schemaCache

	// heartbeatInterval is the liveness cadence captured at Connect time
	// (from the package-level var, which tests may shorten). It is immutable
	// for the client's lifetime, so the heartbeat goroutine reads this field
	// (not the global) — no data race.
	heartbeatInterval time.Duration

	// identity (stable across reconnects; persisted in the keyring)
	identityPriv []byte // X25519 private key (raw 32 bytes) — NEVER logged
	identityPub  []byte // X25519 public key (raw 32 bytes)

	// dynamic identity (set at auth_ok)
	principalID atomicString
	endpointID  atomicString
	tenantID    atomicString
	credential  atomic.Value // string: current principal credential

	// connection
	connMu    sync.Mutex
	cur       *conn
	connected atomic.Bool

	// dispatch (backpressure)
	dispatchQueue  chan transport.Envelope
	sem            chan struct{} // handler slots
	inflightCount  int64         // atomic: accepted-but-unfinished deliveries
	endpointNameMu sync.Mutex
	endpointName   string

	// duplicate-delivery safety (survive reconnects — Client level)
	seenDeliveries     *lruSet // deliveryIDs + messageIDs
	seenInvocations    *lruSet // invocationIDs (completed)
	delivMu            sync.Mutex
	inflightDeliveries map[string]struct{}

	// invocations (target side; survive reconnects within server TTL)
	invMu                sync.Mutex
	inflightInvocations  map[string]*asyncInvocation
	completedInvocations *lruMap // invocationID → completedInvocation
	pendingMu            sync.Mutex
	pendingResults       map[string]completedInvocation // result send failed on a dead session
	connGeneration       atomic.Int64                   // bumped at every auth_ok

	// handlers + capabilities
	handlerMu     sync.RWMutex
	caps          map[string]capRegistration
	msgHandler    func(ctx context.Context, m *Message) error
	eventHandlers map[string]eventHandler

	// participants
	participantMu sync.Mutex
	services      []*Service
	agents        []*Agent

	// crypto enrollment state (pendingMu is shared with pendingResults)
	cryptoMu          sync.Mutex
	cryptoReadySet    map[string]bool
	pendingChallenges map[string]EndpointCryptoChallengePayload

	// cached identity (tenant id for AADs, memberships for agents)
	identityMu sync.Mutex
	identity   *Identity

	// lifecycle
	closed      atomic.Bool
	closeCh     chan struct{}
	wg          sync.WaitGroup // supervisor + dispatcher
	firstAuthOK chan struct{}
	firstErrCh  chan error // fatal (credential dead)
}

// Connect authenticates with the principal credential, runs
// endpoint.register, waits for endpoint.auth_ok, and starts the heartbeat +
// reconnect loops.
//
// Credential exchange: with an ACTIVATION credential (pgn_act_v1_...) the
// server returns the durable endpoint credential in auth_ok (activation
// only); the SDK persists it to the keyring and uses it on all later
// connects (the activation credential is one-time server-side). A later
// Connect that still presents the consumed activation credential
// transparently falls back to the stored durable credential.
//
// Connect blocks until the first auth_ok (or ctx/fatal error). The
// connection then runs for the lifetime of the Client: drops are
// reconnected with exponential backoff + jitter (1s..30s), the endpoint
// re-registers, and durable work (deliveries, invocations, subscriptions)
// resumes from the server.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	stateDir, err := cfg.stateDir()
	if err != nil {
		return nil, err
	}
	kr, err := newKeyring(stateDir)
	if err != nil {
		return nil, err
	}
	priv, principalID, err := kr.loadOrCreateIdentity(cfg.Credential)
	if err != nil {
		return nil, err
	}
	pub, err := x25519Public(priv)
	if err != nil {
		return nil, err
	}
	c := &Client{
		cfg:                  cfg,
		kr:                   kr,
		schemas:              newSchemaCache(),
		heartbeatInterval:    heartbeatInterval,
		identityPriv:         priv,
		identityPub:          pub,
		dispatchQueue:        make(chan transport.Envelope, dispatchQueueCap),
		sem:                  make(chan struct{}, handlerSlotCap),
		seenDeliveries:       newLRUSet(DefaultSeenCap),
		seenInvocations:      newLRUSet(DefaultSeenCap),
		inflightDeliveries:   map[string]struct{}{},
		inflightInvocations:  map[string]*asyncInvocation{},
		completedInvocations: newLRUMap(DefaultSeenCap),
		pendingResults:       map[string]completedInvocation{},
		caps:                 map[string]capRegistration{},
		eventHandlers:        map[string]eventHandler{},
		cryptoReadySet:       map[string]bool{},
		pendingChallenges:    map[string]EndpointCryptoChallengePayload{},
		closeCh:              make(chan struct{}),
		firstAuthOK:          make(chan struct{}),
		firstErrCh:           make(chan error, 1),
	}
	c.credential.Store(cfg.Credential)
	c.rest = newRestClient(cfg.serverBase(), cfg.userAgent(), func() string { return c.credential.Load().(string) })
	if principalID != "" {
		c.principalID.Store(principalID)
	}

	c.wg.Add(2)
	go c.supervisor()
	go c.dispatcher()

	// Wait for the first auth_ok (or a fatal error / ctx).
	var id *Identity
	select {
	case <-c.firstAuthOK:
		// Best-effort identity fetch: the tenant id feeds the AADs, the
		// memberships feed agent network resolution.
		id, _ = c.fetchIdentity(ctx)
	case err := <-c.firstErrCh:
		_ = c.Close()
		return nil, err
	case <-ctx.Done():
		_ = c.Close()
		return nil, ctx.Err()
	}
	if id != nil {
		c.setIdentity(id)
	}
	return c, nil
}

// fetchIdentity does GET /auth/principal/me with a few retries (the first
// call races the server's post-register bookkeeping).
func (c *Client) fetchIdentity(ctx context.Context) (*Identity, error) {
	var lastErr error
	for i := 0; i < 3; i++ {
		id, err := c.rest.whoAmI(ctx)
		if err == nil {
			return id, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil, lastErr
}

func (c *Client) setIdentity(id *Identity) {
	c.identityMu.Lock()
	c.identity = id
	c.identityMu.Unlock()
	if id.TenantID != "" {
		c.tenantID.Store(id.TenantID)
	}
}

// cachedIdentity returns the last fetched identity (nil before the first
// successful fetch).
func (c *Client) cachedIdentity() *Identity {
	c.identityMu.Lock()
	defer c.identityMu.Unlock()
	return c.identity
}

// Close gracefully shuts the client down: endpoint.disconnect (best
// effort), connection close, loop drain. No goroutine leaks. Running
// handler goroutines are user code: they finish on their own (their acks
// fail cleanly once closed); async invocations not yet completed fail with
// a clear error on Complete.
func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(c.closeCh)
	c.connMu.Lock()
	pc := c.cur
	c.connMu.Unlock()
	if pc != nil {
		_ = pc.send(transport.MsgEndpointDisconnect, transport.EndpointDisconnectPayload{})
		_ = pc.ws.Close()
	}
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("sdk: close timed out draining loops")
	}
}

// checkOpen fails fast on a closed client.
func (c *Client) checkOpen() error {
	if c.closed.Load() {
		return ErrClosed
	}
	return nil
}

// PrincipalID returns the authenticated principal's id ("" before the
// first auth_ok).
func (c *Client) PrincipalID() string { return c.principalID.Load() }

// EndpointID returns this endpoint's id ("" before the first auth_ok).
func (c *Client) EndpointID() string { return c.endpointID.Load() }

// --- identity / discovery / operations ---------------------------------------

// WhoAmI returns the principal's identity + memberships (live REST call).
func (c *Client) WhoAmI(ctx context.Context) (*Identity, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	id, err := c.rest.whoAmI(ctx)
	if err != nil {
		return nil, err
	}
	id.EndpointID = c.endpointID.Load()
	c.setIdentity(id)
	return id, nil
}

// Networks returns the networks the principal is an active member of, with
// this endpoint's crypto enrollment state per network.
func (c *Client) Networks(ctx context.Context) ([]NetworkInfo, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	nets, err := c.rest.networks(ctx)
	if err != nil {
		return nil, err
	}
	for i := range nets {
		nets[i].CryptoReady = c.cryptoReady(nets[i].ID)
	}
	return nets, nil
}

// Search discovers participants in a network (GET /networks/{id}/search).
// The returned cursor continues pagination (Query.Cursor).
func (c *Client) Search(ctx context.Context, networkID string, q Query) ([]SearchResult, string, error) {
	if err := c.checkOpen(); err != nil {
		return nil, "", err
	}
	if networkID == "" {
		return nil, "", errors.New("sdk: networkID is required")
	}
	return c.rest.search(ctx, networkID, q)
}

// PublishEvent publishes an event to a network. The payload is encrypted
// client-side (object type event_payload) — the control plane stores and
// relays ciphertext only. Returns the event id.
//
// The payload is DATA: it is delivered verbatim to subscribers, who must
// treat it as untrusted.
func (c *Client) PublishEvent(ctx context.Context, networkID string, ev Event) (string, error) {
	if err := c.checkOpen(); err != nil {
		return "", err
	}
	if networkID == "" {
		return "", errors.New("sdk: networkID is required")
	}
	if ev.Type == "" {
		return "", errors.New("sdk: event Type is required")
	}
	id := ev.ID
	if id == "" {
		id = newObjectID()
	}
	payload := ev.Payload
	if len(payload) == 0 {
		payload = emptyJSONPayload
	}
	env, aad, err := c.encryptObject(networkID, e2ee.ObjectTypeEventPayload, id, c.principalID.Load(), ev.TargetPrincipalID, payload)
	if err != nil {
		return "", err
	}
	req := restEventRequest{
		Type:              ev.Type,
		SchemaVersion:     ev.SchemaVersion,
		TargetPrincipalID: ev.TargetPrincipalID,
		ResourceID:        ev.ResourceID,
		CapabilityID:      ev.CapabilityID,
		Envelope:          env,
		AAD:               aad,
		EventID:           id,
		CorrelationID:     ev.CorrelationID,
		CausationID:       ev.CausationID,
	}
	return c.rest.publishEvent(ctx, networkID, req)
}

// Subscribe creates an event subscription in a network. Returns the
// subscription id.
func (c *Client) Subscribe(ctx context.Context, networkID string, s Subscription) (string, error) {
	if err := c.checkOpen(); err != nil {
		return "", err
	}
	if networkID == "" {
		return "", errors.New("sdk: networkID is required")
	}
	if s.EventPattern == "" {
		return "", errors.New("sdk: Subscription.EventPattern is required")
	}
	req := restSubscriptionRequest{
		EventPattern:        s.EventPattern,
		ProducerPrincipalID: s.ProducerPrincipalID,
		TargetPrincipalID:   s.TargetPrincipalID,
		ResourceID:          s.ResourceID,
		CapabilityID:        s.CapabilityID,
		DeliveryMode:        s.DeliveryMode,
		Enabled:             s.Enabled,
	}
	return c.rest.createSubscription(ctx, networkID, req)
}

// Unsubscribe deletes an event subscription.
func (c *Client) Unsubscribe(ctx context.Context, networkID, subID string) error {
	if err := c.checkOpen(); err != nil {
		return err
	}
	if networkID == "" || subID == "" {
		return errors.New("sdk: networkID and subID are required")
	}
	return c.rest.deleteSubscription(ctx, networkID, subID)
}

// Send sends a durable message in a network. The parts are encrypted
// client-side (object type message). Returns the message id.
func (c *Client) Send(ctx context.Context, m OutgoingMessage) (string, error) {
	if err := c.checkOpen(); err != nil {
		return "", err
	}
	if m.NetworkID == "" {
		return "", errors.New("sdk: OutgoingMessage.NetworkID is required")
	}
	if len(m.Parts) == 0 {
		return "", errors.New("sdk: OutgoingMessage.Parts is required")
	}
	kind := m.Kind
	if kind == "" {
		kind = string(domain.MessageKindAsk)
	}
	id := newObjectID()
	recipient := m.RecipientPrincipalID
	if recipient == "" {
		recipient = m.RecipientGroupID
	}
	partsJSON, err := json.Marshal(m.Parts)
	if err != nil {
		return "", err
	}
	env, aad, err := c.encryptObject(m.NetworkID, e2ee.ObjectTypeMessage, id, c.principalID.Load(), recipient, partsJSON)
	if err != nil {
		return "", err
	}
	req := restMessageRequest{
		ID:                   id,
		ThreadID:             m.ThreadID,
		RecipientPrincipalID: m.RecipientPrincipalID,
		RecipientGroup:       m.RecipientGroupID,
		Kind:                 kind,
		Envelope:             env,
		AAD:                  aad,
	}
	return c.rest.sendMessage(ctx, m.NetworkID, req)
}

// Invoke calls a capability on another principal and waits for the result
// (synchronous form of a durable invocation).
//
// The invocation is durable server-side: it survives this client's
// disconnects. Invoke validates the input against in.InputSchema (when
// set) BEFORE encryption, polls the invocation record until a terminal
// state (default 60s, in.Timeout), decrypts the output, and validates it
// against in.OutputSchema (when set). On timeout the invocation keeps
// running server-side: use in.ID to poll later.
func (c *Client) Invoke(ctx context.Context, in Invocation) (*Invocation, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if in.NetworkID == "" {
		return nil, errors.New("sdk: Invocation.NetworkID is required")
	}
	if in.TargetPrincipalID == "" {
		return nil, errors.New("sdk: Invocation.TargetPrincipalID is required")
	}
	if in.CapabilityID == "" {
		return nil, errors.New("sdk: Invocation.CapabilityID is required")
	}
	id := in.ID
	if id == "" {
		id = newObjectID()
	}
	inputJSON, err := json.Marshal(in.Input)
	if err != nil {
		return nil, fmt.Errorf("sdk: encode invocation input: %w", err)
	}
	// Caller-side input validation (north-star §76): before encryption.
	if len(in.InputSchema) > 0 {
		if err := c.schemas.validate(in.InputSchema, inputJSON); err != nil {
			return nil, err
		}
	}
	env, aad, err := c.encryptObject(in.NetworkID, e2ee.ObjectTypeInvocationInput, id, c.principalID.Load(), in.TargetPrincipalID, inputJSON)
	if err != nil {
		return nil, err
	}
	req := restInvocationRequest{
		TargetPrincipalID: in.TargetPrincipalID,
		CapabilityID:      in.CapabilityID,
		CapabilityVersion: in.CapabilityVersion,
		Envelope:          env,
		AAD:               aad,
		InvocationID:      id,
		IdempotencyKey:    in.IdempotencyKey,
		CorrelationID:     in.CorrelationID,
		CausationID:       in.CausationID,
	}
	rec, err := c.rest.createInvocation(ctx, in.NetworkID, req)
	if err != nil {
		return nil, err
	}
	in.ID = rec.ID
	in.State = rec.State
	in.CallerPrincipalID = "" // caller side: not meaningful

	timeout := in.Timeout
	if timeout <= 0 {
		timeout = DefaultInvokeTimeout
	}
	deadline := time.Now().Add(timeout)
	poll, err := c.awaitInvocation(ctx, in.NetworkID, in.ID, deadline)
	if poll != nil {
		in.State = poll.state
		switch in.State {
		case "completed":
			if poll.protectedOutput != nil {
				plain, err := c.decryptObject(in.NetworkID, poll.protectedOutput.Envelope, poll.protectedOutput.AAD)
				if err != nil {
					in.Err = err
					return &in, err
				}
				if len(in.OutputSchema) > 0 {
					if err := c.schemas.validate(in.OutputSchema, plain); err != nil {
						in.Err = err
						return &in, err
					}
				}
				var out any
				if err := json.Unmarshal(plain, &out); err != nil {
					in.Output = plain // not JSON-decodable: expose raw
				} else {
					in.Output = out
				}
			}
			in.PublicResultCode = poll.publicResultCode
			in.UsageMetadata = poll.usageMetadata
			return &in, nil
		case "failed":
			detail := poll.publicResultCode
			if poll.protectedError != nil {
				if plain, err := c.decryptObject(in.NetworkID, poll.protectedError.Envelope, poll.protectedError.AAD); err == nil && len(plain) > 0 {
					detail = string(plain)
				}
			}
			in.Err = fmt.Errorf("sdk: invocation %s failed: %s", in.ID, detail)
			in.PublicResultCode = poll.publicResultCode
			return &in, in.Err
		case "cancelled":
			in.Err = fmt.Errorf("sdk: invocation %s was cancelled", in.ID)
			return &in, in.Err
		}
	}
	// awaitInvocation returned (nil, err): timeout, ctx, or REST error.
	in.Err = err
	return &in, err
}

// invocationPoll is a terminal invocation record (the poll's outcome).
type invocationPoll struct {
	state            string
	protectedOutput  *encryptedField
	protectedError   *encryptedField
	publicResultCode string
	usageMetadata    map[string]any
}

// awaitInvocation polls the invocation record until terminal, the deadline
// passes, or ctx is done. It returns (nil, err) on timeout/ctx/error and
// (poll, nil) with the terminal record otherwise.
func (c *Client) awaitInvocation(ctx context.Context, networkID, invocationID string, deadline time.Time) (*invocationPoll, error) {
	poll := 250 * time.Millisecond
	for {
		if time.Now().After(deadline) {
			return nil, ErrInvocationTimeout
		}
		wait := poll
		if time.Now().Add(wait).After(deadline) {
			wait = time.Until(deadline)
		}
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		rec, err := c.rest.getInvocation(ctx, networkID, invocationID)
		if err != nil {
			return nil, err
		}
		switch rec.State {
		case "completed", "failed", "cancelled":
			return &invocationPoll{
				state:            rec.State,
				protectedOutput:  rec.ProtectedOutput,
				protectedError:   rec.ProtectedError,
				publicResultCode: rec.PublicResultCode,
				usageMetadata:    rec.UsageMetadata,
			}, nil
		}
		// Back off the poll: 250ms → 500ms → 1s → 2s (cap).
		if poll < 2*time.Second {
			poll *= 2
		}
	}
}

// --- participants ---------------------------------------------------------------

// Service starts building a service participant (a principal that serves
// capability invocations). The name is the endpoint's display name (it
// rides in endpoint.register; identity is the principal's, not the name's).
func (c *Client) Service(name string) *Service {
	s := &Service{client: c, name: name, subs: &eventSubs{client: c, kind: "service", name: name, subscribed: map[string]bool{}}}
	c.participantMu.Lock()
	c.services = append(c.services, s)
	c.participantMu.Unlock()
	c.endpointNameMu.Lock()
	if c.endpointName == "" {
		c.endpointName = name
	}
	c.endpointNameMu.Unlock()
	return s
}

// Agent starts building an agent participant (a principal that receives
// messages/events and serves capabilities). The agent's default network is
// resolved at Run: SetNetwork pins it, otherwise the principal's single
// active membership is used.
func (c *Client) Agent(name string) *Agent {
	a := &Agent{client: c, name: name, subs: &eventSubs{client: c, kind: "agent", name: name, subscribed: map[string]bool{}}}
	c.participantMu.Lock()
	c.agents = append(c.agents, a)
	c.participantMu.Unlock()
	c.endpointNameMu.Lock()
	if c.endpointName == "" {
		c.endpointName = name
	}
	c.endpointNameMu.Unlock()
	return a
}

// Network returns a per-network operations handle (publish/invoke/
// subscribe/search/send scoped to one network).
func (c *Client) Network(_ context.Context, networkID string) *Network {
	return &Network{client: c, id: networkID}
}

// --- connection supervision --------------------------------------------------------

// wsURL builds the endpoint WebSocket URL from the server base URL
// (http→ws, https→wss), path /wss/endpoints (the endpoint WS is registered
// OUTSIDE the /api/v1 middleware — it authenticates with the principal
// credential, not the user token).
func (c *Client) wsURL() string {
	base := c.cfg.serverBase()
	u, err := url.Parse(base)
	if err != nil {
		return base + "/wss/endpoints"
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/wss/endpoints"
	return u.String()
}

// supervisor is the reconnect loop: dial → register → auth_ok → live →
// (drop) → backoff → repeat. It exits on Close or a fatal credential
// error (a dead credential cannot be fixed by retrying).
func (c *Client) supervisor() {
	defer c.wg.Done()
	attempt := 0
	for {
		if c.closed.Load() {
			return
		}
		err := c.connectOnce()
		if c.closed.Load() {
			return
		}
		if err != nil {
			if errors.Is(err, ErrCredentialDead) {
				// Fallback: the presented credential may be a CONSUMED
				// activation credential — the keyring holds the durable
				// one for the same principal.
				current := c.credential.Load().(string)
				if stored, kerr := c.kr.CredentialForCredential(current); kerr == nil && stored != "" && stored != current {
					c.credential.Store(stored)
					continue // retry immediately with the durable credential
				}
				c.firstErr(err)
				return
			}
			// Transient: exponential backoff + jitter (1s..30s cap).
			delay := nextBackoff(attempt, rand.Float64)
			attempt++
			select {
			case <-c.closeCh:
				return
			case <-time.After(delay):
			}
			continue
		}
		// A session completed (the connection dropped). Reset the backoff:
		// the next failure starts at the 1s base again.
		attempt = 0
	}
}

// firstErr reports a fatal error to Connect (once).
func (c *Client) firstErr(err error) {
	select {
	case c.firstErrCh <- err:
	default:
	}
}

// connectOnce runs one connection session: dial, register, wait for
// auth_ok, go live, wait for the connection to die. It returns nil when
// the session ended (the supervisor decides about retrying) or an error
// when the session failed before auth_ok.
func (c *Client) connectOnce() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+c.credential.Load().(string))
	hdr.Set("User-Agent", c.cfg.userAgent())
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	ws, resp, err := dialer.DialContext(ctx, c.wsURL(), hdr)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				return fmt.Errorf("%w: dial %s (http %d)", ErrCredentialDead, c.wsURL(), resp.StatusCode)
			}
			return fmt.Errorf("sdk: dial: %v (http %d)", err, resp.StatusCode)
		}
		return fmt.Errorf("sdk: dial: %w", err)
	}
	pc := &conn{
		ws:     ws,
		c:      c,
		authOK: make(chan transport.EndpointAuthOKPayload, 1),
		dead:   make(chan struct{}),
	}
	// Make this the current conn NOW (before the read loop starts), so that
	// setup-time messages processed by the read loop — the crypto enrollment
	// (endpoint.crypto_challenge → endpoint.crypto_prove) — can send their
	// responses on this conn via c.send. The conn is dial-complete; auth_ok
	// is still pending, but sending on a dialed conn is safe. (c.connected
	// stays false until auth_ok, so user operations are unaffected.)
	c.connMu.Lock()
	c.cur = pc
	c.connMu.Unlock()
	// Register (carries the crypto identity + advertised capabilities).
	if err := pc.send(transport.MsgEndpointRegister, c.registerPayload()); err != nil {
		ws.Close()
		c.connMu.Lock()
		if c.cur == pc {
			c.cur = nil
		}
		c.connMu.Unlock()
		return fmt.Errorf("sdk: send endpoint.register: %w", err)
	}
	go pc.readLoop()
	// Wait for auth_ok.
	var ok transport.EndpointAuthOKPayload
	select {
	case ok = <-pc.authOK:
	case <-pc.dead:
		ws.Close()
		return errors.New("sdk: connection closed before endpoint.auth_ok")
	case <-c.closeCh:
		ws.Close()
		return ErrClosed
	}
	if err := c.handleAuthOK(ok); err != nil {
		ws.Close()
		// A keyring persistence failure must not loop forever: surface it
		// as fatal (the operator must fix the state dir).
		c.firstErr(err)
		return err
	}
	// Promote to live.
	c.connMu.Lock()
	c.cur = pc
	c.connMu.Unlock()
	c.connected.Store(true)
	go pc.heartbeat()
	// Agents resume subscriptions (server is the source of truth).
	c.onLive()
	// Wait for the session to end.
	<-pc.dead
	c.connected.Store(false)
	c.connMu.Lock()
	if c.cur == pc {
		c.cur = nil
	}
	c.connMu.Unlock()
	return nil
}

// registerPayload builds the endpoint.register payload (the current
// capability set + crypto identity).
func (c *Client) registerPayload() transport.EndpointRegisterPayload {
	c.endpointNameMu.Lock()
	name := c.endpointName
	c.endpointNameMu.Unlock()
	return transport.EndpointRegisterPayload{
		EndpointName: name,
		PublicKey:    base64.StdEncoding.EncodeToString(c.identityPub),
		SDKVersion:   Version,
		Capabilities: c.capabilities(),
	}
}

// capabilities returns the registered capability descriptors.
func (c *Client) capabilities() []Capability {
	c.handlerMu.RLock()
	defer c.handlerMu.RUnlock()
	out := make([]Capability, 0, len(c.caps))
	for _, reg := range c.caps {
		out = append(out, reg.capability)
	}
	return out
}

// sendRegister re-sends endpoint.register on the live connection (an
// idempotent upsert): capability changes after the initial register must
// reach the server without a full reconnect.
func (c *Client) sendRegister() error {
	if !c.connected.Load() {
		return nil // the next (re)connect carries it
	}
	return c.send(transport.MsgEndpointRegister, c.registerPayload())
}

// handleAuthOK processes endpoint.auth_ok: identity, the activation →
// durable credential exchange, and keyring persistence.
func (c *Client) handleAuthOK(p transport.EndpointAuthOKPayload) error {
	if p.ProtocolVersion != transport.ProtocolVersion {
		return fmt.Errorf("sdk: protocol mismatch: server speaks %d, SDK speaks %d — update the SDK", p.ProtocolVersion, transport.ProtocolVersion)
	}
	if _, err := domain.ParseID(p.PrincipalID); err != nil {
		return fmt.Errorf("sdk: server returned a malformed principalId: %w", err)
	}
	c.principalID.Store(p.PrincipalID)
	c.endpointID.Store(p.EndpointID)
	if p.Credential != "" {
		// Activation exchange: the server returned the durable endpoint
		// credential (activation only). Use it from now on.
		c.credential.Store(p.Credential)
	}
	if err := c.kr.PersistIdentity(p.PrincipalID, c.credential.Load().(string), c.identityPriv); err != nil {
		return fmt.Errorf("sdk: persist keyring: %w", err)
	}
	// Index the PRESENTED credential too (the one-time activation
	// credential, when this was an activation exchange): a later Connect
	// that still presents the consumed activation must resolve the
	// principal and fall back to the stored durable credential.
	if c.cfg.Credential != "" && c.cfg.Credential != c.credential.Load().(string) {
		if err := c.kr.IndexCredential(c.cfg.Credential, p.PrincipalID); err != nil {
			return fmt.Errorf("sdk: persist keyring: %w", err)
		}
	}
	c.connGeneration.Add(1)
	select {
	case <-c.firstAuthOK:
	default:
		close(c.firstAuthOK)
	}
	return nil
}

// onLive runs per-connection hooks after auth_ok: resume participant
// subscriptions (server is the source of truth) and re-send invocation
// results whose send failed on the dead session.
func (c *Client) onLive() {
	c.flushPendingResults()
	c.participantMu.Lock()
	services := make([]*Service, len(c.services))
	copy(services, c.services)
	agents := make([]*Agent, len(c.agents))
	copy(agents, c.agents)
	c.participantMu.Unlock()
	for _, s := range services {
		go s.ensureSubscriptions()
	}
	for _, a := range agents {
		go a.ensureSubscriptions()
	}
}

// send sends one envelope on the live connection (ErrNotConnected when
// there is none — the caller decides whether to retry).
func (c *Client) send(msgType string, payload any) error {
	c.connMu.Lock()
	pc := c.cur
	c.connMu.Unlock()
	if pc == nil {
		return ErrNotConnected
	}
	return pc.send(msgType, payload)
}

// x25519Public derives the public key from a raw X25519 private key.
func x25519Public(priv []byte) ([]byte, error) {
	sk, err := hpkeKEM().UnmarshalBinaryPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("sdk: x25519 private key: %w", err)
	}
	pub := sk.Public()
	return pub.MarshalBinary()
}

// emptyJSONPayload is the payload for empty events (valid JSON).
var emptyJSONPayload = []byte("{}")
