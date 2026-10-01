package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

// lruMap is a bounded last-recently-used map (values), for the completed-
// invocation cache (re-send the stored result on redelivery).
const (
	MaxInvocationResultBytes     = 256 << 10
	MaxInvocationResultWireBytes = transport.EndpointInvocationResultMaxBytes
	MaxPendingInvocationBytes    = 32 << 20
	MaxCompletedInvocationBytes  = 8 << 20
	MaxActiveInvocations         = MaxPendingInvocationBytes / MaxInvocationResultWireBytes
)

type lruMap struct {
	maxBytes int
	bytes    int
	sizes    map[string]int
	mu       sync.Mutex
	cap      int
	items    map[string]any
	order    []string
}

func newLRUMap(cap int) *lruMap {
	if cap <= 0 {
		cap = DefaultSeenCap
	}
	return &lruMap{cap: cap, items: map[string]any{}, maxBytes: MaxCompletedInvocationBytes, sizes: map[string]int{}}
}

// set inserts/updates key.
func (m *lruMap) set(key string, v any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	size := 1
	if result, ok := v.(completedInvocation); ok {
		size = result.encodedBytes
		if size == 0 {
			raw, _ := json.Marshal(result.result)
			size = len(raw)
		}
	}
	m.bytes -= m.sizes[key]
	m.sizes[key] = size
	m.bytes += size
	if _, ok := m.items[key]; ok {
		m.items[key] = v
		m.touchLocked(key)
	} else {
		m.items[key] = v
		m.order = append(m.order, key)
	}
	for len(m.order) > m.cap || m.bytes > m.maxBytes {
		old := m.order[0]
		m.order = m.order[1:]
		m.bytes -= m.sizes[old]
		delete(m.sizes, old)
		delete(m.items, old)
	}
}

func (m *lruMap) touchLocked(key string) {
	for i, k := range m.order {
		if k == key {
			m.order = append(m.order[:i], m.order[i+1:]...)
			m.order = append(m.order, key)
			return
		}
	}
}

// get returns the value for key (ok = present).
func (m *lruMap) get(key string) (any, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.items[key]
	if ok {
		m.touchLocked(key)
	}
	return v, ok
}

// --- capability registry --------------------------------------------------------

// capRegistration is one registered capability: its descriptor + handler.
type capRegistration struct {
	capability Capability
	handler    CapHandler    // untyped (nil for typed-only)
	typed      reflect.Value // typed handler func (nil for untyped)
	inputType  reflect.Type  // typed handler's input type
}

// eventHandler is one OnEvent registration.
type eventHandler struct {
	pattern string
	fn      func(ctx context.Context, e *Event) error
}

// registerCapability registers (or updates) a capability. When no handler
// is given and one exists, the existing handler is kept (Capability()
// updates the descriptor). A live connection is re-registered (idempotent
// upsert) so the server's capability view stays current.
func (c *Client) registerCapability(cap Capability, h CapHandler, typed reflect.Value, inputType reflect.Type) error {
	if cap.ID == "" {
		return errors.New("sdk: capability ID is required")
	}
	if cap.Version <= 0 {
		cap.Version = 1
	}
	c.handlerMu.Lock()
	old, exists := c.caps[cap.ID]
	// Merge with the existing descriptor (if any): Handle/HandleT advertise
	// a MINIMAL descriptor (ID + Version), so a later Handle must not clobber
	// a previously set full descriptor (schemas, name, tags) — and a later
	// Capability must not clobber a previously registered handler. The new
	// descriptor's non-empty fields win; empty fields keep the old value.
	// Call order (Capability then Handle, or Handle then Capability) is
	// therefore irrelevant.
	base := cap
	if exists {
		if base.Name == "" {
			base.Name = old.capability.Name
		}
		if base.Description == "" {
			base.Description = old.capability.Description
		}
		if len(base.InputSchema) == 0 {
			base.InputSchema = old.capability.InputSchema
		}
		if len(base.OutputSchema) == 0 {
			base.OutputSchema = old.capability.OutputSchema
		}
		if len(base.Tags) == 0 {
			base.Tags = old.capability.Tags
		}
		if len(base.Metadata) == 0 {
			base.Metadata = old.capability.Metadata
		}
	}
	// Validate before changing the registry or disconnecting a working endpoint.
	// A malformed RawMessage otherwise makes every future registration fail.
	if _, err := json.Marshal(base); err != nil {
		c.handlerMu.Unlock()
		return fmt.Errorf("sdk: invalid capability descriptor: %w", err)
	}
	for _, schema := range []json.RawMessage{base.InputSchema, base.OutputSchema} {
		if _, err := c.schemas.compile(schema); err != nil {
			c.handlerMu.Unlock()
			return err
		}
	}
	reg := capRegistration{capability: base, handler: h, typed: typed, inputType: inputType}
	// A zero (invalid) reflect.Value means "no typed handler provided".
	// IsValid() is used (not IsZero(), which panics on a zero Value).
	if (h == nil && !typed.IsValid()) && exists {
		reg.handler = old.handler
		reg.typed = old.typed
		reg.inputType = old.inputType
	}
	c.caps[cap.ID] = reg
	c.capsRevision++
	c.handlerMu.Unlock()
	return c.sendRegister()
}

// matchEventPattern matches an event type against a subscription pattern:
// exact, or a single-level suffix wildcard ("task.*" matches
// "task.created" but NOT "task.sub.created").
func matchEventPattern(pattern, eventType string) bool {
	if pattern == eventType {
		return true
	}
	if !strings.HasSuffix(pattern, ".*") {
		return false
	}
	prefix := pattern[:len(pattern)-1] // keep the dot: "task."
	if !strings.HasPrefix(eventType, prefix) {
		return false
	}
	rest := eventType[len(prefix):]
	return !strings.Contains(rest, ".")
}

// --- message delivery -------------------------------------------------------------

// handleMessageDeliver processes one durable message delivery.
//
// Ack semantics (plan D9): the message is ALWAYS acked — delivery is not
// the handler's concern. The handler runs (if any) for its side effects;
// its error (or panic) does not withhold the ack. A redelivered message
// (uncertain ack, reconnect) is re-acked without re-dispatching.
func (c *Client) handleMessageDeliver(env transport.Envelope) {
	var p transport.EndpointMessageDeliverPayload
	if err := env.DecodePayload(&p); err != nil {
		return
	}
	ack := func() {
		_ = c.send(transport.MsgEndpointMessageAcked, transport.EndpointMessageAckedPayload{MessageID: p.MessageID})
	}
	// Duplicate: re-ack, no re-dispatch.
	if c.seenDeliveries.Contains(p.MessageID) {
		ack()
		return
	}
	c.delivMu.Lock()
	if _, inflight := c.inflightDeliveries[p.MessageID]; inflight {
		c.delivMu.Unlock()
		return // already being processed (its ack will go out)
	}
	c.inflightDeliveries[p.MessageID] = struct{}{}
	c.delivMu.Unlock()

	// Decrypt (fail → no ack: the server retries; a missing epoch key may
	// land via enrollment in the meantime).
	var m Message
	if p.Envelope != nil && p.AAD != nil {
		plain, err := c.decryptObject(p.NetworkID, *p.Envelope, *p.AAD)
		if err != nil {
			c.delivMu.Lock()
			delete(c.inflightDeliveries, p.MessageID)
			c.delivMu.Unlock()
			return
		}
		m.Parts, err = domain.DecodeMessageContent(plain)
		if err != nil {
			c.delivMu.Lock()
			delete(c.inflightDeliveries, p.MessageID)
			c.delivMu.Unlock()
			return // malformed content stays durable; never ACK an empty substitute
		}
	}
	m.ID = p.MessageID
	m.NetworkID = p.NetworkID
	m.ThreadID = p.ThreadID
	m.Kind = p.Kind
	m.SenderPrincipalID = p.SenderPrincipalID

	// Run the handler (if any); a panic is contained and does not withhold
	// the ack (always-ack semantics).
	c.handlerMu.RLock()
	h := c.msgHandler
	c.handlerMu.RUnlock()
	if h != nil {
		func() {
			defer func() { _ = recover() }()
			_ = h(context.Background(), &m)
		}()
	}

	// Mark seen + ack (always).
	c.delivMu.Lock()
	delete(c.inflightDeliveries, p.MessageID)
	c.seenDeliveries.Add(p.MessageID)
	c.delivMu.Unlock()
	ack()
}

// --- event delivery ------------------------------------------------------------------

// handleEventDeliver processes one event delivery.
//
// Ack semantics (plan D9): event_ack AFTER the handler returns nil. A
// handler error (or panic) → NO ack → the server retries with backoff
// (capped). No handler registered → the delivery is processed (nothing to
// do) and acked. A redelivered delivery (uncertain ack, reconnect) is
// re-acked without re-dispatching.
func (c *Client) handleEventDeliver(env transport.Envelope) {
	var p transport.EndpointEventDeliverPayload
	if err := env.DecodePayload(&p); err != nil || p.DispatchID == "" {
		return
	}
	ack := func() {
		_ = c.send(transport.MsgEndpointEventAck, transport.EndpointEventAckPayload{DeliveryID: p.DeliveryID, EventID: p.EventID, DispatchID: p.DispatchID})
	}
	finish := func(ackIt bool) {
		c.delivMu.Lock()
		delete(c.inflightDeliveries, p.DeliveryID)
		if ackIt {
			c.seenDeliveries.Add(p.DeliveryID)
		}
		c.delivMu.Unlock()
		if ackIt {
			ack()
		}
	}
	// Duplicate: re-ack, no re-dispatch.
	if c.seenDeliveries.Contains(p.DeliveryID) {
		ack()
		return
	}
	c.delivMu.Lock()
	if _, inflight := c.inflightDeliveries[p.DeliveryID]; inflight {
		c.delivMu.Unlock()
		return
	}
	c.inflightDeliveries[p.DeliveryID] = struct{}{}
	c.delivMu.Unlock()

	// Decrypt (fail → no ack: the server retries).
	var ev Event
	if p.Envelope != nil && p.AAD != nil {
		plain, err := c.decryptObject(p.NetworkID, *p.Envelope, *p.AAD)
		if err != nil {
			finish(false)
			return
		}
		ev.Payload = plain
	}
	ev.ID = p.EventID
	ev.NetworkID = p.NetworkID
	ev.Type = p.EventType
	ev.ProducerPrincipalID = p.ProducerPrincipalID

	// Route to matching handlers.
	c.handlerMu.RLock()
	var handlers []eventHandler
	for _, h := range c.eventHandlers {
		if matchEventPattern(h.pattern, ev.Type) {
			handlers = append(handlers, h)
		}
	}
	c.handlerMu.RUnlock()
	if len(handlers) == 0 {
		finish(true) // nothing to do: processed
		return
	}
	var firstErr error
	for _, h := range handlers {
		func() {
			defer func() {
				if r := recover(); r != nil && firstErr == nil {
					firstErr = fmt.Errorf("sdk: event handler panic: %v", r)
				}
			}()
			if err := h.fn(context.Background(), &ev); err != nil && firstErr == nil {
				firstErr = err
			}
		}()
	}
	finish(firstErr == nil)
}

// --- invocation dispatch ----------------------------------------------------------------

// completedInvocation is a finished invocation's result, kept for
// redelivery re-send (the server may re-dispatch after an uncertain
// failure; the result is idempotent).
type completedInvocation struct {
	result       transport.EndpointInvocationResultPayload
	generation   int64
	retryAt      time.Time
	attempts     int
	encodedBytes int
}

// asyncInvocation is the target-side control for one in-flight invocation
// (the Invocation.async back-reference).
type asyncInvocation struct {
	c               *Client
	inv             *Invocation
	networkID       string
	capabilityID    string
	dispatchID      string
	resultSubmitted atomic.Bool
	caller          string
	// acceptedGeneration is the connection generation at accept time: a
	// later generation means the session dropped after the accept (the
	// server may have given up on the invocation — Complete checks).
	acceptedGeneration int64
}

func (a *asyncInvocation) accept(ctx context.Context) error {
	if a.c.closed.Load() {
		return ErrClosed
	}
	a.c.invMu.Lock()
	defer a.c.invMu.Unlock()
	if _, ok := a.c.inflightInvocations[a.inv.ID]; !ok {
		return fmt.Errorf("sdk: invocation %s is not in flight (already completed or unknown)", a.inv.ID)
	}
	return nil
}

func (a *asyncInvocation) complete(ctx context.Context, result any, handlerErr error) error {
	if a.c.closed.Load() {
		return ErrClosed
	}
	a.c.invMu.Lock()
	if _, ok := a.c.inflightInvocations[a.inv.ID]; !ok {
		a.c.invMu.Unlock()
		return fmt.Errorf("sdk: invocation %s already completed or unknown", a.inv.ID)
	}
	a.c.invMu.Unlock()
	return a.c.completeInvocation(ctx, a, result, handlerErr)
}

// handleInvocationDispatch processes one capability invocation dispatch.
//
// Lifecycle: decrypt input → register in-flight → invocation_accept →
// handler (validate input first) → invocation_result. Duplicate dispatch
// of a completed invocation re-sends the stored result (idempotent); a
// duplicate of an in-flight invocation is skipped (no double execution —
// the in-flight one produces the result).
func (c *Client) handleInvocationDispatch(env transport.Envelope) {
	var p transport.EndpointInvocationDispatchPayload
	if err := env.DecodePayload(&p); err != nil || p.DispatchID == "" || p.Envelope == nil || p.AAD == nil {
		return
	}
	c.invMu.Lock()
	if comp, ok := c.completedInvocations.get(p.InvocationID); ok {
		c.invMu.Unlock()
		// Only the identical immutable dispatch can receive the cached outcome.
		if comp.(completedInvocation).result.DispatchID != p.DispatchID {
			return
		}
		_ = c.send(transport.MsgEndpointInvocationResult, comp.(completedInvocation).result)
		return
	}
	if c.seenInvocations != nil && c.seenInvocations.Contains(p.InvocationID) {
		c.invMu.Unlock()
		return
	}
	if _, ok := c.inflightInvocations[p.InvocationID]; ok {
		c.invMu.Unlock()
		return // in flight: it will produce the result
	}
	inv := &Invocation{
		ID:                p.InvocationID,
		NetworkID:         p.NetworkID,
		CapabilityID:      p.CapabilityID,
		CapabilityVersion: p.CapabilityVersion,
		IdempotencyKey:    p.IdempotencyKey,
		CorrelationID:     p.CorrelationID,
		CausationID:       p.CausationID,
	}
	ai := &asyncInvocation{
		c:                  c,
		inv:                inv,
		networkID:          p.NetworkID,
		capabilityID:       p.CapabilityID,
		dispatchID:         p.DispatchID,
		acceptedGeneration: c.connGeneration.Load(),
	}
	inv.async = ai
	if len(c.inflightInvocations) >= MaxActiveInvocations {
		c.invMu.Unlock()
		_ = c.send(transport.MsgEndpointInvocationDefer, transport.EndpointInvocationDeferPayload{InvocationID: p.InvocationID, DispatchID: p.DispatchID})
		return
	}
	c.inflightInvocations[p.InvocationID] = ai
	c.invMu.Unlock()

	// Decrypt the input (fail → error result; the input is untrusted data).
	var inputRaw json.RawMessage
	if p.Envelope != nil && p.AAD != nil {
		plain, err := c.decryptObject(p.NetworkID, *p.Envelope, *p.AAD)
		if err != nil {
			c.failInvocation(p.InvocationID, "input_decrypt_failed", fmt.Errorf("decrypt invocation input: %w", err))
			return
		}
		inputRaw = plain
		inv.CallerPrincipalID = p.AAD.Sender
		ai.caller = p.AAD.Sender
	}
	inv.InputRaw = inputRaw

	// Send admission before the handler. A successful socket write can still
	// precede the server commit; a lost admission has an uncertain outcome,
	// never an automatic handler replay.
	if err := c.send(transport.MsgEndpointInvocationAccept, transport.EndpointInvocationAcceptPayload{InvocationID: p.InvocationID, DispatchID: p.DispatchID}); err != nil {
		// No provider work starts after a failed admission write. A successful
		// write still has a crash window until the server durably records it.
		c.invMu.Lock()
		delete(c.inflightInvocations, p.InvocationID)
		c.invMu.Unlock()
		return
	}

	// Handler lookup (+ version check).
	c.handlerMu.RLock()
	reg, ok := c.caps[p.CapabilityID]
	c.handlerMu.RUnlock()
	if !ok {
		c.failInvocation(p.InvocationID, "capability_not_found", fmt.Errorf("capability %s is not advertised by this endpoint", p.CapabilityID))
		return
	}
	if reg.capability.Version > 0 && p.CapabilityVersion > 0 && reg.capability.Version != p.CapabilityVersion {
		c.failInvocation(p.InvocationID, "capability_version_mismatch",
			fmt.Errorf("capability %s version %d requested, endpoint serves %d", p.CapabilityID, p.CapabilityVersion, reg.capability.Version))
		return
	}

	// Target-side input validation (north-star §76): BEFORE the handler.
	if len(reg.capability.InputSchema) > 0 && len(inputRaw) > 0 {
		if err := c.schemas.validate(reg.capability.InputSchema, inputRaw); err != nil {
			c.failInvocation(p.InvocationID, "input_validation_failed", err)
			return
		}
	}

	// Decode the input for the handler. A valid (non-zero) reflect.Value
	// means a typed handler was registered (IsValid(), not IsZero(), which
	// panics on a zero Value).
	var handlerErr error
	var result any
	if reg.typed.IsValid() {
		// Typed handler: decode into the declared input type.
		decoded, err := decodeInput(reg.inputType, inputRaw)
		if err != nil {
			c.failInvocation(p.InvocationID, "input_decode_failed", err)
			return
		}
		inv.Input = decoded
		out, err := invokeTyped(reg.typed, context.Background(), inv, decoded)
		result, handlerErr = out, err
	} else {
		var decoded any
		if len(inputRaw) > 0 {
			if err := json.Unmarshal(inputRaw, &decoded); err != nil {
				c.failInvocation(p.InvocationID, "input_decode_failed", fmt.Errorf("decode invocation input: %w", err))
				return
			}
		}
		inv.Input = decoded
		out, err := reg.handler(context.Background(), inv)
		result, handlerErr = out, err
	}
	if handlerErr != nil {
		if errors.Is(handlerErr, ErrAsync) {
			return // stays in-flight; the handler completes it later
		}
		c.failInvocation(p.InvocationID, "handler_error", handlerErr)
		return
	}
	if err := c.completeInvocation(context.Background(), ai, result, nil); err != nil {
		// Send failed (connection dropped): stay in-flight so the handler
		// can send the saved encrypted outcome on the reconnected session.
	}
}

// decodeInput decodes raw JSON into a value of type t (a pointer to a new
// value of t).
func decodeInput(t reflect.Type, raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		// No input: zero value.
		return reflect.Zero(t).Interface(), nil
	}
	v := reflect.New(t)
	if err := json.Unmarshal(raw, v.Interface()); err != nil {
		return nil, fmt.Errorf("sdk: decode invocation input into %s: %w", t, err)
	}
	return v.Elem().Interface(), nil
}

// invokeTyped calls a typed handler func(ctx, in I) (O, error) via
// reflection.
func invokeTyped(fn reflect.Value, ctx context.Context, inv *Invocation, in any) (any, error) {
	args := []reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(in)}
	out := fn.Call(args)
	result := out[0].Interface()
	errVal := out[1].Interface()
	var err error
	if errVal != nil {
		err, _ = errVal.(error)
	}
	return result, err
}

// failInvocation completes an invocation with an error result: the error
// text is encrypted as an invocation_error object (never a malformed
// ciphertext) and sent as invocation_result {ok: false}.
func (c *Client) failInvocation(invocationID, code string, err error) {
	c.completeInvocationWith(invocationID, code, nil, err)
}

// completeInvocation completes an in-flight invocation (sync path or
// async Complete/CompleteError).
func (c *Client) completeInvocation(ctx context.Context, ai *asyncInvocation, result any, handlerErr error) error {
	// If the session dropped after the accept, the server may have given
	// up on the invocation (TTL expired → cancelled): check before
	// sending, so the caller gets a CLEAR error instead of a silently
	// dropped result.
	if ai != nil && ai.acceptedGeneration != c.connGeneration.Load() {
		if rec, err := c.rest.getInvocation(ctx, ai.networkID, ai.inv.ID); err == nil {
			switch rec.State {
			case "completed", "cancelled":
				return fmt.Errorf("sdk: invocation %s is already %s server-side (its TTL expired or it was cancelled) — the result was not recorded", ai.inv.ID, rec.State)
			case "failed":
				if rec.PublicResultCode != "outcome_unknown" {
					return fmt.Errorf("sdk: invocation %s already failed server-side", ai.inv.ID)
				}
			}
		}
	}
	code := "completed"
	if handlerErr != nil {
		code = "handler_error"
	}
	return c.completeInvocationWith(ai.inv.ID, code, result, handlerErr)
}

// completeInvocationWith builds, encrypts, and sends the invocation result,
// then retains the exact outcome until its durable server receipt.
func (c *Client) completeInvocationWith(invocationID, code string, result any, handlerErr error) error {
	c.invMu.Lock()
	original := c.inflightInvocations[invocationID]
	c.invMu.Unlock()
	if original == nil || !original.resultSubmitted.CompareAndSwap(false, true) {
		return fmt.Errorf("sdk: invocation result already submitted or unknown")
	}
	submitted := false
	defer func() {
		if !submitted {
			original.resultSubmitted.Store(false)
		}
	}()

	ok := handlerErr == nil
	var objectType string
	var plaintext []byte
	if ok {
		objectType = e2ee.ObjectTypeInvocationOutput
		b, err := json.Marshal(result)
		if err != nil {
			// A result that cannot be JSON-encoded is a handler contract
			// violation: report it as an error result (never a malformed
			// ciphertext).
			ok = false
			handlerErr = fmt.Errorf("sdk: encode invocation output: %w", err)
			code = "output_encode_failed"
			objectType = e2ee.ObjectTypeInvocationError
			plaintext = []byte(handlerErr.Error())
		} else {
			// Target-side output validation (north-star §76): BEFORE
			// encryption. A validation failure becomes an invocation_error
			// result — the caller sees a clean error, not a broken object.
			if schema := c.outputSchemaFor(invocationID); len(schema) > 0 {
				if err := c.schemas.validate(schema, b); err != nil {
					ok = false
					handlerErr = err
					code = "output_validation_failed"
					objectType = e2ee.ObjectTypeInvocationError
					plaintext = []byte(err.Error())
				}
			}
			if ok {
				plaintext = b
			}
		}
	} else {
		objectType = e2ee.ObjectTypeInvocationError
		plaintext = []byte(handlerErr.Error())
	}
	if len(plaintext) > MaxInvocationResultBytes {
		ok = false
		code = "output_too_large"
		objectType = e2ee.ObjectTypeInvocationError
		plaintext = []byte("Invocation result exceeds the supported size limit.")
	}
	caller := c.callerFor(invocationID)
	env, aad, err := c.encryptObject(c.networkFor(invocationID), objectType, invocationID, c.principalID.Load(), caller, plaintext)
	if err != nil {
		return err
	}
	c.invMu.Lock()
	ai := c.inflightInvocations[invocationID]
	c.invMu.Unlock()
	if ai == nil || ai.dispatchID == "" {
		return fmt.Errorf("sdk: missing original invocation dispatch assignment")
	}
	payload := transport.EndpointInvocationResultPayload{
		DispatchID:       ai.dispatchID,
		Reconcile:        ai.acceptedGeneration != c.connGeneration.Load(),
		InvocationID:     invocationID,
		OK:               ok,
		Envelope:         &env,
		AAD:              &aad,
		PublicResultCode: code,
	}
	wire, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(wire) > MaxInvocationResultWireBytes-1024 {
		return fmt.Errorf("sdk: encrypted invocation result exceeds supported frame limit")
	}
	// Keep the exact encrypted bytes until the server confirms its commit.
	c.pendingMu.Lock()
	c.pendingResults[invocationID] = completedInvocation{result: payload, generation: ai.acceptedGeneration, retryAt: time.Now().Add(5 * time.Second), attempts: 1, encodedBytes: len(wire)}
	c.pendingMu.Unlock()
	submitted = true
	return c.send(transport.MsgEndpointInvocationResult, payload)
}

// markCompleted retires acknowledged/rejected work into bounded duplicate protection.
func (c *Client) markCompleted(invocationID string, comp completedInvocation) {
	c.invMu.Lock()
	delete(c.inflightInvocations, invocationID)
	c.completedInvocations.set(invocationID, comp)
	if c.seenInvocations != nil {
		c.seenInvocations.Add(invocationID)
	}
	c.invMu.Unlock()
}

// flushPendingResults retries saved outcomes awaiting durable receipts after auth_ok.
func (c *Client) flushPendingResults() {
	c.retryPendingResults(true)
}
func (c *Client) retryPendingResults(force bool) {
	type candidate struct {
		id   string
		comp completedInvocation
	}
	c.pendingMu.Lock()
	var candidates []candidate
	for id, comp := range c.pendingResults {
		if force || !time.Now().Before(comp.retryAt) {
			candidates = append(candidates, candidate{id, comp})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].comp.retryAt.Equal(candidates[j].comp.retryAt) {
			return candidates[i].id < candidates[j].id
		}
		return candidates[i].comp.retryAt.Before(candidates[j].comp.retryAt)
	})
	if len(candidates) > 32 {
		candidates = candidates[:32]
	}
	for i := range candidates {
		comp := candidates[i].comp
		comp.result.Reconcile = comp.generation != c.connGeneration.Load()
		comp.attempts++
		if comp.attempts > 5 {
			comp.attempts = 5
		}
		comp.retryAt = time.Now().Add(time.Duration(5*(1<<min(comp.attempts-1, 4))) * time.Second)
		c.pendingResults[candidates[i].id] = comp
		candidates[i].comp = comp
	}
	c.pendingMu.Unlock()
	for _, item := range candidates {
		_ = c.send(transport.MsgEndpointInvocationResult, item.comp.result)
	}
}
func (c *Client) handleInvocationResultAck(env transport.Envelope) {
	var p transport.EndpointInvocationResultAckPayload
	if err := env.DecodePayload(&p); err != nil || p.DispatchID == "" {
		return
	}
	c.pendingMu.Lock()
	comp, ok := c.pendingResults[p.InvocationID]
	if !ok || comp.result.DispatchID != p.DispatchID {
		c.pendingMu.Unlock()
		return
	}
	if !p.Recorded && p.PublicResultCode != "dispatch_rejected" {
		c.pendingMu.Unlock()
		return
	}
	delete(c.pendingResults, p.InvocationID)
	c.pendingMu.Unlock()
	c.markCompleted(p.InvocationID, comp)
}

// callerFor / networkFor / outputSchemaFor look up dispatch context kept
// on the in-flight (or just-completed) invocation.
func (c *Client) callerFor(invocationID string) string {
	c.invMu.Lock()
	defer c.invMu.Unlock()
	if ai, ok := c.inflightInvocations[invocationID]; ok {
		return ai.caller
	}
	return ""
}

func (c *Client) networkFor(invocationID string) string {
	c.invMu.Lock()
	defer c.invMu.Unlock()
	if ai, ok := c.inflightInvocations[invocationID]; ok {
		return ai.networkID
	}
	return ""
}

func (c *Client) outputSchemaFor(invocationID string) json.RawMessage {
	c.invMu.Lock()
	ai, ok := c.inflightInvocations[invocationID]
	c.invMu.Unlock()
	if !ok {
		return nil
	}
	c.handlerMu.RLock()
	defer c.handlerMu.RUnlock()
	if reg, ok := c.caps[ai.capabilityID]; ok {
		return reg.capability.OutputSchema
	}
	return nil
}
