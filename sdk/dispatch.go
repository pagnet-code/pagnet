package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

// lruMap is a bounded last-recently-used map (values), for the completed-
// invocation cache (re-send the stored result on redelivery).
type lruMap struct {
	mu    sync.Mutex
	cap   int
	items map[string]any
	order []string
}

func newLRUMap(cap int) *lruMap {
	if cap <= 0 {
		cap = DefaultSeenCap
	}
	return &lruMap{cap: cap, items: map[string]any{}}
}

// set inserts/updates key.
func (m *lruMap) set(key string, v any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.items[key]; ok {
		m.items[key] = v
		m.touchLocked(key)
		return
	}
	m.items[key] = v
	m.order = append(m.order, key)
	if len(m.order) > m.cap {
		old := m.order[0]
		m.order = m.order[1:]
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
	reg := capRegistration{capability: base, handler: h, typed: typed, inputType: inputType}
	// A zero (invalid) reflect.Value means "no typed handler provided".
	// IsValid() is used (not IsZero(), which panics on a zero Value).
	if (h == nil && !typed.IsValid()) && exists {
		reg.handler = old.handler
		reg.typed = old.typed
		reg.inputType = old.inputType
	}
	c.caps[cap.ID] = reg
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
		_ = json.Unmarshal(plain, &m.Parts) // malformed parts: empty (data, not control)
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
	if err := env.DecodePayload(&p); err != nil {
		return
	}
	ack := func() {
		_ = c.send(transport.MsgEndpointEventAck, transport.EndpointEventAckPayload{DeliveryID: p.DeliveryID, EventID: p.EventID})
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
	result transport.EndpointInvocationResultPayload
}

// asyncInvocation is the target-side control for one in-flight invocation
// (the Invocation.async back-reference).
type asyncInvocation struct {
	c            *Client
	inv          *Invocation
	networkID    string
	capabilityID string
	caller       string
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
	if err := env.DecodePayload(&p); err != nil {
		return
	}
	c.invMu.Lock()
	if comp, ok := c.completedInvocations.get(p.InvocationID); ok {
		c.invMu.Unlock()
		// Redelivery after uncertain failure: re-send the result.
		_ = c.send(transport.MsgEndpointInvocationResult, comp.(completedInvocation).result)
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
		acceptedGeneration: c.connGeneration.Load(),
	}
	inv.async = ai
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

	// Accept: the endpoint owns this invocation now (it will produce a
	// result). Sent BEFORE the handler so the server's state is durable.
	if err := c.send(transport.MsgEndpointInvocationAccept, transport.EndpointInvocationAcceptPayload{InvocationID: p.InvocationID}); err != nil {
		// The connection dropped mid-accept: the server will re-dispatch
		// (it never saw the accept). We stay in-flight; the handler still
		// runs and completes on the reconnected session.
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
		// (or an async Complete) can retry on the reconnected session.
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
				return fmt.Errorf("sdk: invocation %s already failed server-side", ai.inv.ID)
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
// then records it as completed (for redelivery re-send).
func (c *Client) completeInvocationWith(invocationID, code string, result any, handlerErr error) error {
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
	caller := c.callerFor(invocationID)
	env, aad, err := c.encryptObject(c.networkFor(invocationID), objectType, invocationID, c.principalID.Load(), caller, plaintext)
	if err != nil {
		return err
	}
	payload := transport.EndpointInvocationResultPayload{
		InvocationID:     invocationID,
		OK:               ok,
		Envelope:         &env,
		AAD:              &aad,
		PublicResultCode: code,
	}
	if err := c.send(transport.MsgEndpointInvocationResult, payload); err != nil {
		// The session dropped: queue the result for re-send on the next
		// live connection (onLive flushes pendingResults). The invocation
		// stays in-flight until the result is actually sent.
		c.pendingMu.Lock()
		c.pendingResults[invocationID] = completedInvocation{result: payload}
		c.pendingMu.Unlock()
		return err
	}
	c.markCompleted(invocationID, completedInvocation{result: payload})
	return nil
}

// markCompleted records a sent result (bounded; redelivery re-sends it).
func (c *Client) markCompleted(invocationID string, comp completedInvocation) {
	c.invMu.Lock()
	delete(c.inflightInvocations, invocationID)
	c.completedInvocations.set(invocationID, comp)
	c.invMu.Unlock()
}

// flushPendingResults re-sends results whose send failed on a dead
// session (called after each auth_ok).
func (c *Client) flushPendingResults() {
	c.pendingMu.Lock()
	pending := c.pendingResults
	c.pendingResults = map[string]completedInvocation{}
	c.pendingMu.Unlock()
	for id, comp := range pending {
		if err := c.send(transport.MsgEndpointInvocationResult, comp.result); err == nil {
			c.markCompleted(id, comp)
		} else {
			c.pendingMu.Lock()
			c.pendingResults[id] = comp
			c.pendingMu.Unlock()
		}
	}
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
