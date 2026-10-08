package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
)

type actionSet struct {
	Source  SourceInput `json:"source"`
	Actions []Action    `json:"actions"`
}

// QueueReceipt proves one FULL encrypted action-set commit, not target admission.
type QueueReceipt = durable.Receipt

func (s *Store) verifySource(ctx context.Context, input SourceInput) (event.Event, VerifiedSource, error) {
	if len(input.ExactEvent) > s.config.Queue.MaxEventBytes || len(input.Proof) == 0 || len(input.Proof) > s.config.MaxProofBytes {
		return event.Event{}, VerifiedSource{}, invalid()
	}
	if fabric.DecodeJSON(input.Proof, new(any)) != nil {
		return event.Event{}, VerifiedSource{}, invalid()
	}
	e, err := events.Decode(input.ExactEvent, s.config.Queue.MaxEventBytes)
	if err != nil || e.Time().IsZero() {
		return event.Event{}, VerifiedSource{}, invalid()
	}
	verified, err := s.config.SourceAuthority.Verify(ctx, s.config.Scope, SourceInput{bytes.Clone(input.ExactEvent), bytes.Clone(input.Proof)})
	if err != nil || verified.Caller.VerifyAuthenticated(s.config.Scope.Audience) != nil {
		return event.Event{}, VerifiedSource{}, denied()
	}
	if verified.Parent != nil && verified.Parent.Validate() != nil {
		return event.Event{}, VerifiedSource{}, denied()
	}
	return e, verified, nil
}

// Trigger queues matching installed definitions. No match is explicit and queues
// nothing. Delivery never derives a new target from mutable event data.
func (s *Store) Trigger(ctx context.Context, input SourceInput) (QueueReceipt, error) {
	return s.enqueue(ctx, input, nil)
}

// Emit queues exactly one explicit target, authorized by the current source caller.
func (s *Store) Emit(ctx context.Context, input SourceInput, request EmitRequest) (QueueReceipt, error) {
	return s.enqueue(ctx, input, &request)
}
func (s *Store) enqueue(ctx context.Context, input SourceInput, emit *EmitRequest) (QueueReceipt, error) {
	if ctx == nil || ctx.Err() != nil {
		return QueueReceipt{}, unavailable()
	}
	done, err := s.begin()
	if err != nil {
		return QueueReceipt{}, err
	}
	defer done()
	input = SourceInput{bytes.Clone(input.ExactEvent), bytes.Clone(input.Proof)}
	e, v, err := s.verifySource(ctx, input)
	if err != nil {
		return QueueReceipt{}, err
	}
	type selected struct {
		request    EmitRequest
		definition *TriggerDefinition
	}
	chosen := []selected{}
	if emit != nil {
		chosen = append(chosen, selected{request: *emit})
	} else {
		for _, d := range s.matches[triggerKey{e.Source(), e.Type()}] {
			{
				definition := cloneDefinition(d)
				chosen = append(chosen, selected{EmitRequest{d.Target, d.TargetRevision, bytes.Clone(e.Data())}, &definition})
			}
		}
	}
	if len(chosen) == 0 {
		return QueueReceipt{}, fabric.NewError(fabric.CodeNotFound, "No installed trigger matches this event")
	}
	if len(chosen) > s.config.MaxFanout {
		return QueueReceipt{}, invalid()
	}
	set := actionSet{Source: input}
	for _, pick := range chosen {
		r := pick.request
		r.Input = bytes.Clone(r.Input)
		if r.Target.String() == "" || len(r.Revision) == 0 || len(r.Revision) > 128 || len(r.Input) == 0 || len(r.Input) > s.config.MaxEnvelopeBytes || fabric.DecodeJSON(r.Input, new(any)) != nil {
			return QueueReceipt{}, invalid()
		}
		key := "emit"
		if pick.definition != nil {
			if s.config.DefinitionAuthority.Verify(ctx, s.config.Scope, cloneDefinition(*pick.definition)) != nil {
				return QueueReceipt{}, denied()
			}
			key = pick.definition.ID + "@" + pick.definition.Revision
		}

		id, lineage, err := actionIdentity(s.config.Scope, e, v, key, pick.definition)
		if err != nil {
			return QueueReceipt{}, err
		}
		var preparedDefinition *TriggerDefinition
		if pick.definition != nil {
			d := cloneDefinition(*pick.definition)
			preparedDefinition = &d
		}
		preparation := Preparation{id, e.Time(), r, cloneContext(lineage), preparedDefinition}
		exact, err := s.config.Authorizer.Prepare(ctx, v.Caller, preparation)
		if err != nil {
			return QueueReceipt{}, denied()
		}
		if len(exact) > s.config.MaxEnvelopeBytes {
			return QueueReceipt{}, invalid()
		}
		var envelope fabric.Envelope
		if fabric.DecodeJSON(exact, &envelope) != nil || envelope.Validate() != nil || envelope.ID != id || !envelope.CreatedAt.Equal(e.Time()) || envelope.Operation != fabric.OperationInvoke || envelope.Target == nil || *envelope.Target != r.Target || envelope.ExpectedRevision != r.Revision || envelope.Principal != v.Caller.PrincipalView() || envelope.Source != v.Caller.PrincipalView().Ref {
			return QueueReceipt{}, denied()
		}
		a, _ := json.Marshal(lineage)
		b, _ := json.Marshal(envelope.Context)
		if !bytes.Equal(a, b) {
			return QueueReceipt{}, denied()
		}
		invocation := invokeFromEnvelope(envelope)
		if invocation.Validate() != nil {
			return QueueReceipt{}, denied()
		}
		var wanted, actual bytes.Buffer
		if json.Compact(&wanted, r.Input) != nil || json.Compact(&actual, invocation.Input) != nil || !bytes.Equal(wanted.Bytes(), actual.Bytes()) {
			return QueueReceipt{}, denied()
		}
		action := Action{ID: id, ExactEnvelope: bytes.Clone(exact), EventSource: e.Source(), EventID: e.ID(), EventDigest: digest(input.ExactEvent)}
		if pick.definition != nil {
			action.DefinitionID = pick.definition.ID
			action.DefinitionRevision = pick.definition.Revision
		}
		set.Actions = append(set.Actions, action)
	}
	body, err := json.Marshal(set)
	if err != nil || len(body) > s.config.Queue.MaxEventBytes {
		return QueueReceipt{}, invalid()
	}
	queued := event.New("1.0")
	queued.SetSource("urn:pagnet:actions:" + digest([]byte(s.config.Scope.Domain)))
	queued.SetType("dev.pagnet.actions.queued")
	queued.SetTime(e.Time())
	identity, _ := json.Marshal(struct{ Source, ID, Mode string }{e.Source(), e.ID(), fmt.Sprint(emit != nil)})
	queued.SetID(digest(identity))
	if queued.SetData("application/json", json.RawMessage(body)) != nil {
		return QueueReceipt{}, invalid()
	}
	return s.queue.Publish(ctx, queued)
}

// deliver is the store-owned for the existing bounded durable Workers handler. It
// rechecks current authority, then consumes exact admission receipts. Prefix
// retry is safe only through Admitter's genuine durable identity contract.
func (s *Store) deliver(ctx context.Context, e event.Event) error {
	if ctx == nil || ctx.Err() != nil {
		return unavailable()
	}
	done, err := s.begin()
	if err != nil {
		return err
	}
	defer done()
	if e.Type() != "dev.pagnet.actions.queued" || e.Source() != "urn:pagnet:actions:"+digest([]byte(s.config.Scope.Domain)) {
		return denied()
	}
	var set actionSet
	if fabric.DecodeJSONWithLimits(e.Data(), &set, fabric.WireLimits{MaxBytes: s.config.Queue.MaxEventBytes, MaxDepth: 64, MaxMembers: 4096}) != nil || len(set.Actions) < 1 || len(set.Actions) > s.config.MaxFanout {
		return invalid()
	}
	original, v, err := s.verifySource(ctx, set.Source)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	mode := set.Actions[0].DefinitionID == ""
	for _, action := range set.Actions {
		if seen[action.ID] || (action.DefinitionID == "") != mode {
			return denied()
		}
		seen[action.ID] = true
		key := "emit"
		var definition *TriggerDefinition
		if action.EventSource != original.Source() || action.EventID != original.ID() || action.EventDigest != digest(set.Source.ExactEvent) || len(action.ExactEnvelope) > s.config.MaxEnvelopeBytes {
			return denied()
		}
		var envelope fabric.Envelope
		if fabric.DecodeJSON(action.ExactEnvelope, &envelope) != nil || envelope.Validate() != nil || envelope.ID != action.ID || envelope.Operation != fabric.OperationInvoke || envelope.Principal != v.Caller.PrincipalView() {
			return denied()
		}
		if action.DefinitionID != "" {
			d, ok := s.definitions[action.DefinitionID]
			if !ok || d.Revision != action.DefinitionRevision || d.Source != original.Source() || d.Type != original.Type() || envelope.Target == nil || *envelope.Target != d.Target || envelope.ExpectedRevision != d.TargetRevision || s.config.DefinitionAuthority.Verify(ctx, s.config.Scope, cloneDefinition(d)) != nil {
				return denied()
			}
			key = d.ID + "@" + d.Revision
			definition = &d
		} else if action.DefinitionRevision != "" {
			return denied()
		}
		expected, context, err := actionIdentity(s.config.Scope, original, v, key, definition)
		if err != nil || expected != action.ID || !envelope.CreatedAt.Equal(original.Time()) || envelope.Source != v.Caller.PrincipalView().Ref {
			return denied()
		}
		a, _ := json.Marshal(context)
		b, _ := json.Marshal(envelope.Context)
		if !bytes.Equal(a, b) {
			return denied()
		}
		invocation := invokeFromEnvelope(envelope)
		if invocation.Validate() != nil {
			return denied()
		}
		if s.config.Authorizer.Check(ctx, v.Caller, cloneAction(action)) != nil {
			return denied()
		}
		receipt, err := s.config.Admitter.AdmitOrGet(ctx, AdmissionRequest{cloneAction(action), SourceInput{bytes.Clone(set.Source.ExactEvent), bytes.Clone(set.Source.Proof)}, v.Caller})
		if err != nil {
			return err
		}
		if receipt.ActionID != action.ID || receipt.EnvelopeDigest != digest(action.ExactEnvelope) || len(receipt.AdmissionID) == 0 || len(receipt.AdmissionID) > 256 || receipt.AcceptedAt.IsZero() {
			return denied()
		}
	}
	return nil
}
// ClaimDelivery claims one pending delivery from the actions dispatch queue.
// It is the worker's genuine claim: the caller owns the lease and must Ack or
// let it expire. It exposes no authority; delivery still verifies through the
// store's current source/definition authority and the durable Admitter.
func (s *Store) ClaimDelivery(ctx context.Context, worker string, now time.Time) (durable.Delivery, bool, error) {
	if s == nil || ctx == nil || worker == "" {
		return durable.Delivery{}, false, invalid()
	}
	return s.queue.Claim(ctx, "actions.dispatch", worker, now)
}

// AckDelivery acknowledges a claimed delivery after its actions were durably
// admitted. It never re-admits; an unacked lease is redelivered and the
// Admitter recovers the same retained receipt.
func (s *Store) AckDelivery(ctx context.Context, claim durable.Claim, now time.Time) error {
	if s == nil || ctx == nil || claim.Token == "" {
		return invalid()
	}
	return s.queue.Ack(ctx, claim, now)
}

func (s *Store) StartWorkers(ctx context.Context) (*durable.Workers, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.worker != nil || s.config.Admitter == nil {
		return nil, unavailable()
	}
	worker, err := durable.StartWorkers(ctx, s.queue, durable.WorkerConfig{Handlers: map[string]durable.Handler{"actions.dispatch": s.deliver}, Timeout: 30 * time.Second, PollInterval: 100 * time.Millisecond})
	if err == nil {
		s.worker = worker
	}
	return worker, err
}
func (s *Store) Purge(ctx context.Context, before time.Time, limit int) (int, error) {
	return s.queue.Purge(ctx, before, limit)
}
func (s *Store) State(ctx context.Context) (durable.State, error) { return s.queue.State(ctx) }

func actionIdentity(scope durable.Scope, e event.Event, v VerifiedSource, key string, d *TriggerDefinition) (string, fabric.EnvelopeContext, error) {
	identity, _ := json.Marshal(struct {
		Scope           durable.Scope
		Source, ID, Key string
	}{scope, e.Source(), e.ID(), key})
	id := digest(identity)
	lineage := fabric.EnvelopeContext{Origin: v.Caller.PrincipalView().Ref, IdempotencyKey: id}
	if v.Parent != nil {
		parent := v.Parent
		if parent.Context.Hops >= 64 || len(parent.Context.Ancestry) >= 64 {
			return "", lineage, invalid()
		}
		if parent.Context.Deadline != nil && !parent.Context.Deadline.After(time.Now()) {
			return "", lineage, denied()
		}
		lineage = cloneContext(parent.Context)
		lineage.ParentID = parent.ID
		lineage.Ancestry = append(slices.Clone(parent.Context.Ancestry), parent.ID)
		lineage.ExtensionChain = slices.Clone(parent.Context.ExtensionChain)
		lineage.TriggerLineage = slices.Clone(parent.Context.TriggerLineage)
		lineage.Hops++
		lineage.IdempotencyKey = id
	}
	if d != nil {
		if slices.Contains(lineage.TriggerLineage, d.ID) || len(lineage.TriggerLineage) >= 64 {
			return "", lineage, invalid()
		}
		lineage.TriggerLineage = append(lineage.TriggerLineage, d.ID)
	}
	return id, lineage, nil
}

func cloneAction(a Action) Action { a.ExactEnvelope = bytes.Clone(a.ExactEnvelope); return a }
func cloneContext(c fabric.EnvelopeContext) fabric.EnvelopeContext {
	c.Ancestry = slices.Clone(c.Ancestry)
	c.ExtensionChain = slices.Clone(c.ExtensionChain)
	c.TriggerLineage = slices.Clone(c.TriggerLineage)
	if c.Deadline != nil {
		deadline := *c.Deadline
		c.Deadline = &deadline
	}
	return c
}

func invokeFromEnvelope(e fabric.Envelope) fabric.InvokeRequest {
	return fabric.InvokeRequest{InvocationID: e.ID, Target: *e.Target, ExpectedRevision: e.ExpectedRevision, Input: bytes.Clone(e.Payload), Deadline: e.Context.Deadline, IdempotencyKey: e.Context.IdempotencyKey}
}
func cloneDefinition(d TriggerDefinition) TriggerDefinition {
	d.SignedAuthorization = bytes.Clone(d.SignedAuthorization)
	return d
}
