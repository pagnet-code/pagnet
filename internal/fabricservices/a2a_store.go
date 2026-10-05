package fabricservices

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/a2a"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// A2AAssociations is the adapter-local protocol task mapping backed by the SAME
// signed root invocation ledger. It creates no database/account/planner state.
type A2AAssociations struct {
	ledger      *Invocations
	scope       registry.DescriptorBatchScope
	fingerprint [32]byte
}

func NewA2AAssociations(i *Invocations, scope registry.DescriptorBatchScope, fingerprint [32]byte) (*A2AAssociations, error) {
	if i == nil || scope.Endpoint.String() == "" || scope.ExpectedEndpointRevision == "" || scope.BindingID == "" || fingerprint == ([32]byte{}) {
		return nil, denied()
	}
	return &A2AAssociations{i, scope, fingerprint}, nil
}
func (s *A2AAssociations) Scope() a2a.StoreScope {
	return a2a.StoreScope{Domain: s.ledger.profiles.root.Namespace, ID: s.ledger.profiles.root.StoreID, Audience: s.ledger.profiles.root.Namespace}
}
func (s *A2AAssociations) key(k a2a.AssociationKey) bool {
	return k.Ref == s.scope.Endpoint && k.Revision == s.scope.ExpectedEndpointRevision && k.Audience == s.ledger.profiles.root.Namespace && validText(k.InvocationID, 256) && validText(k.Binding, 256)
}
func (s *A2AAssociations) caller(ctx context.Context) (fabric.ExecutionContext, error) {
	c, original, finalized, ok := node.FinalizedRequestFromContext(ctx)
	defer clear(original)
	defer clear(finalized)
	if !ok {
		return fabric.ExecutionContext{}, denied()
	}
	if _, e := c.DecodeVerifiedEnvelope(original, s.ledger.profiles.root.Namespace); e != nil {
		return fabric.ExecutionContext{}, e
	}
	return c, nil
}
func (s *A2AAssociations) Admit(ctx context.Context, a a2a.Association) error {
	if s == nil || !s.key(a.Key) || a.TaskID != "" || a.ContextID != "" {
		return a2a.ErrAssociation
	}
	caller, e := s.caller(ctx)
	if e != nil || caller.PrincipalView() != a.Key.Principal {
		return a2a.ErrAssociation
	}
	_, original, finalized, ok := node.FinalizedRequestFromContext(ctx)
	defer clear(original)
	defer clear(finalized)
	var env fabric.Envelope
	if !ok || fabric.DecodeJSON(finalized, &env) != nil || env.Target == nil {
		return a2a.ErrAssociation
	}
	digest := sha256.Sum256(env.Payload)
	var input a2a.Input
	if fabric.DecodeJSON(env.Payload, &input) != nil || a.Operation != input.Operation || a.Mode != input.Mode || a.InputSHA != hex.EncodeToString(digest[:]) {
		return a2a.ErrAssociation
	}
	request := fabric.InvokeRequest{InvocationID: env.ID, Target: *env.Target, ExpectedRevision: env.ExpectedRevision, Input: env.Payload, Deadline: env.Context.Deadline, IdempotencyKey: env.Context.IdempotencyKey}
	r, fresh, e := s.ledger.Reserve(ctx, caller, s.scope, s.fingerprint, request)
	if e != nil {
		return e
	}
	if !fresh {
		return a2a.ErrAttempted
	}
	if r.Facts.Principal != a.Key.Principal || r.Facts.InvocationID != a.Key.InvocationID {
		return a2a.ErrConflict
	}
	// This additional FULL association pin is still BEFORE any SDK paid effect.
	// Failure leaves the earlier attempt unknown, never permission to resend.
	return s.ledger.read(ctx, caller, a.Key.Principal, a.Key.InvocationID, s.scope, "associate_admission", func(_ context.Context, tx *registry.AuthorityTx, r Receipt, row registry.AuthorityRecord) error {
		if r.AssociationBinding != "" {
			return a2a.ErrConflict
		}
		r.AssociationBinding = a.Key.Binding
		r.Operation = a.Operation
		r.Mode = a.Mode
		return s.ledger.updateReceipt(tx, row, r)
	})
}
func (s *A2AAssociations) Lookup(ctx context.Context, k a2a.AssociationKey) (a2a.Association, error) {
	if s == nil || !s.key(k) {
		return a2a.Association{}, a2a.ErrAssociation
	}
	caller, e := s.caller(ctx)
	if e != nil {
		return a2a.Association{}, e
	}
	var a a2a.Association
	e = s.ledger.read(ctx, caller, k.Principal, k.InvocationID, s.scope, "association_read", func(_ context.Context, _ *registry.AuthorityTx, r Receipt, _ registry.AuthorityRecord) error {
		if r.AssociationBinding != k.Binding || r.Facts.Fingerprint != s.fingerprint {
			return a2a.ErrAssociation
		}
		a = a2a.Association{Key: k, InputSHA: hex.EncodeToString(r.Facts.InputSHA[:]), Operation: r.Operation, Mode: r.Mode, TaskID: r.TaskID, ContextID: r.ContextID}
		return nil
	})
	return a, e
}
func (s *A2AAssociations) Associate(ctx context.Context, k a2a.AssociationKey, task, conversation string) error {
	if s == nil || !s.key(k) || !validText(task, 4096) || !validText(conversation, 4096) {
		return a2a.ErrAssociation
	}
	caller, e := s.caller(ctx)
	if e != nil {
		return e
	}
	return s.ledger.read(ctx, caller, k.Principal, k.InvocationID, s.scope, "associate", func(_ context.Context, tx *registry.AuthorityTx, r Receipt, row registry.AuthorityRecord) error {
		if r.AssociationBinding != k.Binding || r.Facts.Fingerprint != s.fingerprint {
			return a2a.ErrAssociation
		}
		if r.TaskID != "" {
			if r.TaskID == task && r.ContextID == conversation {
				return nil
			}
			return a2a.ErrAssociation
		}
		r.TaskID = task
		r.ContextID = conversation
		return s.ledger.updateReceipt(tx, row, r)
	})
}
func (i *Invocations) updateReceipt(tx *registry.AuthorityTx, row registry.AuthorityRecord, r Receipt) error {
	id := "invocation/" + invocationKey(r.Facts.Principal, r.Facts.InvocationID)
	value, e := i.encode(id, r)
	if e != nil {
		return e
	}
	s, srow, e := i.state(tx)
	if e != nil {
		return e
	}
	if uint64(len(value)) > s.Config.MaxBytes-s.Bytes {
		return a2a.ErrCapacity
	}
	if _, e = tx.CAS(serviceKey(id), row.Revision, value, false); e != nil {
		return e
	}
	s.Bytes += uint64(len(value))
	value, e = i.encode("configuration", s)
	if e != nil {
		return e
	}
	_, e = tx.CAS(serviceKey("configuration"), srow.Revision, value, false)
	return e
}

var _ a2a.AssociationStore = (*A2AAssociations)(nil)

func (s *A2AAssociations) SupportsRootIdempotency() bool {
	if s == nil || s.ledger == nil {
		return false
	}
	_, ok := s.ledger.policy.(InvocationHistoryPolicy)
	return ok
}
