package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// AdapterInvoker is the real endpoint association. The Admitter invokes it
// exactly once per action identity, and only after the admission commit has
// durably succeeded. A replayed (already-admitted) action never reaches the
// adapter, so a paid operation is never re-dispatched. The implementation must
// resolve the actual registered binding/adapter and never fall back to a
// generic Node.Execute queue callback.
type AdapterInvoker interface {
	Invoke(context.Context, AdmissionRequest) (fabric.InvocationStream, error)
}

// TargetScope resolves an action's exact current native authority scope. It must
// reflect the real retained endpoint/offer and a binding it actually publishes,
// never a caller assertion. The returned endpoint is the physical (non-offer)
// endpoint, its current descriptor revision, and a published binding ID.
type TargetScope struct {
	Endpoint         fabric.EndpointRef
	EndpointRevision fabric.Revision
	BindingID        string
}

type TargetScopeResolver interface {
	ResolveTargetScope(context.Context, fabric.EndpointRef, fabric.Revision) (TargetScope, error)
}

// DurableAdmissionRecord is the retained, signed admission receipt value. It is
// the exact action identity plus canonical-byte commitment, recoverable after a
// lost reply or restart. The outer signed authority record is the receipt.
type DurableAdmissionRecord struct {
	Format         int           `json:"format"`
	ActionID       string        `json:"actionId"`
	EnvelopeDigest string        `json:"envelopeDigest"`
	AdmissionID    string        `json:"admissionId"`
	Scope          durable.Scope `json:"scope"`
	AcceptedAt     time.Time     `json:"acceptedAt"`
}

// DurableAdmitter is the production durable Admitter. It commits the exact
// action identity and canonical bytes through the domain's existing universal
// original claim (SignDispatchAdmission) BEFORE any adapter effect, retains the
// receipt in the same FULL commit, and recovers that same receipt after a lost
// reply. It never re-dispatches an already-paid operation.
type DurableAdmitter struct {
	store   *registry.Store
	scope   durable.Scope
	owner   func(context.Context) (fabric.ExecutionContext, error)
	source  SourceAuthority
	targets TargetScopeResolver
	adapter AdapterInvoker
}

func NewDurableAdmitter(store *registry.Store, scope durable.Scope, owner func(context.Context) (fabric.ExecutionContext, error), source SourceAuthority, targets TargetScopeResolver, adapter AdapterInvoker) (*DurableAdmitter, error) {
	if store == nil || owner == nil || source == nil || targets == nil || adapter == nil || scope.Audience == "" || scope.Domain == "" {
		return nil, invalid()
	}
	return &DurableAdmitter{store: store, scope: scope, owner: owner, source: source, targets: targets, adapter: adapter}, nil
}

func (a *DurableAdmitter) receiptKey(id string) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityDispatch, ID: "actions-admission/" + id}
}
func admissionID(actionID, envelopeDigest string) string {
	sum := sha256.Sum256([]byte("pagnet.actions.admission.v1\x00" + actionID + "\x00" + envelopeDigest))
	return "actions-admission/" + hex.EncodeToString(sum[:])
}

func (a *DurableAdmitter) AdmitOrGet(ctx context.Context, request AdmissionRequest) (AdmissionReceipt, error) {
	if ctx == nil || ctx.Err() != nil {
		return AdmissionReceipt{}, unavailable()
	}
	action := request.Action
	if action.ID == "" || len(action.ExactEnvelope) == 0 || len(action.ExactEnvelope) > 65536 {
		return AdmissionReceipt{}, invalid()
	}
	var envelope fabric.Envelope
	if fabric.DecodeJSONWithLimits(action.ExactEnvelope, &envelope, fabric.WireLimits{MaxBytes: 65536, MaxDepth: 64, MaxMembers: 4096}) != nil || envelope.Validate() != nil || envelope.Operation != fabric.OperationInvoke || envelope.Target == nil || envelope.ID != action.ID || envelope.Principal.Ref == "" {
		return AdmissionReceipt{}, invalid()
	}
	envelopeDigest := sha256.Sum256(action.ExactEnvelope)
	// Reverify the original source independently. The Admitter is a self-contained
	// acceptance boundary: it does not trust a caller context carried on the queue.
	verified, err := a.source.Verify(ctx, a.scope, SourceInput{bytesClone(request.Source.ExactEvent), bytesClone(request.Source.Proof)})
	if err != nil {
		return AdmissionReceipt{}, err
	}
	if verified.Caller.VerifyAuthenticated(a.scope.Audience) != nil || verified.Caller.PrincipalView() != envelope.Principal {
		return AdmissionReceipt{}, denied()
	}
	if verified.Parent != nil && verified.Parent.Validate() != nil {
		return AdmissionReceipt{}, denied()
	}
	target, err := a.targets.ResolveTargetScope(ctx, *envelope.Target, envelope.ExpectedRevision)
	if err != nil {
		return AdmissionReceipt{}, err
	}
	if target.Endpoint.String() == "" || target.Endpoint.IsOffer() || target.Endpoint.Domain() != envelope.Target.Endpoint().Domain() || target.EndpointRevision == "" || target.BindingID == "" || len(target.BindingID) > 256 {
		return AdmissionReceipt{}, invalid()
	}
	// Prepare the invocation target (registered input schema) before the
	// authority transaction; its exact metadata is rechecked under the lock.
	prepared, err := a.store.PrepareInvocationTarget(ctx, *envelope.Target, envelope.ExpectedRevision, envelope.Payload)
	if err != nil {
		return AdmissionReceipt{}, err
	}
	namespace := a.store.AuthorityIdentity().Namespace
	provenance := fabric.Provenance{Origin: envelope.Context.Origin, ParentID: envelope.Context.ParentID, Hops: envelope.Context.Hops, Ancestry: envelope.Context.Ancestry, ExtensionChain: envelope.Context.ExtensionChain, TriggerLineage: envelope.Context.TriggerLineage}
	forward, err := fabric.NewAuthenticatedForwardContext(envelope.Principal, namespace, action.ExactEnvelope, provenance)
	if err != nil {
		return AdmissionReceipt{}, err
	}
	frame := fabric.DispatchAdmissionFrame{
		SourceDomain:            namespace,
		CallerRef:               envelope.Principal.Ref,
		AudienceDomain:          namespace,
		InvocationID:            envelope.ID,
		AttemptID:               action.ID,
		ReplayID:                action.ID,
		FinalizedDispatchDigest: envelopeDigest,
	}
	if envelope.Context.Deadline != nil {
		frame.Deadline = envelope.Context.Deadline.UTC().Format(time.RFC3339Nano)
	}
	owner, err := a.owner(ctx)
	if err != nil {
		return AdmissionReceipt{}, err
	}
	key := a.receiptKey(action.ID)
	scope := registry.AuthorityScope{Endpoint: target.Endpoint, ExpectedRevision: target.EndpointRevision, BindingID: target.BindingID}
	digestText := hex.EncodeToString(envelopeDigest[:])
	var retained *DurableAdmissionRecord
	var committedAt time.Time
	err = a.store.WithNativeAuthority(ctx, owner, scope, func(tx *registry.AuthorityTx) error {
		record, e := tx.Get(key)
		if e == nil {
			var stored DurableAdmissionRecord
			if fabric.DecodeJSONWithLimits(record.Value, &stored, fabric.WireLimits{MaxBytes: 64 << 10, MaxDepth: 8, MaxMembers: 128}) != nil ||
				stored.Format != 1 || stored.ActionID != action.ID || stored.EnvelopeDigest != digestText || stored.Scope != a.scope || stored.AcceptedAt.IsZero() ||
				stored.AdmissionID != admissionID(action.ID, digestText) || record.Retired {
				return conflict("Retained action admission differs from the exact requested action")
			}
			accepted := stored.AcceptedAt
			retained = &stored
			committedAt = accepted
			return nil
		}
		if !isAuthorityNotFound(e) {
			return e
		}
		// Fresh admission: the universal original claim and the canonical bytes
		// commit atomically, BEFORE any adapter effect. A rolled-back claim rolls
		// back this receipt too; a committed one is never re-signed.
		if _, e := tx.SignDispatchAdmission(forward, action.ExactEnvelope, action.ExactEnvelope, frame, prepared); e != nil {
			return e
		}
		committedAt = time.Now().UTC()
		value, e := json.Marshal(DurableAdmissionRecord{Format: 1, ActionID: action.ID, EnvelopeDigest: digestText, AdmissionID: admissionID(action.ID, digestText), Scope: a.scope, AcceptedAt: committedAt})
		if e != nil {
			return e
		}
		if _, e := tx.CAS(key, 0, value, false); e != nil {
			return e
		}
		return nil
	})
	if err != nil {
		return AdmissionReceipt{}, err
	}
	receipt := AdmissionReceipt{ActionID: action.ID, EnvelopeDigest: digestText, AdmissionID: admissionID(action.ID, digestText), AcceptedAt: committedAt}
	if retained != nil {
		// Lost reply / restart: the exact durable receipt is recovered. The
		// adapter effect is never repeated for an already-paid operation.
		return receipt, nil
	}
	stream, err := a.adapter.Invoke(ctx, AdmissionRequest{Action: cloneAction(action), Source: SourceInput{bytesClone(request.Source.ExactEvent), bytesClone(request.Source.Proof)}, Caller: forward})
	if err != nil {
		return AdmissionReceipt{}, err
	}
	if stream == nil {
		return AdmissionReceipt{}, fabric.NewError(fabric.CodeProtocolError, "Admitted action adapter returned no invocation stream")
	}
	defer stream.Close()
	for {
		if _, e := stream.Next(ctx); e != nil {
			if errors.Is(e, io.EOF) {
				break
			}
			return AdmissionReceipt{}, e
		}
	}
	return receipt, nil
}

func isAuthorityNotFound(err error) bool {
	var structured *fabric.Error
	return errors.As(err, &structured) && structured.Code == fabric.CodeNotFound
}
func conflict(message string) error { return fabric.NewError(fabric.CodeStaleReference, message) }
func bytesClone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
