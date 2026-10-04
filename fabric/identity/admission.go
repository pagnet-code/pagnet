package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func (a *Authority) facts(caller fabric.ExecutionContext, s Scope, original, finalized []byte, attemptID, replayID string) (AdmissionFacts, fabric.Envelope, error) {
	var facts AdmissionFacts
	originalEnv, e := caller.DecodeVerifiedEnvelope(original, a.root.Namespace)
	if e != nil {
		return facts, fabric.Envelope{}, e
	}
	var final fabric.Envelope
	if e = fabric.DecodeJSON(finalized, &final); e != nil {
		return facts, final, e
	}
	if e = final.Validate(); e != nil {
		return facts, final, e
	}
	if final.Operation != fabric.OperationInvoke || final.Target == nil || *final.Target != s.Endpoint || final.ExpectedRevision != s.DescriptorRevision || !text(attemptID) || !text(replayID) {
		return facts, final, invalid("Final local invocation scope or retry identity invalid")
	}
	// This is not authentication of transformed bytes. Exact caller/system fields
	// stay immutable and the separate finalized admission authorizes the transform.
	x, y := originalEnv, final
	x.Payload = nil
	y.Payload = nil
	x.Metadata = nil
	y.Metadata = nil
	x.Target = nil
	y.Target = nil
	x.ExpectedRevision = ""
	y.ExpectedRevision = ""
	xb, _ := encode(x)
	yb, _ := encode(y)
	if !bytes.Equal(xb, yb) {
		return facts, final, invalid("Finalized invocation changed authenticated caller or provenance")
	}
	if final.Context.Deadline != nil && !time.Now().Before(*final.Context.Deadline) {
		return facts, final, invalid("Finalized local invocation expired")
	}
	facts = AdmissionFacts{Scope: s, OriginalCaller: caller.PrincipalView(), Provenance: caller.ProvenanceView(), OriginalDigest: sha256.Sum256(original), FinalizedDigest: sha256.Sum256(finalized), OriginalBytes: bytes.Clone(original), FinalizedBytes: bytes.Clone(finalized), InvocationID: final.ID, AttemptID: attemptID, ReplayID: replayID}
	return facts, final, nil
}
func validWitness(w Witness, facts AdmissionFacts) error {
	if !text(w.Version) || w.FinalizedDigest != facts.FinalizedDigest || len(w.Value) > 16<<10 {
		return invalid("Admission fence witness malformed or changed finalized digest")
	}
	var bounded any
	return fabric.DecodeJSONWithLimits(w.Value, &bounded, fabric.WireLimits{MaxBytes: 16 << 10, MaxDepth: 16, MaxMembers: 512})
}
func admissionRequestDigest(v Admission) ([32]byte, error) {
	v.Proof = registry.AuthorityRecord{}
	v.OriginalControllerEpoch = 0
	v.CallerSignature = nil
	v.DispatchSignature = nil
	v.CallerFrame = fabric.CallerProofFrame{}
	v.DispatchFrame = fabric.DispatchAdmissionFrame{}
	v.Witness = Witness{}
	return digest(v)
}

// Admit records original authenticated caller identity and exact transformed
// dispatch, with a configured authorization fence held THROUGH SQLite COMMIT.
// A retry preserves its original controller admission. No native execution is
// started by this method; origin admission and actual native ownership remain
// separate boundaries.
func (a *Authority) Admit(ctx context.Context, owner fabric.ExecutionContext, c Controller, b Binding, caller fabric.ExecutionContext, original, finalized []byte, id, attemptID, replayID string) (Admission, error) {
	var result Admission
	if !text(id) || b.Scope != c.Scope {
		return result, invalid("Local admission identity or binding scope invalid")
	}
	facts, env, e := a.facts(caller, c.Scope, original, finalized, attemptID, replayID)
	if e != nil {
		return result, e
	}
	bindingDigest, e := digest(b)
	if e != nil {
		return result, e
	}
	base := Admission{ID: id, Scope: c.Scope, OriginalCaller: facts.OriginalCaller, Provenance: facts.Provenance, OriginalDigest: facts.OriginalDigest, FinalizedDigest: facts.FinalizedDigest, InvocationID: facts.InvocationID, AttemptID: attemptID, ReplayID: replayID, OriginalControllerEpoch: c.Epoch(), BindingDigest: bindingDigest}
	if env.Context.Deadline != nil {
		base.Deadline = env.Context.Deadline.UTC().Format(time.RFC3339Nano)
	}
	requestDigest, e := admissionRequestDigest(base)
	if e != nil {
		return result, e
	}
	e = a.withFence(ctx, facts, func(w Witness) error {
		return a.transact(ctx, owner, c.Scope, false, func(tx *registry.AuthorityTx) error {
			if e := a.currentController(tx, c); e != nil {
				return e
			}
			if e := a.currentBinding(tx, b); e != nil {
				return e
			}
			existing, e := tx.Get(admissionKey(c.Scope, id))
			if e == nil {
				var stored Admission
				if e = decodeValue(existing, &stored); e != nil {
					return e
				}
				got, e := admissionRequestDigest(stored)
				if e != nil || got != requestDigest || existing.Retired {
					return conflict("Admission identity reused with changed original or final dispatch")
				}
				stored.Proof = existing
				result = stored
				return nil
			}
			var typed *fabric.Error
			if !errors.As(e, &typed) || typed.Code != fabric.CodeNotFound {
				return e
			}
			base.Witness = w
			base.CallerFrame = fabric.CallerProofFrame{SourceDomain: a.root.Namespace, CallerRef: base.OriginalCaller.Ref, IssuerKeyRevision: a.root.KeyRevision, AudienceDomain: a.root.Namespace, Operation: env.Operation, OriginalEnvelopeID: env.ID, ReplayID: replayID, OriginalEnvelopeDigest: facts.OriginalDigest, Deadline: base.Deadline}
			base.CallerSignature, e = tx.SignCallerProof(caller, original, base.CallerFrame)
			if e != nil {
				return e
			}
			base.DispatchFrame = fabric.DispatchAdmissionFrame{SourceDomain: a.root.Namespace, CallerRef: base.OriginalCaller.Ref, AudienceDomain: a.root.Namespace, InvocationID: env.ID, AttemptID: attemptID, ReplayID: replayID, FinalizedDispatchDigest: facts.FinalizedDigest, Deadline: base.Deadline}
			base.DispatchSignature, e = tx.SignDispatchAdmission(caller, original, finalized, base.DispatchFrame)
			if e != nil {
				return e
			}
			raw, e := storedValue(base)
			if e != nil {
				return e
			}
			record, e := tx.CAS(admissionKey(c.Scope, id), 0, raw, false)
			if e != nil {
				return e
			}
			base.Proof = record
			result = base
			return nil
		})
	})
	// Keep known committed evidence when a buggy infrastructure fence fails after
	// invoking commit. Error still forbids actuation; retries remain immutable.
	return result, e
}
