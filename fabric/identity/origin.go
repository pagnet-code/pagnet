package identity

import (
	"bytes"
	"context"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func (a *Authority) originalAdmission(tx *registry.AuthorityTx, v Admission) error {
	r, e := exactRecord(tx, a.root, v.Proof, admissionKey(v.Scope, v.ID))
	if e != nil {
		return e
	}
	var stored Admission
	if e = decodeValue(r, &stored); e != nil {
		return e
	}
	stored.Proof = r
	one, _ := digest(v)
	two, _ := digest(stored)
	if one != two {
		return invalid("Original admission fields differ from durable proof")
	}
	return nil
}
func (a *Authority) originalOrigin(tx *registry.AuthorityTx, v Origin) error {
	r, e := exactRecord(tx, a.root, v.Proof, originKey(v.Scope, v.ID))
	if e != nil {
		return e
	}
	var stored Origin
	if e = decodeValue(r, &stored); e != nil {
		return e
	}
	stored.Proof = r
	one, _ := digest(v)
	two, _ := digest(stored)
	if one != two {
		return invalid("Original origin fields differ from durable proof")
	}
	return nil
}
func originRequestDigest(v Origin) ([32]byte, error) {
	v.Proof = registry.AuthorityRecord{}
	v.RegisteredControllerEpoch = 0
	v.Witness = Witness{}
	return digest(v)
}

// RegisterOrigin registers BEFORE a genuine native activation, preserving the
// exact source admission A while checking current controller B and current
// worker/descriptor bindings. It grants no process liveness; that requires
// independent supervisor/kernel proof in the native adapter.
func (a *Authority) RegisterOrigin(ctx context.Context, owner fabric.ExecutionContext, c Controller, b Binding, source Admission, caller fabric.ExecutionContext, original, finalized []byte, id, nativeGeneration string) (Origin, error) {
	var result Origin
	if !text(id) || !text(nativeGeneration) || source.Scope != c.Scope || b.Scope != c.Scope {
		return result, invalid("Native origin scope or generation invalid")
	}
	facts, env, e := a.facts(caller, c.Scope, original, finalized, source.AttemptID, source.ReplayID)
	if e != nil {
		return result, e
	}
	facts = withNativeSourceFacts(facts, PurposeNativeOrigin, source)
	if facts.OriginalDigest != source.OriginalDigest || facts.FinalizedDigest != source.FinalizedDigest || facts.OriginalCaller != source.OriginalCaller {
		return result, invalid("Native origin original admission bytes differ")
	}
	bound, e := digest(b)
	if e != nil || bound != source.BindingDigest {
		return result, conflict("Native original worker binding changed")
	}
	admissionDigest, e := digest(source)
	if e != nil {
		return result, e
	}
	prepared, preparationErr := a.store.PrepareInvocationTarget(ctx, source.Target, source.TargetRevision, env.Payload)
	base := Origin{ID: id, Scope: c.Scope, AdmissionID: source.ID, AdmissionDigest: admissionDigest, OriginalControllerEpoch: source.OriginalControllerEpoch, RegisteredControllerEpoch: c.Epoch(), Worker: b.Worker, NativeGeneration: nativeGeneration}
	commitment, e := originRequestDigest(base)
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
			if e := a.originalAdmission(tx, source); e != nil {
				return e
			}
			if preparationErr != nil {
				return preparationErr
			}
			if e := verifySelectedSource(tx, source, env, prepared); e != nil {
				return e
			}
			if _, e := tx.Get(retirementKey(c.Scope, id)); e == nil {
				return conflict("Native origin generation permanently retired")
			} else {
				var typed *fabric.Error
				if !errors.As(e, &typed) || typed.Code != fabric.CodeNotFound {
					return e
				}
			}
			existing, e := tx.Get(originKey(c.Scope, id))
			if e == nil {
				var stored Origin
				if e = decodeValue(existing, &stored); e != nil {
					return e
				}
				got, e := originRequestDigest(stored)
				if e != nil || got != commitment || existing.Retired {
					return conflict("Native origin identity reused with changed source or generation")
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
			raw, e := storedValue(base)
			if e != nil {
				return e
			}
			record, e := tx.CAS(originKey(c.Scope, id), 0, raw, false)
			if e != nil {
				return e
			}
			base.Proof = record
			result = base
			return nil
		})
	})
	return result, e
}

// CommitSource records history-only evidence after exact original-origin
// verification. Current registry owner authentication remains mandatory even
// after endpoint retirement. It cannot reactivate a native process or choice.
func (a *Authority) CommitSource(ctx context.Context, owner fabric.ExecutionContext, origin Origin, outcome SourceOutcome) (registry.AuthorityRecord, error) {
	var result registry.AuthorityRecord
	if outcome.OriginID != origin.ID || outcome.NativeGeneration != origin.NativeGeneration || !text(outcome.SourceID) || !text(outcome.NativeSessionID) || outcome.CiphertextCommitment == ([32]byte{}) {
		return result, invalid("Native source scope or ciphertext commitment invalid")
	}
	switch outcome.Effect {
	case fabric.EffectUnknown, fabric.EffectNotStarted, fabric.EffectCompleted:
	default:
		return result, invalid("Native source effect invalid")
	}
	e := a.transact(ctx, owner, origin.Scope, true, func(tx *registry.AuthorityTx) error {
		if e := a.originalOrigin(tx, origin); e != nil {
			return e
		}
		raw, e := encode(outcome)
		if e != nil {
			return e
		}
		result, e = tx.CAS(registry.AuthorityKey{Kind: registry.AuthoritySource, Endpoint: origin.Scope.Endpoint, ID: keyID("source:", origin.ID, outcome.SourceID)}, 0, raw, false)
		return e
	})
	if e != nil {
		return registry.AuthorityRecord{}, e
	}
	return result, nil
}

// RetireOrigin preserves signed history while permanently preventing activation
// under this original generation. Source receipts may still settle its history.
func (a *Authority) RetireOrigin(ctx context.Context, owner fabric.ExecutionContext, origin Origin, reason string) (registry.AuthorityRecord, error) {
	var result registry.AuthorityRecord
	if !text(reason) {
		return result, invalid("Native origin retirement reason invalid")
	}
	e := a.transact(ctx, owner, origin.Scope, true, func(tx *registry.AuthorityTx) error {
		if e := a.originalOrigin(tx, origin); e != nil {
			return e
		}
		commitment, e := digest(origin)
		if e != nil {
			return e
		}
		raw, e := encode(struct {
			OriginDigest [32]byte `json:"originDigest"`
			Reason       string   `json:"reason"`
		}{commitment, reason})
		if e != nil {
			return e
		}
		result, e = tx.CAS(retirementKey(origin.Scope, origin.ID), 0, raw, false)
		return e
	})
	if e != nil {
		return registry.AuthorityRecord{}, e
	}
	return result, nil
}
func retirementKey(s Scope, id string) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityRetirement, Endpoint: s.Endpoint, ID: keyID("retired:", id)}
}

func (a *Authority) RetireWorker(ctx context.Context, owner fabric.ExecutionContext, c Controller, b Binding) (registry.AuthorityRecord, error) {
	var result registry.AuthorityRecord
	if c.Scope != b.Scope {
		return result, invalid("Worker retirement scope differs")
	}
	e := a.transact(ctx, owner, c.Scope, false, func(tx *registry.AuthorityTx) error {
		if e := a.currentController(tx, c); e != nil {
			return e
		}
		raw, e := storedValue(Binding{Scope: b.Scope, Worker: b.Worker})
		if e != nil {
			return e
		}
		current, e := tx.Get(bindingKey(b.Scope))
		if e != nil {
			return e
		}
		if current.Retired {
			if b.Proof.Key != bindingKey(b.Scope) || registry.VerifyAuthorityRecord(a.root, b.Proof) != nil || current.PreviousRevision != b.Proof.Revision || !bytes.Equal(current.Value, raw) {
				return conflict("Worker retirement proof differs")
			}
			var original Binding
			if e = decodeValue(b.Proof, &original); e != nil {
				return e
			}
			original.Proof = b.Proof
			one, _ := digest(original)
			two, _ := digest(b)
			if one != two {
				return invalid("Worker retirement original fields differ")
			}
			result = current
			return nil
		}
		if e := a.currentBinding(tx, b); e != nil {
			return e
		}
		result, e = tx.CAS(bindingKey(b.Scope), b.Proof.Revision, raw, true)
		return e
	})
	if e != nil {
		return registry.AuthorityRecord{}, e
	}
	return result, nil
}
