package identity

import (
	"context"
	"errors"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// HistoricalNativeOriginFacts carries current control separately from exact
// original admission. No transformed revision is substituted into caller bytes.
type HistoricalNativeOriginFacts struct {
	Current          NativeControlFacts
	OriginalBinding  Binding
	Original         AdmissionFacts
	Admission        Admission
	NativeGeneration string
}
type HistoricalNativeOriginFence interface {
	WithHistoricalNativeOrigin(context.Context, HistoricalNativeOriginFacts, func(Witness) error) error
}

// RegisterHistoricalOrigin continues an already admitted original source on the
// SAME physical worker after a descriptor-only authorization change. It is a
// distinct purpose requiring explicit current policy, not old witness replay.
func (a *Authority) RegisterHistoricalOrigin(ctx context.Context, owner fabric.ExecutionContext, current Controller, currentBinding, originalBinding Binding, source Admission, caller fabric.ExecutionContext, original, finalized []byte, id, generation string) (result Origin, err error) {
	if ctx == nil || !text(id) || !text(generation) || current.Scope != currentBinding.Scope || source.Scope != originalBinding.Scope || source.Scope.Endpoint != current.Scope.Endpoint || source.Scope.BindingID != current.Scope.BindingID || originalBinding.Worker != currentBinding.Worker {
		return result, invalid("Historical native origin physical scope differs")
	}
	fence, ok := a.fence.(HistoricalNativeOriginFence)
	if !ok {
		return result, fabric.NewError(fabric.CodeUnsupported, "Configured authority does not support historical native origin fencing")
	}
	if originalBinding.Proof.Retired || originalBinding.Proof.Key != bindingKey(originalBinding.Scope) || registry.VerifyAuthorityRecord(a.root, originalBinding.Proof) != nil {
		return result, invalid("Original native binding proof invalid")
	}
	var signed Binding
	if decodeValue(originalBinding.Proof, &signed) != nil {
		return result, invalid("Original native binding proof malformed")
	}
	signed.Proof = originalBinding.Proof
	x, e := digest(signed)
	y, e2 := digest(originalBinding)
	if e != nil || e2 != nil || x != y || y != source.BindingDigest {
		return result, invalid("Original native binding fields differ")
	}
	facts, env, e := a.facts(caller, source.Scope, original, finalized, source.AttemptID, source.ReplayID)
	if e != nil {
		return result, e
	}
	facts = withNativeSourceFacts(facts, PurposeNativeOrigin, source)
	if facts.OriginalDigest != source.OriginalDigest || facts.FinalizedDigest != source.FinalizedDigest || facts.OriginalCaller != source.OriginalCaller {
		return result, invalid("Historical original admission bytes changed")
	}
	sourceDigest, e := digest(source)
	if e != nil {
		return result, e
	}
	prepared, preparationErr := a.store.PrepareInvocationTarget(ctx, source.Target, source.TargetRevision, env.Payload)
	base := Origin{ID: id, Scope: source.Scope, AdmissionID: source.ID, AdmissionDigest: sourceDigest, OriginalControllerEpoch: source.OriginalControllerEpoch, RegisteredControllerEpoch: current.Epoch(), Worker: originalBinding.Worker, NativeGeneration: generation}
	commitment, e := originRequestDigest(base)
	if e != nil {
		return result, e
	}
	lifetime, cancel := context.WithTimeout(ctx, 5e9)
	defer cancel()
	control := NativeControlFacts{Scope: current.Scope, Owner: a.root.Owner, Controller: current, Binding: currentBinding}
	fenceFacts := HistoricalNativeOriginFacts{Current: control, OriginalBinding: originalBinding, Original: facts, Admission: source, NativeGeneration: generation}
	var mu sync.Mutex
	active := true
	calls := 0
	defer func() {
		mu.Lock()
		active = false
		mu.Unlock()
		if recover() != nil {
			err = fabric.NewError(fabric.CodeProtocolError, "Historical native origin fence panicked")
		}
	}()
	err = fence.WithHistoricalNativeOrigin(lifetime, fenceFacts, func(w Witness) error {
		mu.Lock()
		defer mu.Unlock()
		if !active || calls != 0 {
			return invalid("Historical native origin fence callback closed or reused")
		}
		calls++
		if e := validWitness(w, facts); e != nil {
			return e
		}
		return a.transact(lifetime, owner, current.Scope, false, func(tx *registry.AuthorityTx) error {
			if e := a.currentController(tx, current); e != nil {
				return e
			}
			if e := a.currentBinding(tx, currentBinding); e != nil {
				return e
			}
			if e := a.originalAdmission(tx, source); e != nil {
				return e
			}
			if source.Target.IsOffer() {
				if preparationErr != nil {
					return preparationErr
				}
				if e := verifySelectedSource(tx, source, env, prepared); e != nil {
					return e
				}
			}
			if _, e := tx.Get(retirementKey(source.Scope, id)); e == nil {
				return conflict("Original native generation permanently retired")
			} else {
				var typed *fabric.Error
				if !errors.As(e, &typed) || typed.Code != fabric.CodeNotFound {
					return e
				}
			}
			existing, e := tx.Get(originKey(source.Scope, id))
			if e == nil {
				var stored Origin
				if decodeValue(existing, &stored) != nil {
					return invalid("Historical origin proof malformed")
				}
				got, e := originRequestDigest(stored)
				if e != nil || got != commitment || existing.Retired {
					return conflict("Historical native origin identity changed")
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
			proof, e := tx.CAS(originKey(source.Scope, id), 0, raw, false)
			if e != nil {
				return e
			}
			base.Proof = proof
			result = base
			return nil
		})
	})
	mu.Lock()
	active = false
	if err == nil && calls != 1 {
		err = invalid("Historical native origin fence did not authorize registration")
	}
	mu.Unlock()
	if err != nil {
		var typed *fabric.Error
		if !errors.As(err, &typed) {
			err = fabric.NewError(fabric.CodeProtocolError, "Historical native origin fence failed")
		}
	}
	return result, err
}
