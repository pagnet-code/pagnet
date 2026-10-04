package identity

import (
	"context"

	"errors"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type controlRequestReceipt struct {
	RequestDigest [32]byte   `json:"requestDigest"`
	Controller    Controller `json:"controller"`
}

// AcquireController advances a durable monotonic control epoch. RequestID is a
// stable trusted-controller retry identity. Replaying it after replacement
// returns its original proof, never a new executable epoch. Every effect must
// independently recheck that proof against the CURRENT control row.
func (a *Authority) AcquireController(ctx context.Context, owner fabric.ExecutionContext, s Scope, expectedEpoch uint64, requestID, controllerID string) (Controller, error) {
	var result Controller
	if !text(requestID) || !text(controllerID) {
		return result, invalid("Invalid local controller request")
	}
	request := Controller{Scope: s, ControllerID: controllerID, RequestID: requestID, ExpectedEpoch: expectedEpoch}
	commitment, e := digest(request)
	if e != nil {
		return result, e
	}
	receiptKey := registry.AuthorityKey{Kind: registry.AuthorityController, ID: keyID("request:", s.Endpoint.String(), requestID)}
	e = a.transact(ctx, owner, s, false, func(tx *registry.AuthorityTx) error {
		existing, e := tx.Get(receiptKey)
		if e == nil {
			var receipt controlRequestReceipt
			if e = decodeValue(existing, &receipt); e != nil {
				return e
			}
			if receipt.RequestDigest != commitment || registry.VerifyAuthorityRecord(a.root, receipt.Controller.Proof) != nil {
				return conflict("Controller request identity reused with changed input")
			}
			result = receipt.Controller
			return nil
		}
		var typed *fabric.Error
		if !errors.As(e, &typed) || typed.Code != fabric.CodeNotFound {
			return e
		}
		raw, e := storedValue(request)
		if e != nil {
			return e
		}
		r, e := tx.CAS(controllerKey(s), expectedEpoch, raw, false)
		if e != nil {
			return e
		}
		result = request
		result.Proof = r
		raw, e = encode(controlRequestReceipt{commitment, result})
		if e != nil {
			return e
		}
		_, e = tx.CAS(receiptKey, 0, raw, false)
		return e
	})
	if e != nil {
		return Controller{}, e
	}
	return result, nil
}
func (a *Authority) currentController(tx *registry.AuthorityTx, c Controller) error {
	r, e := exactRecord(tx, a.root, c.Proof, controllerKey(c.Scope))
	if e != nil {
		return e
	}
	var stored Controller
	if e = decodeValue(r, &stored); e != nil {
		return e
	}
	stored.Proof = r
	one, _ := digest(c)
	two, _ := digest(stored)
	if one != two {
		return invalid("Controller proof and fields differ")
	}
	return nil
}
func (a *Authority) currentBinding(tx *registry.AuthorityTx, b Binding) error {
	r, e := exactRecord(tx, a.root, b.Proof, bindingKey(b.Scope))
	if e != nil {
		return e
	}
	var stored Binding
	if e = decodeValue(r, &stored); e != nil {
		return e
	}
	stored.Proof = r
	one, _ := digest(b)
	two, _ := digest(stored)
	if one != two {
		return invalid("Worker binding proof and fields differ")
	}
	return nil
}

// BindWorker records authenticated local ownership facts. Its caller must be
// trusted composition AFTER kernel peer + exact worker ownership authentication;
// this method does not treat the public WorkerBinding as evidence of liveness.
func (a *Authority) BindWorker(ctx context.Context, owner fabric.ExecutionContext, c Controller, expectedRevision uint64, worker WorkerBinding) (Binding, error) {
	var result Binding
	if !text(worker.WorkerID) || !text(worker.StateDirectoryID) || !text(worker.OwnershipGeneration) || !text(worker.ActualRuntime) || worker.ProfileDigest == ([32]byte{}) {
		return result, invalid("Incomplete native worker ownership binding")
	}
	e := a.transact(ctx, owner, c.Scope, false, func(tx *registry.AuthorityTx) error {
		if e := a.currentController(tx, c); e != nil {
			return e
		}
		result = Binding{Scope: c.Scope, Worker: worker}
		raw, e := storedValue(result)
		if e != nil {
			return e
		}
		r, e := tx.CAS(bindingKey(c.Scope), expectedRevision, raw, false)
		result.Proof = r
		return e
	})
	if e != nil {
		return Binding{}, e
	}
	return result, nil
}

// RenewWorkerBinding explicitly updates descriptor authorization for the SAME
// physical worker. It preserves its worker/state directory/generation/runtime /
// profile identity. Original binding proofs/capture scope remain unchanged; the
// new signed CAS proves current descriptor authorization for subsequent work.
func (a *Authority) RenewWorkerBinding(ctx context.Context, owner fabric.ExecutionContext, c Controller, original Binding) (Binding, error) {
	var result Binding
	if c.Scope.Endpoint != original.Scope.Endpoint || c.Scope.BindingID != original.Scope.BindingID {
		return result, invalid("Physical binding renewal endpoint or binding identity changed")
	}
	e := a.transact(ctx, owner, c.Scope, false, func(tx *registry.AuthorityTx) error {
		if e := a.currentController(tx, c); e != nil {
			return e
		}
		if e := a.currentBinding(tx, original); e != nil {
			// Recover the exact previous CAS after a lost acknowledgement. An old
			// signed proof is provenance only; it cannot authorize a further CAS.
			if original.Proof.Retired || original.Proof.Key != bindingKey(original.Scope) || registry.VerifyAuthorityRecord(a.root, original.Proof) != nil {
				return e
			}
			var previous Binding
			if decodeValue(original.Proof, &previous) != nil {
				return e
			}
			previous.Proof = original.Proof
			one, _ := digest(previous)
			two, _ := digest(original)
			if one != two {
				return e
			}
			current, readErr := tx.Get(bindingKey(c.Scope))
			if readErr != nil || current.Retired || registry.VerifyAuthorityRecord(a.root, current) != nil || current.Revision != original.Proof.Revision+1 {
				return e
			}
			var recovered Binding
			if decodeValue(current, &recovered) != nil || recovered.Scope != c.Scope || recovered.Worker != original.Worker {
				return e
			}
			recovered.Proof = current
			result = recovered
			return nil
		}
		if original.Scope == c.Scope {
			result = original
			return nil
		}
		result = Binding{Scope: c.Scope, Worker: original.Worker}
		raw, e := storedValue(result)
		if e != nil {
			return e
		}
		proof, e := tx.CAS(bindingKey(c.Scope), original.Proof.Revision, raw, false)
		result.Proof = proof
		return e
	})
	if e != nil {
		return Binding{}, e
	}
	return result, nil
}
