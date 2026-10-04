package identity

import (
	"context"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// NativeDispatchSpec commits trusted binder-derived operation/selector/profile.
// Capacity is explicitly configured once for each physical worker and cannot be
// changed by an invocation or a controller replacement.
type NativeDispatchSpec struct {
	OperationDigest      [32]byte `json:"operationDigest"`
	SelectorDigest       [32]byte `json:"selectorDigest"`
	SpecDigest           [32]byte `json:"specDigest"`
	MaxCommandsPerWorker int64    `json:"maxCommandsPerWorker,string"`
}

// NativeDispatchReservation is FULL-committed before asking a worker for its
// durable intent ACK. It is no native acceptance/completion claim. A failed ACK
// never reallocates this command/ordinal, including after controller takeover.
type NativeDispatchReservation struct {
	Version             string                   `json:"version"`
	OriginalCaller      fabric.Principal         `json:"originalCaller"`
	InvocationID        string                   `json:"invocationId"`
	Scope               Scope                    `json:"scope"`
	OriginalAdmissionID string                   `json:"originalAdmissionId"`
	AdmissionDigest     [32]byte                 `json:"admissionDigest"`
	OriginalDigest      [32]byte                 `json:"originalDigest"`
	FinalizedDigest     [32]byte                 `json:"finalizedDigest"`
	BindingDigest       [32]byte                 `json:"bindingDigest"`
	Worker              WorkerBinding            `json:"worker"`
	Spec                NativeDispatchSpec       `json:"spec"`
	CommandID           string                   `json:"commandId"`
	Sequence            int64                    `json:"sequence,string"`
	Proof               registry.AuthorityRecord `json:"proof"`
}
type nativeDispatchCounter struct {
	Version      string             `json:"version"`
	Endpoint     fabric.EndpointRef `json:"endpoint"`
	BindingID    string             `json:"bindingId"`
	Worker       WorkerBinding      `json:"worker"`
	MaxCommands  int64              `json:"maxCommands,string"`
	LastSequence int64              `json:"lastSequence,string"`
}

const nativeDispatchVersion = "pagnet.native-dispatch.v1"

func (r NativeDispatchReservation) Commitment() NativeIntentCommitment {
	return NativeIntentCommitment{r.CommandID, r.Sequence, r.Spec.OperationDigest, r.Spec.SelectorDigest, r.Spec.SpecDigest}
}
func validDispatchSpec(s NativeDispatchSpec) bool {
	return s.OperationDigest != ([32]byte{}) && s.SelectorDigest != ([32]byte{}) && s.SpecDigest != ([32]byte{}) && s.MaxCommandsPerWorker > 0 && s.MaxCommandsPerWorker <= 1000000
}
func dispatchKey(p fabric.Principal, invocation string) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityDispatch, ID: keyID("dispatch-invocation:", p.Ref, p.Kind, p.Issuer, invocation)}
}
func dispatchCounterKey(w WorkerBinding) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityDispatch, ID: keyID("dispatch-worker:", w.WorkerID, w.StateDirectoryID, w.OwnershipGeneration)}
}
func dispatchCommandID(root registry.AuthorityIdentity, p fabric.Principal, invocation string) string {
	return keyID("native-dispatch:", root.Namespace, root.StoreID, p.Ref, p.Kind, p.Issuer, invocation)
}
func dispatchRequestDigest(r NativeDispatchReservation) ([32]byte, error) {
	r.Proof = registry.AuthorityRecord{}
	r.CommandID = ""
	r.Sequence = 0
	return digest(r)
}
func missingDispatchRecord(e error) bool {
	var structured *fabric.Error
	return errors.As(e, &structured) && structured.Code == fabric.CodeNotFound
}

// VerifyNativeDispatchReservation authenticates an immutable retained mapping,
// not current authorization or worker liveness. Actual actuation additionally
// requires current controller/binding/source checks and the bounded worker ACK
// fence. Local workers may use authenticated sparse reservation ordinals: gaps
// caused by cancellation are not commands; older unaccepted ordinals become
// permanently stale after a newer ordinal is durably accepted.
func VerifyNativeDispatchReservation(root registry.AuthorityIdentity, r NativeDispatchReservation, source Admission, b Binding, intent NativeIntentCommitment) error {
	if r.Version != nativeDispatchVersion || !validDispatchSpec(r.Spec) || r.Sequence <= 0 || r.Sequence > r.Spec.MaxCommandsPerWorker || r.Spec.SpecDigest != b.Worker.ProfileDigest || r.CommandID != dispatchCommandID(root, r.OriginalCaller, r.InvocationID) || r.Proof.Key != dispatchKey(r.OriginalCaller, r.InvocationID) || r.Proof.Revision != 1 || r.Proof.PreviousRevision != 0 || r.Proof.Retired || registry.VerifyAuthorityRecord(root, r.Proof) != nil {
		return invalid("Native dispatch reservation proof invalid")
	}
	if r.OriginalCaller != source.OriginalCaller || r.InvocationID != source.InvocationID || r.Scope != source.Scope || r.Scope != b.Scope || r.OriginalAdmissionID != source.ID || r.OriginalDigest != source.OriginalDigest || r.FinalizedDigest != source.FinalizedDigest || r.BindingDigest != source.BindingDigest || r.Worker != b.Worker || intent != r.Commitment() {
		return conflict("Native dispatch reservation original physical or operation scope changed")
	}
	if source.Proof.Retired || source.Proof.Key != admissionKey(source.Scope, source.ID) || registry.VerifyAuthorityRecord(root, source.Proof) != nil || b.Proof.Retired || b.Proof.Key != bindingKey(b.Scope) || registry.VerifyAuthorityRecord(root, b.Proof) != nil {
		return invalid("Native dispatch reservation source or binding proof invalid")
	}
	var storedSource Admission
	if decodeValue(source.Proof, &storedSource) != nil {
		return invalid("Native dispatch source proof malformed")
	}
	storedSource.Proof = source.Proof
	one, e := digest(source)
	two, e2 := digest(storedSource)
	if e != nil || e2 != nil || one != two {
		return invalid("Native dispatch source fields differ from signed proof")
	}
	sourceDigest, e := digest(source)
	bindingDigest, e2 := digest(b)
	if e != nil || e2 != nil || sourceDigest != r.AdmissionDigest || bindingDigest != r.BindingDigest {
		return conflict("Native dispatch source or binding commitment differs")
	}
	var storedBinding Binding
	if decodeValue(b.Proof, &storedBinding) != nil {
		return invalid("Native dispatch binding proof malformed")
	}
	storedBinding.Proof = b.Proof
	storedDigest, e := digest(storedBinding)
	if e != nil || storedDigest != bindingDigest {
		return invalid("Native dispatch binding fields differ from signed proof")
	}
	var stored NativeDispatchReservation
	if decodeValue(r.Proof, &stored) != nil {
		return invalid("Native dispatch mapping proof malformed")
	}
	stored.Proof = r.Proof
	supplied, e := digest(r)
	retained, e2 := digest(stored)
	if e != nil || e2 != nil || supplied != retained {
		return invalid("Native dispatch mapping fields differ from signed proof")
	}
	return nil
}

// ReserveNativeDispatch uses only the existing signed registry/private ledger.
// The domain-global replay key includes complete original principal/invocation,
// never target/revision/binding. Changed retries cannot acquire another mapping.
// Current owner/controller/binding/original admission and configured permission
// fence remain mandatory even for exact retries. No worker/provider is called.
// Registry reservation and worker ACK are separate FULL commits, not an atomic
// distributed transaction. Error returns no alleged committed mapping; an exact
// retry reads retained state after ambiguous/lost registry acknowledgement.
func (a *Authority) ReserveNativeDispatch(ctx context.Context, owner fabric.ExecutionContext, c Controller, b Binding, source Admission, caller fabric.ExecutionContext, original, finalized []byte, spec NativeDispatchSpec) (NativeDispatchReservation, error) {
	var result NativeDispatchReservation
	if ctx == nil || ctx.Err() != nil {
		return result, fabric.NewError(fabric.CodeCancelled, "Native dispatch reservation canceled")
	}
	if !validDispatchSpec(spec) || spec.SpecDigest != b.Worker.ProfileDigest || source.Scope != c.Scope || b.Scope != c.Scope {
		return result, invalid("Incomplete native dispatch reservation commitment")
	}
	facts, _, e := a.facts(caller, c.Scope, original, finalized, source.AttemptID, source.ReplayID)
	if e != nil {
		return result, e
	}
	if facts.OriginalCaller != source.OriginalCaller || facts.InvocationID != source.InvocationID || facts.OriginalDigest != source.OriginalDigest || facts.FinalizedDigest != source.FinalizedDigest {
		return result, conflict("Native dispatch original or finalized admission differs")
	}
	bindingDigest, e := digest(b)
	if e != nil || bindingDigest != source.BindingDigest {
		return result, conflict("Native dispatch original binding differs")
	}
	admissionDigest, e := digest(source)
	if e != nil {
		return result, e
	}
	base := NativeDispatchReservation{Version: nativeDispatchVersion, OriginalCaller: facts.OriginalCaller, InvocationID: facts.InvocationID, Scope: c.Scope, OriginalAdmissionID: source.ID, AdmissionDigest: admissionDigest, OriginalDigest: facts.OriginalDigest, FinalizedDigest: facts.FinalizedDigest, BindingDigest: bindingDigest, Worker: b.Worker, Spec: spec}
	requestDigest, e := dispatchRequestDigest(base)
	if e != nil {
		return result, e
	}
	lifetime, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	e = a.withFence(lifetime, facts, func(Witness) error {
		return a.transact(lifetime, owner, c.Scope, false, func(tx *registry.AuthorityTx) error {
			if e := a.currentController(tx, c); e != nil {
				return e
			}
			if e := a.currentBinding(tx, b); e != nil {
				return e
			}
			if e := a.originalAdmission(tx, source); e != nil {
				return e
			}
			key := dispatchKey(facts.OriginalCaller, facts.InvocationID)
			record, e := tx.Get(key)
			if e == nil {
				var retained NativeDispatchReservation
				if decodeValue(record, &retained) != nil {
					return invalid("Retained native dispatch mapping malformed")
				}
				retained.Proof = record
				old, e := dispatchRequestDigest(retained)
				if e != nil || old != requestDigest {
					return conflict("Native invocation already reserved a different original dispatch")
				}
				if e := VerifyNativeDispatchReservation(a.root, retained, source, b, retained.Commitment()); e != nil {
					return e
				}
				result = retained
				return nil
			}
			if !missingDispatchRecord(e) {
				return e
			}
			counterKey := dispatchCounterKey(b.Worker)
			counterRecord, e := tx.Get(counterKey)
			var expected uint64
			counter := nativeDispatchCounter{Version: nativeDispatchVersion, Endpoint: c.Scope.Endpoint, BindingID: c.Scope.BindingID, Worker: b.Worker, MaxCommands: spec.MaxCommandsPerWorker}
			if e == nil {
				if counterRecord.Retired || registry.VerifyAuthorityRecord(a.root, counterRecord) != nil || decodeValue(counterRecord, &counter) != nil || counter.Version != nativeDispatchVersion || counter.Endpoint != c.Scope.Endpoint || counter.BindingID != c.Scope.BindingID || counter.Worker != b.Worker || counter.MaxCommands != spec.MaxCommandsPerWorker || counter.LastSequence <= 0 || counter.LastSequence > counter.MaxCommands {
					return conflict("Native physical worker counter changed or retired")
				}
				expected = counterRecord.Revision
			} else if !missingDispatchRecord(e) {
				return e
			}
			if counter.LastSequence >= counter.MaxCommands {
				return invalid("Native physical worker dispatch capacity exhausted")
			}
			counter.LastSequence++
			raw, e := encode(counter)
			if e != nil {
				return e
			}
			if _, e = tx.CAS(counterKey, expected, raw, false); e != nil {
				return e
			}
			base.CommandID = dispatchCommandID(a.root, facts.OriginalCaller, facts.InvocationID)
			base.Sequence = counter.LastSequence
			raw, e = storedValue(base)
			if e != nil {
				return e
			}
			record, e = tx.CAS(key, 0, raw, false)
			if e != nil {
				return e
			}
			base.Proof = record
			if e = VerifyNativeDispatchReservation(a.root, base, source, b, base.Commitment()); e != nil {
				return e
			}
			result = base
			return nil
		})
	})
	if e != nil {
		return NativeDispatchReservation{}, e
	}
	return result, nil
}
