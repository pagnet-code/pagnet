package nativeauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// IntentRequest is the bounded private wire form. Exact native bytes are derived
// again by the worker's trusted binder; duplicating a maximum-size finalized
// prompt alongside its derived operation would exceed the private frame budget.
// Ownership always comes from the worker bootstrap, never this request.
type IntentRequest struct {
	CurrentBinding    fabricidentity.Binding                   `json:"currentBinding"`
	CurrentController fabricidentity.Controller                `json:"currentController"`
	OriginalAdmission fabricidentity.Admission                 `json:"originalAdmission"`
	Commitment        fabricidentity.NativeIntentCommitment    `json:"commitment"`
	Reservation       fabricidentity.NativeDispatchReservation `json:"reservation"`
	Finalized         json.RawMessage                          `json:"finalized"`
	OriginalBinding   *fabricidentity.Binding                  `json:"originalBinding,omitempty"`
}

func (i VerifiedIntent) Request() IntentRequest {
	return IntentRequest{CurrentBinding: i.CurrentBinding, CurrentController: i.CurrentController, OriginalAdmission: i.OriginalAdmission, Commitment: i.Commitment, Reservation: i.Reservation, Finalized: bytes.Clone(i.Finalized), OriginalBinding: i.OriginalBinding}
}
func (i IntentRequest) Verify(pinned Scope, binder OperationBinder) (VerifiedIntent, error) {
	return i.verify(pinned, binder, false)
}
func (i IntentRequest) VerifyCancellation(pinned Scope, binder OperationBinder) (VerifiedIntent, error) {
	return i.verify(pinned, binder, true)
}
func (i IntentRequest) verify(pinned Scope, binder OperationBinder, cancellation bool) (VerifiedIntent, error) {
	var final fabric.Envelope
	if e := fabric.DecodeJSON(i.Finalized, &final); e != nil {
		return VerifiedIntent{}, e
	}
	if binder == nil {
		return VerifiedIntent{}, errors.New("local native binder missing")
	}
	operation, e := binder.Bind(final)
	if e != nil {
		return VerifiedIntent{}, e
	}
	intent := VerifiedIntent{Scope: pinned, CurrentBinding: i.CurrentBinding, CurrentController: i.CurrentController, OriginalAdmission: i.OriginalAdmission, Commitment: i.Commitment, Reservation: i.Reservation, Operation: operation, Finalized: bytes.Clone(i.Finalized), OriginalBinding: i.OriginalBinding}
	if e = validateIntent(pinned, binder, intent, cancellation); e != nil {
		return VerifiedIntent{}, e
	}
	return intent, nil
}

// ValidateIntent checks immutable signatures and the trusted binder against the
// worker's independently pinned ownership. It does not claim a signed controller
// is current: the controller must hold FenceNativeIntent through the durable ACK,
// and the journal independently fences its retained highest controller epoch.
func ValidateIntent(pinned Scope, binder OperationBinder, i VerifiedIntent) error {
	return validateIntent(pinned, binder, i, false)
}

// ValidateCancellationIntent authenticates the exact retained source without
// treating its expired paid-work deadline as a reason to refuse cancellation.
// This historical verifier never authorizes a new paid effect.
func ValidateCancellationIntent(pinned Scope, binder OperationBinder, i VerifiedIntent) error {
	return validateIntent(pinned, binder, i, true)
}
func validateIntent(pinned Scope, binder OperationBinder, i VerifiedIntent, cancellation bool) error {
	local, ok := pinned.Local()
	if !ok || pinned != i.Scope || binder == nil || pinned.Validate() != nil {
		return errors.New("local native intent ownership differs")
	}
	root := registry.AuthorityIdentity{Namespace: local.Namespace, StoreID: local.StoreID, Owner: local.Owner, PublicKey: local.PublicKey[:], KeyRevision: local.KeyRevision}
	originalBinding := i.CurrentBinding
	if i.OriginalBinding != nil {
		if !cancellation {
			return errors.New("fresh native intent cannot carry historical binding")
		}
		originalBinding = *i.OriginalBinding
	}
	originalScope, e := NewLocalScope(root, originalBinding)
	if e != nil || !pinned.SamePhysical(originalScope) || originalBinding.Scope != i.OriginalAdmission.Scope {
		return errors.New("local native original binding differs")
	}
	currentScope, e := NewLocalScope(root, i.CurrentBinding)
	if e != nil || !pinned.SamePhysical(currentScope) || i.CurrentBinding.Scope != i.CurrentController.Scope {
		return errors.New("local native intent binding differs")
	}
	controllerFields, _ := json.Marshal([]string{local.Endpoint.String(), local.BindingID})
	controllerID := sha256.Sum256(controllerFields)
	controllerKey := registry.AuthorityKey{Kind: registry.AuthorityController, ID: "current:" + hex.EncodeToString(controllerID[:])}
	var controller fabricidentity.Controller
	if e = verifyRecord(root, i.CurrentController.Proof, controllerKey, &controller); e != nil {
		return e
	}
	controller.Proof = i.CurrentController.Proof
	if !sameJSON(controller, i.CurrentController) {
		return errors.New("local native controller fields differ from signed proof")
	}
	var source fabricidentity.Admission
	if e = verifyRecord(root, i.OriginalAdmission.Proof, registry.AuthorityKey{Kind: registry.AuthorityAdmission, Endpoint: local.Endpoint, ID: i.OriginalAdmission.ID}, &source); e != nil {
		return e
	}
	source.Proof = i.OriginalAdmission.Proof
	bindingBytes, _ := json.Marshal(originalBinding)
	if !sameJSON(source, i.OriginalAdmission) || source.BindingDigest != sha256.Sum256(bindingBytes) || source.FinalizedDigest != sha256.Sum256(i.Finalized) || source.OriginalControllerEpoch == 0 || source.OriginalControllerEpoch > controller.Epoch() {
		return errors.New("local native original admission differs from signed source")
	}
	var final fabric.Envelope
	if e = fabric.DecodeJSON(i.Finalized, &final); e != nil || final.Validate() != nil || final.Target == nil || *final.Target != source.Target || source.Target.Endpoint() != local.Endpoint || final.ExpectedRevision != source.TargetRevision || final.ID != source.InvocationID {
		return errors.New("local native finalized invocation differs")
	}
	if !cancellation && final.Context.Deadline != nil && !time.Now().Before(*final.Context.Deadline) {
		return errors.New("local native finalized invocation expired")
	}
	operation, e := binder.Bind(final)
	if e != nil || operation.Kind != i.Operation.Kind || operation.SpecDigest != local.ProfileDigest || operation.SpecDigest != i.Operation.SpecDigest || !bytes.Equal(operation.Payload, i.Operation.Payload) || len(operation.Payload) > MaxNativeOperationBytes {
		return errors.New("local native operation differs from finalized invocation")
	}
	selector, _ := json.Marshal(struct {
		Purpose, Kind string
		SpecDigest    [32]byte
	}{"pagnet.native-local-selector.v1", operation.Kind, operation.SpecDigest})
	c := i.Commitment
	if !text(c.CommandID, 256) || c.Sequence <= 0 || c.Sequence == 9223372036854775807 || c.OperationDigest != sha256.Sum256(operation.Payload) || c.SelectorDigest != sha256.Sum256(selector) || c.SpecDigest != local.ProfileDigest {
		return errors.New("local native intent commitment differs")
	}
	return fabricidentity.VerifyNativeDispatchReservation(root, i.Reservation, i.OriginalAdmission, originalBinding, c)
}

func sameJSON(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func verifyRecord(root registry.AuthorityIdentity, proof registry.AuthorityRecord, key registry.AuthorityKey, value any) error {
	if proof.Retired || proof.Key != key || registry.VerifyAuthorityRecord(root, proof) != nil {
		return errors.New("local native authority signature or scope differs")
	}
	return fabric.DecodeJSON(proof.Value, value)
}

// ValidateOriginalAdmission authenticates retained historical provenance only;
// it cannot authorize a new native operation or establish a current controller.
func ValidateOriginalAdmission(pinned Scope, source fabricidentity.Admission) error {
	local, ok := pinned.Local()
	if !ok || pinned.Validate() != nil || source.Scope.Endpoint != local.Endpoint || source.Target.Endpoint() != local.Endpoint || source.TargetRevision == "" || source.Scope.BindingID != local.BindingID || source.ID == "" || source.OriginalControllerEpoch == 0 {
		return errors.New("local native source scope differs")
	}
	root := registry.AuthorityIdentity{Namespace: local.Namespace, StoreID: local.StoreID, Owner: local.Owner, PublicKey: local.PublicKey[:], KeyRevision: local.KeyRevision}
	var stored fabricidentity.Admission
	if e := verifyRecord(root, source.Proof, registry.AuthorityKey{Kind: registry.AuthorityAdmission, Endpoint: local.Endpoint, ID: source.ID}, &stored); e != nil {
		return e
	}
	stored.Proof = source.Proof
	if !sameJSON(stored, source) {
		return errors.New("local native source fields differ from proof")
	}
	return nil
}

// ValidateOriginalOrigin binds original source admission to an actual worker
// activation generation. This authenticates historical provenance, not current
// liveness or authorization to reactivate/resolve a native choice.
func ValidateOriginalOrigin(pinned Scope, source fabricidentity.Admission, origin fabricidentity.Origin, generation string) error {
	if e := ValidateOriginalAdmission(pinned, source); e != nil {
		return e
	}
	local, _ := pinned.Local()
	root := registry.AuthorityIdentity{Namespace: local.Namespace, StoreID: local.StoreID, Owner: local.Owner, PublicKey: local.PublicKey[:], KeyRevision: local.KeyRevision}
	var stored fabricidentity.Origin
	if e := verifyRecord(root, origin.Proof, registry.AuthorityKey{Kind: registry.AuthorityOrigin, Endpoint: local.Endpoint, ID: origin.ID}, &stored); e != nil {
		return e
	}
	stored.Proof = origin.Proof
	exactSource, _ := json.Marshal(source)
	expectedWorker := fabricidentity.WorkerBinding{WorkerID: local.WorkerID, StateDirectoryID: local.StateDirectoryID, OwnershipGeneration: local.OwnershipGeneration, ActualRuntime: local.ActualRuntime, ProfileDigest: local.ProfileDigest}
	if !sameJSON(stored, origin) || origin.Scope != source.Scope || origin.Worker != expectedWorker || origin.AdmissionID != source.ID || origin.AdmissionDigest != sha256.Sum256(exactSource) || origin.OriginalControllerEpoch != source.OriginalControllerEpoch || generation == "" || origin.NativeGeneration != generation {
		return errors.New("local native activation origin differs from original source")
	}
	return nil
}
