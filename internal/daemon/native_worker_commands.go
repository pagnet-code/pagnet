package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// BindOwnership authenticates the backend's exact immutable scope before any
// original command can enter this private worker's durable dispatch lane.
func (p *NativeWorkerProxy) BindOwnership(ctx context.Context, o transport.NativeWorkerOwnership) error {
	if err := validateOwnership(p.scope, p.bootstrap.Native, o.Profile, &o); err != nil {
		return err
	}
	_, err := p.call(ctx, sessionworker.Request{Type: "ownership_bind", Ownership: &o})
	return err
}

// AcceptDispatch returns after the original command and source have fsynced in
// the independent worker. It does not wait for the runtime turn to complete.
func (p *NativeWorkerProxy) AcceptDispatch(ctx context.Context, o transport.NativeWorkerOwnership, proof transport.NativeDispatchProof, kind string, operation sessionworker.Operation) (sessionworker.Outcome, error) {
	if proof.OwnershipID != o.ID || proof.OwnershipGeneration != p.scope.Generation || proof.SourceCommandID == "" {
		return sessionworker.Outcome{}, ErrNativeObservationConflict
	}
	if err := p.BindOwnership(ctx, o); err != nil {
		return sessionworker.Outcome{}, err
	}
	payload, err := json.Marshal(operation)
	if err != nil {
		return sessionworker.Outcome{}, err
	}
	response, err := p.call(ctx, sessionworker.Request{Type: "dispatch", CommandID: proof.SourceCommandID, Kind: kind, Payload: payload, NativeDispatch: &proof})
	if err != nil {
		return sessionworker.Outcome{}, err
	}
	if response.Outcome == nil || response.Outcome.CommandID != proof.SourceCommandID || response.Outcome.Kind != kind || response.Outcome.SourceAdmission == nil || response.Outcome.SourceAdmission.NativeAdmissionID != proof.SourceAdmissionID {
		return sessionworker.Outcome{}, ErrNativeObservationConflict
	}
	if response.Outcome.State == "uncertain" {
		return *response.Outcome, errors.New("original native command has an uncertain outcome; it cannot be replayed")
	}
	return *response.Outcome, nil
}

// SettleDispatches retains the original mapping across acknowledgement loss.
// The backend must commit the settled contiguous floor before local pruning.
func (p *NativeWorkerProxy) SettleDispatches(ctx context.Context, ownership transport.NativeWorkerOwnership) (*transport.NativeWorkerOwnership, error) {
	response, err := p.call(ctx, sessionworker.Request{Type: "dispatches"})
	if err != nil {
		return nil, err
	}
	floor := ownership.RetiredFloor
	for _, r := range response.Dispatches {
		if r.Proof.OwnershipID != ownership.ID || r.Proof.OwnershipGeneration != p.scope.Generation {
			return nil, ErrNativeObservationConflict
		}
		if r.Proof.DispatchSequence != floor+1 || (r.State != "completed" && r.State != "failed" && r.State != "cancelled") {
			break
		}
		if r.State != "cancelled" {
			if _, err = p.call(ctx, sessionworker.Request{Type: "ack", Sequence: r.OperationSequence}); err != nil {
				return nil, err
			}
		}
		floor = r.Proof.DispatchSequence
	}
	if floor == ownership.RetiredFloor {
		return &ownership, nil
	}
	// LastDispatchSequence in a replayed register response may lag newer
	// admissions; exact authenticated local proofs bound this metadata advance.
	if floor > ownership.LastDispatchSequence {
		ownership.LastDispatchSequence = floor
	}
	updated, err := p.connection.RetireNativeWorkerOwnership(ctx, p.scope, p.bootstrap.Native, ownership.Profile, ownership, floor, nil, false)
	if err != nil {
		return nil, err
	}
	_, err = p.call(ctx, sessionworker.Request{Type: "dispatch_retire", Sequence: floor})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// Server dispatch order and local operation order are independent: local
// resize/view operations may occupy an operation without a server ordinal.
func nativeDispatchOperationSequence(proof transport.NativeDispatchProof, records []sessionworker.NativeDispatchRecord) (int64, error) {
	for _, record := range records {
		if record.Proof.DispatchSequence != proof.DispatchSequence {
			continue
		}
		if !reflect.DeepEqual(record.Proof, proof) || record.OperationSequence <= 0 {
			return 0, ErrNativeObservationConflict
		}
		return record.OperationSequence, nil
	}
	return 0, ErrNativeOriginAdmissionDeferred
}
