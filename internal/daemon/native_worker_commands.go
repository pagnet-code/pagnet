package daemon

import (
	"context"
	"encoding/json"
	"errors"

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
	replay := len(response.Dispatches) > 0 && response.Dispatches[0].Proof.DispatchSequence <= floor
	if replay {
		// The private journal may still retain a cloud-committed prefix after
		// acknowledgement loss. Revalidate its original contiguous evidence;
		// a higher remote floor alone is never permission to prune locally.
		floor = response.Dispatches[0].Proof.DispatchSequence - 1
		if floor < 0 {
			return nil, ErrNativeObservationConflict
		}
	}
	var stop *sessionworker.NativeDispatchRecord
	for _, r := range response.Dispatches {
		if replay && r.Proof.DispatchSequence > ownership.RetiredFloor {
			break
		}
		if r.Proof.OwnershipID != ownership.ID || r.Proof.OwnershipGeneration != p.scope.Generation {
			return nil, ErrNativeObservationConflict
		}
		if r.Proof.DispatchSequence == floor+1 && r.Kind == "attach" && r.State == "view_pending" {
			// A disconnected terminal handler may never confirm its final view
			// failure. Recover only the original worker's definitive failure;
			// successful/ambiguous views still require their original handler.
			original, readErr := p.call(ctx, sessionworker.Request{Type: "outcome", Sequence: r.OperationSequence})
			if readErr != nil {
				return nil, readErr
			}
			out := original.Outcome
			if out == nil || out.Sequence != r.OperationSequence || out.CommandID != r.Proof.SourceCommandID || out.Kind != r.Kind || out.SourceAdmission == nil {
				return nil, ErrNativeObservationConflict
			}
			a := out.SourceAdmission
			if a.Scope != p.scope || a.NativeAdmissionID != r.Proof.SourceAdmissionID || a.RunnerID != r.Proof.SourceRunnerID || !a.RunnerEpoch.Equal(r.Proof.SourceRunnerEpoch) || a.BootID != r.Proof.SourceBootID {
				return nil, ErrNativeObservationConflict
			}
			if out.State != "failed" {
				break
			}
			if _, err = p.call(ctx, sessionworker.Request{Type: "terminal_view_commit", NativeDispatch: &r.Proof}); err != nil {
				return nil, err
			}
			r.State = out.State
		}
		if r.Proof.DispatchSequence != floor+1 || (r.State != "completed" && r.State != "failed" && r.State != "cancelled" && r.State != sessionworker.ResourceInterrupted && r.State != sessionworker.OwnerStopped) {
			break
		}
		if r.State != "cancelled" {
			if _, err = p.call(ctx, sessionworker.Request{Type: "ack", Sequence: r.OperationSequence}); err != nil {
				return nil, err
			}
		}
		floor = r.Proof.DispatchSequence
		stop = nil
		if r.Kind == "stop" && r.State == "completed" {
			copy := r
			stop = &copy
		}
	}
	if replay && floor != ownership.RetiredFloor {
		return nil, ErrNativeOriginAdmissionDeferred
	}
	if !replay && floor == ownership.RetiredFloor {
		return &ownership, nil
	}
	// Local completion is not yet permission to retire its original source:
	// pending capture/transfer/receipt references must drain first. Advancing
	// the cloud floor before this check would revoke a still-running cloud turn.
	if _, err = p.call(ctx, sessionworker.Request{Type: "dispatch_retire_check", Sequence: floor}); err != nil {
		return nil, err
	}
	// The authenticated dispatch record retains original outcome kind/state and
	// source proof after ack removes the operation. Readiness below proves all
	// source evidence drained before that retained proof may be committed remotely.
	var unstartedStop *transport.NativeDispatchProof
	if stop != nil {
		snapshot, err := p.Snapshot(ctx)
		if err != nil {
			return nil, err
		}
		if snapshot.Scope != p.scope {
			return nil, ErrNativeObservationConflict
		}
		if replay || (!snapshot.IdentityPending && snapshot.PID == 0 && !snapshot.HasTerminal) {
			proof := stop.Proof
			unstartedStop = &proof
		}
	}
	// LastDispatchSequence in a replayed register response may lag newer
	// admissions; exact authenticated local proofs bound this metadata advance.
	if floor > ownership.LastDispatchSequence {
		ownership.LastDispatchSequence = floor
	}
	updated, err := p.connection.RetireNativeWorkerOwnership(ctx, p.scope, p.bootstrap.Native, ownership.Profile, ownership, floor, nil, false, unstartedStop)
	if err != nil {
		return nil, err
	}
	_, err = p.call(ctx, sessionworker.Request{Type: "dispatch_retire", Sequence: floor})
	if err != nil {
		return nil, err
	}
	if replay {
		return p.SettleDispatches(ctx, *updated)
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
		if !transport.SameNativeDispatchProof(record.Proof, proof) || record.OperationSequence <= 0 {
			return 0, ErrNativeObservationConflict
		}
		return record.OperationSequence, nil
	}
	return 0, ErrNativeOriginAdmissionDeferred
}
