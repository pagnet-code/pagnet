package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/pagnet-code/pagnet/transport"
)

// DeletionRecovery owns only the original journal's lifetime lock. It cannot
// create a native owner, admit commands, or resume an interrupted native effect.
type DeletionRecovery struct {
	journal *Journal
	lease   int64
	key     []byte
}

func OpenDeletionRecovery(ctx context.Context, dir string, scope Scope) (*DeletionRecovery, error) {
	_, key, err := LoadControllerBootstrap(dir, scope)
	if err != nil {
		return nil, err
	}
	// OpenJournal can create storage; this lane must find the original first.
	info, err := os.Lstat(filepath.Join(dir, "intents.sqlite"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		clear(key)
		return nil, errors.New("original private worker journal is unavailable")
	}
	j, err := OpenExistingJournal(dir, scope)
	if err != nil {
		clear(key)
		return nil, err
	}
	lease, err := j.AdvanceLease(ctx)
	if err != nil {
		clear(key)
		_ = j.Close()
		return nil, err
	}
	return &DeletionRecovery{journal: j, lease: lease, key: key}, nil
}

func (r *DeletionRecovery) Close() error { clear(r.key); return r.journal.Close() }

// SourceCall accepts only the immutable deletion publication/receipt lane.
func (r *DeletionRecovery) SourceCall(ctx context.Context, req Request) (response Response, err error) {
	switch req.Type {
	case "observations":
		var page NativeObservationPage
		page, err = r.journal.ObservationPageForLease(ctx, r.lease, req.Cursor, req.Limit)
		response.Observations = page.Observations
		page.Observations = nil
		response.ObservationPage = &page
	case "observation_ack":
		err = r.journal.acknowledgeObservation(ctx, r.lease, req.ObservationID, req.SourceDigest, req.SourceReceipt, r.key)
	case "source_disposition":
		if req.SourceReceipt == nil {
			return response, ErrConflict
		}
		err = r.journal.RecordNativeSourceDisposition(ctx, r.lease, req.ObservationID, req.SourceDigest, *req.SourceReceipt)
	default:
		err = errors.New("unsupported deletion recovery journal request")
	}
	return
}

// Prepare requires the final original completed stop and quiesced readers.
// With no materialized source evidence, the backend must independently accept
// the returned unstarted stop proof before any local dispatch pruning.
func (r *DeletionRecovery) Prepare(ctx context.Context, owned transport.NativeWorkerOwnership, proof *transport.NativeOwnershipDeletionProof) (int64, *transport.NativeDispatchProof, error) {
	j := r.journal
	var raw string
	var last, floor int64
	if err := j.db.QueryRowContext(ctx, `SELECT ownership,last_sequence,retired FROM worker_dispatch_meta WHERE singleton=1`).Scan(&raw, &last, &floor); err != nil {
		return 0, nil, err
	}
	var original transport.NativeWorkerOwnership
	if json.Unmarshal([]byte(raw), &original) != nil {
		return 0, nil, ErrConflict
	}
	normalized := owned
	normalized.LastDispatchSequence, normalized.RetiredFloor = 0, 0
	normalized.State, normalized.DeletionProof = "active", nil
	if !transport.SameNativeWorkerOwnership(original, normalized) || owned.RetiredFloor > last {
		return 0, nil, ErrConflict
	}
	var unsafe, materialized bool
	if err := j.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_source_registration WHERE quiesced=0) OR EXISTS(SELECT 1 FROM worker_intent WHERE state NOT IN ('completed','failed','resource_interrupted','owner_stopped')),(EXISTS(SELECT 1 FROM worker_source_registration) OR EXISTS(SELECT 1 FROM worker_turn_sources) OR EXISTS(SELECT 1 FROM worker_observations) OR EXISTS(SELECT 1 FROM worker_stopped_receipts))`).Scan(&unsafe, &materialized); err != nil {
		return 0, nil, err
	}
	if unsafe {
		return 0, nil, errors.New("original native outcome or reader remains unsettled")
	}
	records, err := j.DispatchRecords(ctx, r.lease)
	if err != nil {
		return 0, nil, err
	}
	var stop *transport.NativeDispatchProof
	if len(records) > 0 {
		final := records[len(records)-1]
		if final.Proof.DispatchSequence != last || final.Kind != "stop" || final.State != "completed" {
			return 0, nil, ErrConflict
		}
		copy := final.Proof
		stop = &copy
	} else if floor != last {
		return 0, nil, ErrConflict
	}
	// A fully pruned original journal can outlive a stale waiting GC marker:
	// RetireDispatches already required the backend's committed floor. The
	// caller must revalidate that exact floor with the authenticated backend
	// before recording retirement preparation; missing mappings permit no new
	// effects and never imply a native stop.
	if proof != nil {
		if proof.StopProof.OwnershipID != owned.ID || proof.StopProof.OwnershipGeneration != j.scope.Generation || proof.StopProof.DispatchSequence != last || (stop != nil && !transport.SameNativeDispatchProof(*stop, proof.StopProof)) {
			return 0, nil, ErrConflict
		}
		if materialized {
			if err := r.validateStoppedProof(ctx, proof); err != nil {
				return 0, nil, err
			}
		}
		if err := j.collectDeletionQuarantines(ctx, r.lease, proof, r.key); err != nil {
			return 0, nil, err
		}
	} else if materialized {
		return 0, nil, errors.New("materialized native runtime requires authenticated deletion stop proof")
	}
	for _, record := range records {
		if record.State != "completed" && record.State != "failed" && record.State != ResourceInterrupted && record.State != OwnerStopped && record.State != "cancelled" {
			return 0, nil, ErrConflict
		}
		if record.OperationSequence > 0 {
			// A replayed dispatch may already have lost its acknowledged operation.
			var exists bool
			if err := j.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_intent WHERE sequence=?)`, record.OperationSequence).Scan(&exists); err != nil {
				return 0, nil, err
			}
			if exists {
				if err := j.Acknowledge(ctx, r.lease, record.OperationSequence); err != nil {
					return 0, nil, err
				}
			}
		}
	}
	if err := j.CheckDispatchRetirement(ctx, r.lease, last); err != nil {
		return 0, nil, err
	}
	if proof != nil {
		stop = nil
	}
	return last, stop, nil
}

func (r *DeletionRecovery) RetireDispatches(ctx context.Context, floor int64) error {
	return r.journal.RetireDispatches(ctx, r.lease, floor)
}
func (r *DeletionRecovery) CommitRetirement(ctx context.Context, proof transport.NativeWorkerOwnership) error {
	return r.journal.CommitOwnershipRetirement(ctx, r.lease, proof)
}

func (r *DeletionRecovery) validateStoppedProof(ctx context.Context, proof *transport.NativeOwnershipDeletionProof) error {
	var raw []byte
	err := r.journal.db.QueryRowContext(ctx, `SELECT payload FROM worker_stopped_receipts WHERE observation_id=?`, proof.StoppedObservationID).Scan(&raw)
	var e stoppedReceipt
	if errors.Is(err, sql.ErrNoRows) {
		var payload, receipt []byte
		var sequence int64
		err = r.journal.db.QueryRowContext(ctx, `SELECT o.payload,d.receipt,s.source_sequence FROM worker_observations o JOIN worker_source_dispositions d ON d.observation_id=o.id JOIN worker_observation_sequence s ON s.observation_id=o.id WHERE o.id=?`, proof.StoppedObservationID).Scan(&payload, &receipt, &sequence)
		if err != nil {
			return err
		}
		if json.Unmarshal(payload, &e.Observation) != nil || json.Unmarshal(receipt, &e.Receipt) != nil {
			return ErrConflict
		}
		e.Observation.SourceSequence = sequence
	} else if err != nil {
		return err
	} else if json.Unmarshal(raw, &e) != nil {
		return ErrConflict
	}
	if validateStoppedReceipt(r.journal.scope, e) != nil {
		return ErrConflict
	}
	wire, err := NativeBackendObservation(e.Observation)
	if err != nil || proof.OriginID != wire.OriginID || proof.NativeGeneration != e.Observation.NativeGeneration || proof.NativeSessionID != e.Observation.NativeSessionID || proof.StoppedDigest != wire.Digest || proof.StoppedSourceSequence != e.Observation.SourceSequence || proof.StoppedDisposition != e.Receipt.Disposition || !proof.StoppedObservedAt.Equal(wire.ObservedAt) || !proof.StoppedExpiresAt.Equal(wire.ExpiresAt) {
		return ErrConflict
	}
	return nil
}
