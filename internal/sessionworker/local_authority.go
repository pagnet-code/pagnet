package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"

	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

// LocalIntentSource is immutable admission provenance, not a cloud session or
// a native completion receipt. Prompt bodies remain outside the durable intent.
type LocalIntentSource struct {
	Kind         string                                   `json:"kind"`
	IntentDigest string                                   `json:"intentDigest"`
	Admission    fabricidentity.Admission                 `json:"admission"`
	Commitment   fabricidentity.NativeIntentCommitment    `json:"commitment"`
	Reservation  fabricidentity.NativeDispatchReservation `json:"reservation"`
	Binding      fabricidentity.Binding                   `json:"binding"`
	Receipt      fabricidentity.NativeIntentReceipt       `json:"receipt"`
}

func (j *Journal) initializeLocalAuthority() error {
	if !j.isLocal() {
		return nil
	}
	if j.localReadiness == nil {
		var e error
		j.localReadiness, e = newLocalReadiness()
		if e != nil {
			return e
		}
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS worker_local_stream_heads(sequence INTEGER PRIMARY KEY,payload BLOB NOT NULL,closed INTEGER NOT NULL CHECK(closed IN(0,1)))`,
		`CREATE TABLE IF NOT EXISTS worker_local_cancellations(sequence INTEGER PRIMARY KEY,command_id TEXT NOT NULL,admission_id TEXT NOT NULL,controller_epoch INTEGER NOT NULL CHECK(controller_epoch>0))`,
		`CREATE TABLE IF NOT EXISTS worker_local_control(singleton INTEGER PRIMARY KEY CHECK(singleton=1),highest_epoch INTEGER NOT NULL CHECK(highest_epoch>=0))`,
		`INSERT OR IGNORE INTO worker_local_control VALUES(1,0)`,
		`CREATE TABLE IF NOT EXISTS worker_local_current_control(singleton INTEGER PRIMARY KEY CHECK(singleton=1),proof BLOB NOT NULL CHECK(length(proof)<=65536))`,
		`CREATE TABLE IF NOT EXISTS worker_local_intent(sequence INTEGER PRIMARY KEY,admission_id TEXT NOT NULL UNIQUE,source BLOB NOT NULL)`,
	} {
		if _, e := j.db.Exec(q); e != nil {
			return e
		}
	}
	if e := j.initializeLocalActivations(); e != nil {
		return e
	}
	var highest int64
	if e := j.db.QueryRow(`SELECT highest_epoch FROM worker_local_control WHERE singleton=1`).Scan(&highest); e != nil || highest < 0 {
		return ErrConflict
	}
	if highest > 0 {
		var raw []byte
		if e := j.db.QueryRow(`SELECT proof FROM worker_local_current_control WHERE singleton=1`).Scan(&raw); e != nil {
			return ErrConflict
		}
		var c nativeauthority.LocalControl
		if len(raw) > 64<<10 || json.Unmarshal(raw, &c) != nil || nativeauthority.ValidateLocalControl(j.authority, c) != nil || c.CurrentController.Epoch() != uint64(highest) {
			return ErrConflict
		}
	}
	rows, e := j.db.Query(`SELECT i.sequence,i.command_id,i.kind,i.digest,s.admission_id,s.source FROM worker_intent i LEFT JOIN worker_local_intent s ON s.sequence=i.sequence ORDER BY i.sequence`)
	if e != nil {
		return e
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var sequence int64
		var command, kind, digest, admissionID string
		var raw []byte
		if e = rows.Scan(&sequence, &command, &kind, &digest, &admissionID, &raw); e != nil {
			return e
		}
		count++
		if count > maxCommands || len(raw) == 0 || len(raw) > 64<<10 {
			return ErrConflict
		}
		var source LocalIntentSource
		if e = json.Unmarshal(raw, &source); e != nil {
			return e
		}
		if nativeauthority.ValidateOriginalAdmission(j.authority, source.Admission) != nil || validateLocalReservation(j.authority, source) != nil || source.Admission.ID != admissionID || source.Kind != kind || source.IntentDigest != digest || source.Commitment.Sequence != sequence || source.Commitment.CommandID != command || source.Receipt.Sequence != sequence || source.Receipt.CommandID != command || source.Receipt.OperationDigest != source.Commitment.OperationDigest || source.Receipt.OriginalAdmissionID != source.Admission.ID || source.Receipt.OwnershipGeneration != j.ownershipGeneration() || source.Receipt.ControllerEpoch < source.Admission.OriginalControllerEpoch || source.Receipt.ControllerEpoch > uint64(highest) {
			return ErrConflict
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if e = rows.Close(); e != nil {
		return e
	}
	var actual int
	if e = j.db.QueryRow(`SELECT COUNT(*) FROM worker_local_intent`).Scan(&actual); e != nil || actual != count {
		return ErrConflict
	}
	var invalidCancellation bool
	if e = j.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM worker_local_cancellations c LEFT JOIN worker_local_intent s ON s.sequence=c.sequence LEFT JOIN worker_intent i ON i.sequence=c.sequence WHERE s.sequence IS NULL OR i.sequence IS NULL OR c.command_id!=i.command_id OR c.admission_id!=s.admission_id OR c.controller_epoch>? OR c.controller_epoch<=0)`, highest).Scan(&invalidCancellation); e != nil || invalidCancellation {
		return ErrConflict
	}
	return nil
}

type localQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (j *Journal) localIntentSource(ctx context.Context, q localQuery, sequence int64) (*LocalIntentSource, error) {
	var raw []byte
	if e := q.QueryRowContext(ctx, `SELECT source FROM worker_local_intent WHERE sequence=?`, sequence).Scan(&raw); e != nil {
		return nil, e
	}
	if len(raw) == 0 || len(raw) > 64<<10 {
		return nil, ErrConflict
	}
	var source LocalIntentSource
	if e := json.Unmarshal(raw, &source); e != nil {
		return nil, e
	}
	return &source, nil
}

// AdmitLocal must be invoked through the current registry/admission fence and
// genuinely authenticated local IPC. Parsing signed assertions alone does not
// establish current authorization. It commits exact original source, operation
// commitment and monotonic controller epoch in the same FULL journal transaction.
// The caller starts native work ONLY when fresh is true, after this ACK returns.
func (j *Journal) AdmitLocal(ctx context.Context, lease int64, binder nativeauthority.OperationBinder, intent nativeauthority.VerifiedIntent) (out Outcome, receipt fabricidentity.NativeIntentReceipt, fresh bool, err error) {
	if !j.isLocal() || nativeauthority.ValidateIntent(j.authority, binder, intent) != nil {
		return out, receipt, false, ErrFenced
	}
	i, c := intent.Commitment, intent.CurrentController
	if c.Epoch() > math.MaxInt64 {
		return out, receipt, false, ErrFenced
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return out, receipt, false, err
	}
	defer tx.Rollback()
	next, retired, err := checkLease(ctx, tx, lease)
	if err != nil {
		return out, receipt, false, err
	}
	var highest int64
	if err = tx.QueryRowContext(ctx, `SELECT highest_epoch FROM worker_local_control WHERE singleton=1`).Scan(&highest); err != nil {
		return out, receipt, false, err
	}
	if c.Epoch() < uint64(highest) {
		return out, receipt, false, ErrFenced
	}
	var ownershipRetired bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_ownership_retirement)`).Scan(&ownershipRetired); err != nil || ownershipRetired {
		if err == nil {
			err = ErrRetired
		}
		return out, receipt, false, err
	}
	if i.Sequence <= retired {
		return out, receipt, false, ErrRetired
	}
	digest := intentDigest(intent.Operation.Kind, intent.Operation.Payload)
	var oldDigest string
	var result []byte
	err = tx.QueryRowContext(ctx, `SELECT sequence,command_id,kind,state,result,digest FROM worker_intent WHERE sequence=?`, i.Sequence).Scan(&out.Sequence, &out.CommandID, &out.Kind, &out.State, &result, &oldDigest)
	if err == nil {
		out.Result = result
		if out.CommandID != i.CommandID || out.Kind != intent.Operation.Kind || oldDigest != digest {
			return out, receipt, false, ErrConflict
		}
		out.LocalSource, err = j.localIntentSource(ctx, tx, i.Sequence)
		if err != nil {
			return out, receipt, false, err
		}
		exactOld, _ := json.Marshal(out.LocalSource.Admission)
		exactNew, _ := json.Marshal(intent.OriginalAdmission)
		if out.LocalSource.Commitment != i || !sameLocalJSON(out.LocalSource.Reservation, intent.Reservation) || string(exactOld) != string(exactNew) {
			return out, receipt, false, ErrConflict
		}
		receipt = out.LocalSource.Receipt
	} else {
		if !errors.Is(err, sql.ErrNoRows) {
			return out, receipt, false, err
		}
		if i.Sequence < next {
			return out, receipt, false, ErrRetired
		}
		var used bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_local_intent WHERE admission_id=?)`, intent.OriginalAdmission.ID).Scan(&used); err != nil {
			return out, receipt, false, err
		}
		if used {
			return out, receipt, false, ErrConflict
		}
		var count, active int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(state='admitted' AND kind IN ('prompt','activate')),0) FROM worker_intent`).Scan(&count, &active); err != nil {
			return out, receipt, false, err
		}
		if count >= maxCommands {
			return out, receipt, false, ErrFull
		}
		if (intent.Operation.Kind == "prompt" || intent.Operation.Kind == "activate") && active != 0 {
			return out, receipt, false, ErrNativeBusy
		}
		receipt = fabricidentity.NativeIntentReceipt{CommandID: i.CommandID, Sequence: i.Sequence, OperationDigest: i.OperationDigest, OriginalAdmissionID: intent.OriginalAdmission.ID, ControllerEpoch: c.Epoch(), OwnershipGeneration: j.ownershipGeneration()}
		source := &LocalIntentSource{Kind: intent.Operation.Kind, IntentDigest: digest, Admission: intent.OriginalAdmission, Commitment: i, Reservation: intent.Reservation, Binding: intent.CurrentBinding, Receipt: receipt}
		raw, e := json.Marshal(source)
		if e != nil || len(raw) > 64<<10 {
			return out, fabricidentity.NativeIntentReceipt{}, false, ErrFull
		}
		if err = j.reserveTerminalTx(ctx, tx, i.Sequence, intent.Operation.Kind); err != nil {
			return out, fabricidentity.NativeIntentReceipt{}, false, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO worker_intent(sequence,command_id,digest,kind,state) VALUES(?,?,?,?,'admitted')`, i.Sequence, i.CommandID, digest, intent.Operation.Kind); err != nil {
			return out, fabricidentity.NativeIntentReceipt{}, false, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO worker_local_intent(sequence,admission_id,source) VALUES(?,?,?)`, i.Sequence, intent.OriginalAdmission.ID, raw); err != nil {
			return out, fabricidentity.NativeIntentReceipt{}, false, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE worker_meta SET next_sequence=? WHERE singleton=1`, i.Sequence+1); err != nil {
			return out, fabricidentity.NativeIntentReceipt{}, false, err
		}
		out = Outcome{LocalSource: source, Sequence: i.Sequence, CommandID: i.CommandID, Kind: intent.Operation.Kind, State: "admitted"}
		fresh = true
	}
	if err = j.storeLocalControlTx(ctx, tx, nativeauthority.LocalControl{CurrentBinding: intent.CurrentBinding, CurrentController: c}); err != nil {
		return out, fabricidentity.NativeIntentReceipt{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return out, fabricidentity.NativeIntentReceipt{}, false, err
	}
	return out, receipt, fresh, nil
}

func sameLocalJSON(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && string(x) == string(y)
}

func validateLocalReservation(scope AuthorityScope, source LocalIntentSource) error {
	local, ok := scope.Local()
	if !ok {
		return ErrFenced
	}
	root := registry.AuthorityIdentity{Namespace: local.Namespace, StoreID: local.StoreID, Owner: local.Owner, PublicKey: local.PublicKey[:], KeyRevision: local.KeyRevision}
	bound, e := nativeauthority.NewLocalScope(root, source.Binding)
	if e != nil || !scope.SamePhysical(bound) {
		return ErrFenced
	}
	return fabricidentity.VerifyNativeDispatchReservation(root, source.Reservation, source.Admission, source.Binding, source.Commitment)
}
