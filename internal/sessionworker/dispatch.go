package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

var ErrDispatchGap = errors.New("earlier native dispatch must arrive first")

// prepareDispatchOperation takes source labels from the immutable server
// proof. The private caller cannot relabel a task or an original admission.
func prepareDispatchOperation(req Request) (json.RawMessage, error) {
	if req.NativeDispatch == nil || (req.Kind != "activate" && req.Kind != "prompt" && req.Kind != "stop" && req.Kind != "hibernate" && req.Kind != "attach" && req.Kind != "restart" && req.Kind != "resolve") {
		return nil, ErrConflict
	}
	var op Operation
	if decodeClosed(req.Payload, &op) != nil {
		return nil, ErrConflict
	}
	p := req.NativeDispatch
	if (op.SourceCommandID != "" && op.SourceCommandID != p.SourceCommandID) || (op.SourceAdmissionID != "" && op.SourceAdmissionID != p.SourceAdmissionID) || (op.SourceTask != nil && taskSourceJSON(op.SourceTask) != taskSourceJSON(p.TaskSource)) {
		return nil, ErrConflict
	}
	op.SourceCommandID = p.SourceCommandID
	op.SourceAdmissionID = p.SourceAdmissionID
	op.SourceTask = cloneNativeTaskSource(p.TaskSource)
	if req.Kind == "resolve" {
		if p.TaskSource != nil || ValidateNativeResolveOperation(op) != nil {
			return nil, ErrConflict
		}
		return json.Marshal(op)
	}
	if op.SourceTask != nil {
		op.InputKind = "task"
	}
	if op.InputKind == "event" {
		op.InputKind = "notice"
	}
	if op.InputKind == "channel" {
		op.InputKind = "user_input"
	}
	if req.Kind == "prompt" && (!ValidNativeInputKind(op.InputKind) || op.Input == "" || len(op.Input) > 128<<10) {
		return nil, ErrConflict
	}
	return json.Marshal(op)
}

func (j *Journal) initializeDispatches() error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS worker_dispatch_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),ownership TEXT NOT NULL,last_sequence INTEGER NOT NULL,retired INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS worker_dispatches(dispatch_sequence INTEGER PRIMARY KEY,operation_sequence INTEGER NOT NULL UNIQUE,command_id TEXT NOT NULL UNIQUE,proof BLOB NOT NULL,state TEXT NOT NULL DEFAULT 'admitted')`,
		`CREATE TABLE IF NOT EXISTS worker_terminal_view_commits(operation_sequence INTEGER PRIMARY KEY,committed INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TRIGGER IF NOT EXISTS worker_dispatch_settle AFTER UPDATE OF state ON worker_intent BEGIN UPDATE worker_dispatches SET state=NEW.state WHERE operation_sequence=NEW.sequence; END`,
	} {
		if _, err := j.db.Exec(q); err != nil {
			return err
		}
	}
	// Older retained mappings may recover their kind only from the original
	// still-retained intent. Pruned historical kinds remain unknown.
	columns, err := j.db.Query(`PRAGMA table_info(worker_dispatches)`)
	if err != nil {
		return err
	}
	hasKind := false
	for columns.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err = columns.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			columns.Close()
			return err
		}
		if name == "operation_kind" {
			hasKind = true
		}
	}
	err = columns.Err()
	columns.Close()
	if err != nil {
		return err
	}
	if !hasKind {
		if _, err = j.db.Exec(`ALTER TABLE worker_dispatches ADD COLUMN operation_kind TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if _, err = j.db.Exec(`CREATE TRIGGER IF NOT EXISTS worker_dispatch_kind_immutable BEFORE UPDATE OF operation_kind ON worker_dispatches WHEN NEW.operation_kind<>OLD.operation_kind AND (OLD.operation_kind<>'' OR NOT EXISTS(SELECT 1 FROM worker_intent i WHERE i.sequence=OLD.operation_sequence AND i.command_id=OLD.command_id AND i.kind=NEW.operation_kind)) BEGIN SELECT RAISE(ABORT,'original dispatch operation kind is immutable'); END`); err != nil {
		return err
	}
	if _, err = j.db.Exec(`UPDATE worker_dispatches SET operation_kind=(SELECT i.kind FROM worker_intent i WHERE i.sequence=operation_sequence AND i.command_id=worker_dispatches.command_id) WHERE operation_kind='' AND EXISTS(SELECT 1 FROM worker_intent i WHERE i.sequence=operation_sequence AND i.command_id=worker_dispatches.command_id)`); err != nil {
		return err
	}
	var last, retired, count int64
	err = j.db.QueryRow(`SELECT last_sequence,retired,((SELECT COUNT(*) FROM worker_dispatches)+(SELECT COUNT(*) FROM worker_dispatch_cancellations WHERE state='finalized' AND dispatch_sequence>worker_dispatch_meta.retired AND dispatch_sequence<=worker_dispatch_meta.last_sequence)) FROM worker_dispatch_meta WHERE singleton=1`).Scan(&last, &retired, &count)
	if errors.Is(err, sql.ErrNoRows) {
		var orphaned int
		if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_dispatches`).Scan(&orphaned); err != nil {
			return err
		}
		if orphaned != 0 {
			return ErrConflict
		}
		return nil
	}
	if err != nil {
		return err
	}
	if last < retired || retired < 0 || last-retired != count || count > maxCommands {
		return ErrConflict
	}
	var invalid int
	var ownership string
	if err = j.db.QueryRow(`SELECT ownership FROM worker_dispatch_meta WHERE singleton=1`).Scan(&ownership); err != nil {
		return err
	}
	var o transport.NativeWorkerOwnership
	if json.Unmarshal([]byte(ownership), &o) != nil || o.InstanceID != j.scope.InstanceID || o.OwnershipGeneration != j.scope.Generation {
		return ErrConflict
	}
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_dispatches WHERE dispatch_sequence<=? OR dispatch_sequence>? OR operation_sequence<=0 OR operation_sequence>=(SELECT next_sequence FROM worker_meta WHERE singleton=1) OR state NOT IN ('admitted','completed','failed','uncertain','resource_interrupted','owner_stopped') OR (state='resource_interrupted' AND NOT EXISTS(SELECT 1 FROM worker_resource_settlements s WHERE s.sequence=operation_sequence AND json(json_extract(s.payload,'$.proof'))=json(proof))) OR (state='owner_stopped' AND NOT EXISTS(SELECT 1 FROM worker_owner_stop_settlements s WHERE s.sequence=operation_sequence AND json(json_extract(s.payload,'$.proof'))=json(proof))) OR operation_kind NOT IN ('','activate','prompt','stop','hibernate','attach','restart','resolve') OR EXISTS(SELECT 1 FROM worker_intent i WHERE i.sequence=operation_sequence AND (i.command_id<>worker_dispatches.command_id OR (operation_kind<>'' AND i.kind<>operation_kind))) OR json_extract(proof,'$.ownershipId') IS NOT ? OR json_extract(proof,'$.ownershipGeneration') IS NOT ? OR json_extract(proof,'$.dispatchSequence') IS NOT dispatch_sequence OR json_extract(proof,'$.sourceCommandId') IS NOT command_id`, retired, last, o.ID, j.scope.Generation).Scan(&invalid); err != nil {
		return err
	}
	if invalid != 0 {
		return ErrConflict
	}
	return nil
}

// BindDispatchOwnership pins server ownership to this exact worker profile.
// Transport replacement cannot bind a different ownership to the same worker.
func (j *Journal) BindDispatchOwnership(ctx context.Context, lease int64, o transport.NativeWorkerOwnership, runtime, profileFingerprint string) error {
	if _, err := domain.ParseID(o.ID); err != nil {
		return ErrConflict
	}
	if _, err := domain.ParseID(o.OriginalAdmissionID); err != nil {
		return ErrConflict
	}
	if o.InstanceID != j.scope.InstanceID || o.OwnershipGeneration != j.scope.Generation || o.Runtime != runtime || o.ProfileFingerprint != profileFingerprint || len(profileFingerprint) != 64 || o.State != "active" {
		return ErrConflict
	}
	// Sequence counters are mutable server metadata, never local allocation input.
	o.LastDispatchSequence, o.RetiredFloor = 0, 0
	raw, err := json.Marshal(o)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, _, err = checkLease(ctx, tx, lease); err != nil {
		return err
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT ownership FROM worker_dispatch_meta WHERE singleton=1`).Scan(&existing)
	if err == nil {
		if existing != string(raw) {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var unbound int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_intent WHERE kind IN ('activate','prompt')`).Scan(&unbound); err != nil {
		return err
	}
	if unbound != 0 {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO worker_dispatch_meta VALUES(1,?,0,0)`, string(raw))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// prepareDispatchTx allocates the local operation ordinal and original server
// dispatch proof inside the same transaction as admission, before any effect.
func (j *Journal) prepareDispatchTx(ctx context.Context, tx *sql.Tx, next, requested int64, command string, p transport.NativeDispatchProof) (int64, bool, error) {
	if p.OwnershipGeneration != j.scope.Generation || p.DispatchSequence <= 0 || p.DispatchSequence == 9223372036854775807 || p.SourceCommandID != command || p.SourceRunnerEpoch.IsZero() || p.SourceBootID == "" || len(p.SourceBootID) > 256 {
		return 0, false, ErrConflict
	}
	for _, id := range []string{p.OwnershipID, p.SourceCommandID, p.SourceAdmissionID, p.SourceRunnerID} {
		if _, err := domain.ParseID(id); err != nil {
			return 0, false, ErrConflict
		}
	}
	if err := CheckDispatchCancellationTx(ctx, tx, p); err != nil {
		return 0, false, err
	}
	var ownership string
	var last, floor int64
	if err := tx.QueryRowContext(ctx, `SELECT ownership,last_sequence,retired FROM worker_dispatch_meta WHERE singleton=1`).Scan(&ownership, &last, &floor); err != nil {
		return 0, false, ErrConflict
	}
	var o transport.NativeWorkerOwnership
	if json.Unmarshal([]byte(ownership), &o) != nil || o.ID != p.OwnershipID {
		return 0, false, ErrConflict
	}
	if p.DispatchSequence <= floor {
		return 0, false, ErrRetired
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return 0, false, err
	}
	var sequence int64
	var original []byte
	err = tx.QueryRowContext(ctx, `SELECT operation_sequence,proof FROM worker_dispatches WHERE dispatch_sequence=?`, p.DispatchSequence).Scan(&sequence, &original)
	if err == nil {
		if string(original) != string(raw) || (requested != 0 && requested != sequence) {
			return 0, false, ErrConflict
		}
		return sequence, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, err
	}
	if p.DispatchSequence > last+1 {
		return 0, false, ErrDispatchGap
	}
	if p.DispatchSequence != last+1 || (requested != 0 && requested != next) {
		return 0, false, ErrConflict
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM worker_dispatches)+(SELECT COUNT(*) FROM worker_dispatch_cancellations)`).Scan(&count); err != nil {
		return 0, false, err
	}
	if count >= maxCommands {
		return 0, false, ErrFull
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_dispatches(dispatch_sequence,operation_sequence,command_id,proof) VALUES(?,?,?,?)`, p.DispatchSequence, next, command, raw); err != nil {
		return 0, false, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE worker_dispatch_meta SET last_sequence=? WHERE singleton=1`, p.DispatchSequence); err != nil {
		return 0, false, err
	}
	if err = advanceFinalizedDispatchesTx(ctx, tx); err != nil {
		return 0, false, err
	}
	return next, true, nil
}

// CheckDispatchRetirement verifies the same original-source drain guards as
// pruning, before the controller advances the backend floor. It never erases
// mappings or evidence, so a lost cloud reply can replay the original proof.
func (j *Journal) CheckDispatchRetirement(ctx context.Context, lease, floor int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = validateDispatchRetirementTx(ctx, tx, lease, floor); err != nil {
		return err
	}
	return tx.Commit()
}

func validateDispatchRetirementTx(ctx context.Context, tx *sql.Tx, lease, floor int64) error {
	_, operationFloor, err := checkLease(ctx, tx, lease)
	if err != nil {
		return err
	}
	var last, old int64
	if err = tx.QueryRowContext(ctx, `SELECT last_sequence,retired FROM worker_dispatch_meta WHERE singleton=1`).Scan(&last, &old); err != nil {
		return err
	}
	if floor < old || floor > last {
		return ErrConflict
	}
	var unsafe int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_dispatches d WHERE dispatch_sequence<=? AND (state NOT IN ('completed','failed','resource_interrupted','owner_stopped') OR EXISTS(SELECT 1 FROM worker_resource_settlements s WHERE s.sequence=d.operation_sequence AND finished=0) OR operation_sequence>? OR EXISTS(SELECT 1 FROM worker_terminal_view_commits v WHERE v.operation_sequence=d.operation_sequence AND v.committed=0) OR EXISTS(SELECT 1 FROM worker_output_spools p WHERE p.sequence=d.operation_sequence) OR EXISTS(SELECT 1 FROM worker_terminal_reservations r WHERE r.sequence=d.operation_sequence) OR EXISTS(SELECT 1 FROM worker_resource_interruptions r WHERE r.sequence=d.operation_sequence) OR EXISTS(SELECT 1 FROM worker_turn_sources t WHERE t.sequence=d.operation_sequence) OR EXISTS(SELECT 1 FROM worker_observations o WHERE json_extract(o.payload,'$.turnSource.sequence')=d.operation_sequence))`, floor, operationFloor).Scan(&unsafe); err != nil {
		return err
	}
	if unsafe != 0 {
		return ErrConflict
	}
	return nil
}

// RetireDispatches follows the matching backend retirement COMMIT. A worker
// rejects premature pruning even from its authenticated controller: outcomes
// must be settled and acknowledged, with all original turn evidence drained.
func (j *Journal) RetireDispatches(ctx context.Context, lease, floor int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = validateDispatchRetirementTx(ctx, tx, lease, floor); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_terminal_view_commits WHERE operation_sequence IN (SELECT operation_sequence FROM worker_dispatches WHERE dispatch_sequence<=?)`, floor); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_owner_stop_settlements WHERE sequence IN (SELECT operation_sequence FROM worker_dispatches WHERE dispatch_sequence<=?)`, floor); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_resource_settlements WHERE sequence IN (SELECT operation_sequence FROM worker_dispatches WHERE dispatch_sequence<=?)`, floor); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_dispatches WHERE dispatch_sequence<=?`, floor); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE worker_dispatch_meta SET retired=? WHERE singleton=1`, floor); err != nil {
		return err
	}
	var ownershipRaw string
	if err = tx.QueryRowContext(ctx, `SELECT ownership FROM worker_dispatch_meta WHERE singleton=1`).Scan(&ownershipRaw); err != nil {
		return err
	}
	var ownership transport.NativeWorkerOwnership
	if json.Unmarshal([]byte(ownershipRaw), &ownership) != nil {
		return ErrConflict
	}
	if err = RetireDispatchCancellationsTx(ctx, tx, ownership.ID, floor); err != nil {
		return err
	}
	return tx.Commit()
}

// NativeDispatchRecord retains only immutable routing metadata and settlement.
// It survives local outcome acknowledgement until backend retirement commits.
type NativeDispatchRecord struct {
	Kind              string                        `json:"kind,omitempty"`
	Proof             transport.NativeDispatchProof `json:"proof"`
	OperationSequence int64                         `json:"operationSequence"`
	State             string                        `json:"state"`
}

func (j *Journal) DispatchRecords(ctx context.Context, lease int64) ([]NativeDispatchRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, _, err = checkLease(ctx, tx, lease); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT proof,operation_sequence,state,operation_kind FROM (SELECT proof,operation_sequence,operation_kind,CASE WHEN EXISTS(SELECT 1 FROM worker_terminal_view_commits v WHERE v.operation_sequence=worker_dispatches.operation_sequence AND v.committed=0) THEN 'view_pending' ELSE state END AS state FROM worker_dispatches UNION ALL SELECT json_extract(payload,'$.proposal.proof'),0,'','cancelled' FROM worker_dispatch_cancellations WHERE state='finalized' AND dispatch_sequence<=(SELECT last_sequence FROM worker_dispatch_meta WHERE singleton=1)  ) ORDER BY json_extract(proof,'$.dispatchSequence') LIMIT ?`, maxCommands)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []NativeDispatchRecord
	for rows.Next() {
		var r NativeDispatchRecord
		var raw []byte
		if err = rows.Scan(&raw, &r.OperationSequence, &r.State, &r.Kind); err != nil {
			return nil, err
		}
		if decodeClosed(raw, &r.Proof) != nil {
			return nil, ErrConflict
		}
		records = append(records, r)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return records, nil
}

// Finalized cancellation is an ordinal tombstone, never a native operation.
// This runs in the finalization/admission transaction so reopening cannot
// observe a skipped ordinal without its matching committed marker.
func advanceFinalizedDispatchesTx(ctx context.Context, tx *sql.Tx) error {
	var last int64
	if err := tx.QueryRowContext(ctx, `SELECT last_sequence FROM worker_dispatch_meta WHERE singleton=1`).Scan(&last); err != nil {
		return err
	}
	for {
		var finalized bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_dispatch_cancellations WHERE dispatch_sequence=? AND state='finalized')`, last+1).Scan(&finalized); err != nil {
			return err
		}
		if !finalized {
			break
		}
		last++
	}
	_, err := tx.ExecContext(ctx, `UPDATE worker_dispatch_meta SET last_sequence=? WHERE singleton=1`, last)
	return err
}
