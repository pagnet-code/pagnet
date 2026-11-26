package sessionworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/internal/nativedirect"
	"github.com/pagnet-code/pagnet/transport"
)

func logicalDirectTurn(admission string) string {
	sum := sha256.Sum256([]byte(admission))
	return "pagnet-direct-turn-" + hex.EncodeToString(sum[:])
}

func validDirectTurn(s NativeTurnSource) bool {
	d := s.SourceDirectASK
	return d != nil && d.Validate() == nil && s.SourceTask == nil && s.SourceInvocation == nil && s.SourceAccountMessage == nil && s.SourceCommandID == "" && s.SourceAdmissionID == "" && s.Sequence == 0 && s.InputKind == "direct_ask" && s.LogicalTurnID == logicalDirectTurn(d.AdmissionID) && s.NativeGeneration == d.NativeGeneration && s.NativeSessionID == d.NativeSessionID
}

func (j *Journal) migrateDirectAdmissions() error {
	const schema = `CREATE TABLE worker_direct_admissions(admission_id TEXT PRIMARY KEY,delivery_key TEXT NOT NULL UNIQUE,digest TEXT NOT NULL,record BLOB NOT NULL CHECK(length(record)<=98304),state TEXT NOT NULL CHECK(state IN ('reserved','submitted','unknown')))`
	var schemaSQL string
	err := j.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='worker_direct_admissions'`).Scan(&schemaSQL)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = j.db.Exec(schema)
		return err
	}
	if err != nil {
		return err
	}
	if strings.Contains(schemaSQL, "'submitted'") {
		return nil
	}
	// Rebuilding also upgrades the original reserved/unknown-only CHECK.
	tx, err := j.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`ALTER TABLE worker_direct_admissions RENAME TO worker_direct_admissions_old`, schema, `INSERT INTO worker_direct_admissions SELECT * FROM worker_direct_admissions_old`, `DROP TABLE worker_direct_admissions_old`} {
		if _, err = tx.Exec(q); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Submitted means possibly dispatched. Only the transaction winner may ever
// dispatch; recovered status and duplicate calls never authorize another call.
// This dormant helper has no production caller and never calls a runtime.
func (o *SessionOwner) beginDirectASKSubmission(ctx context.Context, controllerLease int64, source nativedirect.NativeDirectASKSource, wire json.RawMessage) (*DirectASKReservation, bool, error) {
	return o.beginDirectASKSubmissionAt(ctx, controllerLease, source, wire, time.Now().UTC(), o.physicalSnapshot)
}

func (o *SessionOwner) beginDirectASKSubmissionAt(ctx context.Context, lease int64, source nativedirect.NativeDirectASKSource, wire json.RawMessage, now time.Time, collect func() NativeSnapshot) (*DirectASKReservation, bool, error) {
	if o == nil || o.journal == nil || source.ValidateWire(wire) != nil || source.Scope != o.journal.scope || !now.Before(source.Deadline) {
		return nil, false, ErrFenced
	}
	started := time.Now()
	verified, err := o.journal.verifyOwnershipSnapshot(ctx, lease, NativeOwnershipVerifyRequest{Ownership: source.Ownership}, collect)
	if err != nil {
		return nil, false, err
	}
	s := verified.Snapshot
	if s.NativeGeneration != source.NativeGeneration || s.NativeSessionID != source.NativeSessionID || s.NativeStartIdentity != source.NativeStartIdentity || s.PID != source.NativePID {
		return nil, false, ErrFenced
	}
	j := o.journal
	record, _ := json.Marshal(DirectASKReservation{Source: source, Wire: wire})
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if _, _, err = checkLease(ctx, tx, lease); err != nil {
		return nil, false, err
	}
	var owned string
	var retired bool
	if err = tx.QueryRowContext(ctx, `SELECT ownership,EXISTS(SELECT 1 FROM worker_ownership_retirement) FROM worker_dispatch_meta WHERE singleton=1`).Scan(&owned, &retired); err != nil {
		return nil, false, err
	}
	var bound transport.NativeWorkerOwnership
	if retired || json.Unmarshal([]byte(owned), &bound) != nil || !transport.SameNativeWorkerOwnership(bound, source.Ownership) || !now.Add(time.Since(started)).Before(source.Deadline) {
		return nil, false, ErrFenced
	}
	var raw []byte
	var state string
	if err = tx.QueryRowContext(ctx, `SELECT record,state FROM worker_direct_admissions WHERE admission_id=?`, source.AdmissionID).Scan(&raw, &state); errors.Is(err, sql.ErrNoRows) {
		return nil, false, ErrFenced
	} else if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(raw, record) {
		return nil, false, ErrConflict
	}
	status := &DirectASKReservation{Source: source, Wire: append(json.RawMessage(nil), wire...), State: state}
	if state != "reserved" {
		return status, false, tx.Commit()
	}
	if err = j.reserveTerminalIdentityTx(ctx, tx, 0, "prompt", source.AdmissionID); err != nil {
		return nil, false, err
	}
	sourceJSON, _ := source.CanonicalBytes()
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_direct_turn_sources(admission_id,native_generation,logical_turn,native_session,source) VALUES(?,?,?,?,?)`, source.AdmissionID, source.NativeGeneration, logicalDirectTurn(source.AdmissionID), source.NativeSessionID, string(sourceJSON)); err != nil {
		return nil, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE worker_direct_admissions SET state='submitted' WHERE admission_id=? AND state='reserved'`, source.AdmissionID)
	if err != nil {
		return nil, false, err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return nil, false, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	status.State = "submitted"
	return status, true, nil
}

func (j *Journal) validateDirectExecution() error {
	rows, err := j.db.Query(`SELECT t.admission_id,t.native_generation,t.logical_turn,t.native_session,t.source,a.record,a.state,r.rows_left,r.capture_left,r.content_left FROM worker_direct_turn_sources t LEFT JOIN worker_direct_admissions a ON a.admission_id=t.admission_id LEFT JOIN worker_direct_terminal_reservations r ON r.admission_id=t.admission_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, generation, turn, session, raw, state string
		var record []byte
		var reservedRows, capture, content int
		if err = rows.Scan(&id, &generation, &turn, &session, &raw, &record, &state, &reservedRows, &capture, &content); err != nil {
			return err
		}
		var source nativedirect.NativeDirectASKSource
		var admission DirectASKReservation
		if json.Unmarshal([]byte(raw), &source) != nil || json.Unmarshal(record, &admission) != nil {
			return ErrConflict
		}
		canonical, e := source.CanonicalBytes()
		expected, _ := json.Marshal(admission.Source)
		if e != nil || !bytes.Equal(canonical, []byte(raw)) || !bytes.Equal(canonical, expected) || source.AdmissionID != id || source.NativeGeneration != generation || source.NativeSessionID != session || turn != logicalDirectTurn(id) || state != "submitted" && state != "unknown" || reservedRows != terminalSourceReserveRows || capture != terminalCaptureReserveBytes || content != terminalContentReserveBytes {
			return ErrConflict
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	var invalid bool
	err = j.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM worker_direct_terminal_reservations r WHERE NOT EXISTS(SELECT 1 FROM worker_direct_turn_sources t WHERE t.admission_id=r.admission_id)) OR EXISTS(SELECT 1 FROM worker_direct_admissions a WHERE a.state='submitted' AND NOT EXISTS(SELECT 1 FROM worker_direct_turn_sources t WHERE t.admission_id=a.admission_id))`).Scan(&invalid)
	if err == nil && invalid {
		return ErrConflict
	}
	return err
}
