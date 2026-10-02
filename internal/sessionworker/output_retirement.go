package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/pagnet-code/pagnet/transport"
)

// Called only inside the explicit ownership-deletion transaction AFTER its
// authenticated original stopped receipt/proof has been checked. The key is
// supplied by the worker owner, never an IPC request. Unprojected ciphertext
// and uncertain native operations are blockers, not deletion candidates.
func (j *Journal) collectStoppedNativeReservationsTx(ctx context.Context, tx *sql.Tx, captureKey []byte, generation, sessionID, originID string) error {
	if generation == "" || sessionID == "" || originID == "" {
		return ErrConflict
	}
	var live bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_source_registration WHERE native_generation=? AND (origin_id!=? OR quiesced=0))`, generation, originID).Scan(&live); err != nil {
		return err
	}
	if live {
		return ErrConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT t.sequence,t.logical_turn,t.native_session,t.source_command,t.source_admission,t.input_kind,COALESCE(p.ciphertext,X''),COALESCE(q.payload,X'') FROM worker_turn_sources t LEFT JOIN worker_output_spools p ON p.sequence=t.sequence LEFT JOIN worker_resource_interruptions q ON q.sequence=t.sequence WHERE t.native_generation=? AND (EXISTS(SELECT 1 FROM worker_terminal_reservations r WHERE r.sequence=t.sequence) OR p.sequence IS NOT NULL OR q.sequence IS NOT NULL)`, generation)
	if err != nil {
		return err
	}
	type candidate struct {
		source         NativeTurnSource
		cipher, marker []byte
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		c.source.NativeGeneration = generation
		if err = rows.Scan(&c.source.Sequence, &c.source.LogicalTurnID, &c.source.NativeSessionID, &c.source.SourceCommandID, &c.source.SourceAdmissionID, &c.source.InputKind, &c.cipher, &c.marker); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range candidates {
		s := c.source
		var settled, pending bool
		if s.NativeSessionID != sessionID {
			return ErrConflict
		}
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_intent WHERE sequence=? AND state IN ('completed','failed')) OR ?<=(SELECT retired FROM worker_meta WHERE singleton=1)`, s.Sequence, s.Sequence).Scan(&settled); err != nil {
			return err
		}
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_observations WHERE json_extract(payload,'$.turnSource.sequence')=?) OR EXISTS(SELECT 1 FROM worker_interaction_sources WHERE native_generation=? AND logical_turn=?)`, s.Sequence, generation, s.LogicalTurnID).Scan(&pending); err != nil {
			return err
		}
		if !settled || pending {
			return ErrConflict
		}
		if len(c.cipher) > 0 {
			tail, openErr := openOutputSpool(captureKey, j.scope, j.dir, generation, s.Sequence, c.cipher)
			clear(tail.Key)
			var origin struct {
				ID string `json:"id"`
			}
			if openErr != nil || tail.Text != "" || tail.Ready != nil || json.Unmarshal(tail.Origin, &origin) != nil || origin.ID != originID || tail.Source.NativeSessionID != sessionID || tail.Source.SourceCommandID != s.SourceCommandID || tail.Source.SourceAdmissionID != s.SourceAdmissionID || tail.Source.LogicalTurnID != s.LogicalTurnID || tail.Source.InputKind != s.InputKind {
				return ErrConflict
			}
		}
		if len(c.marker) > 0 {
			var m transport.NativeResourceInterruption
			if json.Unmarshal(c.marker, &m) != nil || m.Source.OriginID != originID || m.Source.NativeGeneration != generation || m.Source.SessionID != sessionID || m.Source.NativeTurnSequence != s.Sequence || m.Source.LogicalTurnID != s.LogicalTurnID || m.Source.SourceCommandID != s.SourceCommandID || m.Source.SourceAdmissionID != s.SourceAdmissionID || m.Source.InputKind != s.InputKind {
				return ErrConflict
			}
		}
	}
	// All candidates are authenticated before any mutation; caller COMMIT is
	// shared with receipt cleanup. Failure rolls the entire deletion back.
	for _, c := range candidates {
		for _, q := range []string{`DELETE FROM worker_output_spools WHERE sequence=?`, `DELETE FROM worker_terminal_reservations WHERE sequence=?`, `DELETE FROM worker_resource_interruptions WHERE sequence=?`} {
			if _, err = tx.ExecContext(ctx, q, c.source.Sequence); err != nil {
				return err
			}
		}
	}
	return nil
}
