package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

type NativeTurnSource struct {
	SourceTask        *transport.NativeTaskSource `json:"sourceTask,omitempty"`
	InputKind         string                      `json:"inputKind,omitempty"`
	Sequence          int64                       `json:"sequence"`
	LogicalTurnID     string                      `json:"logicalTurnId"`
	NativeGeneration  string                      `json:"nativeGeneration"`
	NativeSessionID   string                      `json:"nativeSessionId"`
	SourceCommandID   string                      `json:"sourceCommandId,omitempty"`
	SourceAdmissionID string                      `json:"sourceAdmissionId,omitempty"`
}

func logicalWorkerTurn(sequence int64) string { return fmt.Sprintf("pagnet-worker-turn-%d", sequence) }
func (j *Journal) initializeTurnSources() error {
	for _, query := range []string{
		`CREATE TABLE IF NOT EXISTS worker_turn_sources(sequence INTEGER NOT NULL,logical_turn TEXT NOT NULL,native_generation TEXT NOT NULL,native_session TEXT NOT NULL,source_command TEXT NOT NULL,source_admission TEXT NOT NULL,input_kind TEXT NOT NULL DEFAULT '',completed INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(native_generation,logical_turn))`,
		`CREATE TABLE IF NOT EXISTS worker_interaction_sources(native_generation TEXT NOT NULL,native_id TEXT NOT NULL,native_session TEXT NOT NULL,logical_turn TEXT NOT NULL,PRIMARY KEY(native_generation,native_session,native_id))`,
	} {
		if _, err := j.db.Exec(query); err != nil {
			return err
		}
	}
	columns, err := j.db.Query(`PRAGMA table_info(worker_turn_sources)`)
	if err != nil {
		return err
	}
	hasKind, hasTask := false, false
	for columns.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err = columns.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			columns.Close()
			return err
		}
		if name == "source_task" {
			hasTask = true
		}
		if name == "input_kind" {
			hasKind = true
		}
	}
	err = columns.Err()
	columns.Close()
	if err != nil {
		return err
	}
	if !hasKind {
		if _, err = j.db.Exec(`ALTER TABLE worker_turn_sources ADD COLUMN input_kind TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if !hasTask {
		if _, err = j.db.Exec(`ALTER TABLE worker_turn_sources ADD COLUMN source_task TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	var count int
	if err := j.db.QueryRow(`SELECT COUNT(*) FROM worker_turn_sources`).Scan(&count); err != nil {
		return err
	}
	if count > maxCommands {
		return ErrFull
	}
	if err := j.db.QueryRow(`SELECT COUNT(*) FROM worker_interaction_sources`).Scan(&count); err != nil {
		return err
	}
	if count > maxPendingObservations {
		return ErrFull
	}
	return nil
}

// BindNativeTurn commits exact accepted operation provenance before the driver
// receives the request. Proven-unaccepted endpoint retry binds a new native
// generation, never rewrites a prior generation's source.
func (j *Journal) BindNativeTurn(ctx context.Context, source NativeTurnSource) error {
	if source.SourceTask != nil && (source.InputKind != "task" || source.SourceCommandID == "" || source.SourceTask.TaskID == "" || source.SourceTask.InputAAD.ObjectType != e2ee.ObjectTypeTask || source.SourceTask.InputAAD.ObjectID != source.SourceTask.TaskID || source.SourceTask.InputAAD.KeyEpochID == "" || source.SourceTask.InputAAD.NativeContent != nil || source.SourceTask.InputAAD.ValidateScope() != nil) {
		return errors.New("invalid original task source descriptor")
	}
	source.SourceTask = cloneNativeTaskSource(source.SourceTask)
	if (source.InputKind != "" && !ValidNativeInputKind(source.InputKind)) || source.Sequence <= 0 || source.LogicalTurnID != logicalWorkerTurn(source.Sequence) || source.NativeGeneration == "" || source.NativeSessionID == "" || len(source.NativeSessionID) > 1024 || len(source.NativeGeneration) > 256 || (source.SourceCommandID == "") != (source.SourceAdmissionID == "") || len(source.SourceCommandID) > 256 || len(source.SourceAdmissionID) > 256 {
		return errors.New("invalid accepted native turn source")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous NativeTurnSource
	previous, err = readNativeTurn(ctx, tx, source.NativeGeneration, source.LogicalTurnID)
	if err == nil {
		if !reflect.DeepEqual(previous, source) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var kind, state string
	if err = tx.QueryRowContext(ctx, `SELECT kind,state FROM worker_intent WHERE sequence=?`, source.Sequence).Scan(&kind, &state); err != nil {
		return err
	}
	if kind != "prompt" || state != "admitted" {
		return ErrConflict
	}
	// A source remains while its original outcome or any original event/choice
	// still needs it. No current-controller admission is inferred during pruning.
	_, err = tx.ExecContext(ctx, `DELETE FROM worker_turn_sources AS t WHERE completed=1 AND sequence<=(SELECT retired FROM worker_meta WHERE singleton=1) AND NOT EXISTS(SELECT 1 FROM worker_interaction_sources i WHERE i.native_generation=t.native_generation AND i.logical_turn=t.logical_turn) AND NOT EXISTS(SELECT 1 FROM worker_observations o WHERE json_extract(o.payload,'$.nativeGeneration')=t.native_generation AND json_extract(o.payload,'$.turnSource.logicalTurnId')=t.logical_turn)`)
	if err != nil {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_turn_sources`).Scan(&count); err != nil {
		return err
	}
	if count >= maxCommands {
		return ErrFull
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO worker_turn_sources(sequence,logical_turn,native_generation,native_session,source_command,source_admission,input_kind,source_task) VALUES(?,?,?,?,?,?,?,?)`, source.Sequence, source.LogicalTurnID, source.NativeGeneration, source.NativeSessionID, source.SourceCommandID, source.SourceAdmissionID, source.InputKind, taskSourceJSON(source.SourceTask))
	if err != nil {
		return err
	}
	return tx.Commit()
}
func readNativeTurn(ctx context.Context, tx *sql.Tx, generation, turn string) (NativeTurnSource, error) {
	var source NativeTurnSource
	var task string
	err := tx.QueryRowContext(ctx, `SELECT sequence,logical_turn,native_generation,native_session,source_command,source_admission,input_kind,source_task FROM worker_turn_sources WHERE native_generation=? AND logical_turn=?`, generation, turn).Scan(&source.Sequence, &source.LogicalTurnID, &source.NativeGeneration, &source.NativeSessionID, &source.SourceCommandID, &source.SourceAdmissionID, &source.InputKind, &task)
	if err == nil && task != "" {
		err = json.Unmarshal([]byte(task), &source.SourceTask)
	}
	return source, err
}

// A resolution uses the interaction's first source, even if a vendor reports
// the newest active turn ID. Human/background events have no fabricated source.
func (j *Journal) NativeEventSource(ctx context.Context, generation string, event session.SessionEvent) (*NativeTurnSource, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	turn := event.TurnID
	if event.Interaction != nil {
		var original string
		err = tx.QueryRowContext(ctx, `SELECT logical_turn FROM worker_interaction_sources WHERE native_generation=? AND native_session=? AND native_id=?`, generation, event.SessionID, event.Interaction.NativeInteractionID).Scan(&original)
		if err == nil {
			turn = original
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, false, err
		}
	}
	source, err := readNativeTurn(ctx, tx, generation, turn)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, strings.HasPrefix(turn, "pagnet-worker-turn-"), nil
	}
	if err != nil {
		return nil, false, err
	}
	if source.NativeSessionID != event.SessionID {
		return nil, false, ErrConflict
	}
	return &source, false, nil
}

// Called inside the same transaction as complete encrypted source COMMIT.
func retainNativeEventSource(ctx context.Context, tx *sql.Tx, observation NativeObservation) error {
	event := observation.Event
	if len(event.TurnID) > 256 || len(event.SessionID) > 1024 {
		return errors.New("native source session/turn identity exceeds bound")
	}
	if event.Interaction != nil && len(event.Interaction.NativeInteractionID) > 1024 {
		return errors.New("native interaction source identity exceeds bound")
	}
	if observation.TurnSource != nil {
		stored, err := readNativeTurn(ctx, tx, observation.NativeGeneration, observation.TurnSource.LogicalTurnID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(stored, *observation.TurnSource) {
			return ErrConflict
		}
	}
	if event.Interaction != nil && event.Interaction.NativeInteractionID != "" {
		if event.Interaction.Resolved {
			if _, err := tx.ExecContext(ctx, `DELETE FROM worker_interaction_sources WHERE native_generation=? AND native_session=? AND native_id=?`, observation.NativeGeneration, event.SessionID, event.Interaction.NativeInteractionID); err != nil {
				return err
			}
		} else {
			originalTurn := event.TurnID
			if observation.TurnSource != nil {
				originalTurn = observation.TurnSource.LogicalTurnID
			}
			var turn string
			err := tx.QueryRowContext(ctx, `SELECT logical_turn FROM worker_interaction_sources WHERE native_generation=? AND native_session=? AND native_id=?`, observation.NativeGeneration, event.SessionID, event.Interaction.NativeInteractionID).Scan(&turn)
			if err == nil {
				if turn != originalTurn {
					return ErrConflict
				}
			} else if errors.Is(err, sql.ErrNoRows) {
				var count int
				if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_interaction_sources`).Scan(&count); err != nil {
					return err
				}
				if count >= maxPendingObservations {
					return ErrFull
				}
				if _, err = tx.ExecContext(ctx, `INSERT INTO worker_interaction_sources(native_generation,native_id,native_session,logical_turn) VALUES(?,?,?,?)`, observation.NativeGeneration, event.Interaction.NativeInteractionID, event.SessionID, originalTurn); err != nil {
					return err
				}
			} else {
				return err
			}
		}
	}
	if observation.TurnSource != nil && (event.Type == session.EventTurnCompleted || event.Type == session.EventTurnFailed || event.Type == session.EventSessionLost) {
		_, err := tx.ExecContext(ctx, `UPDATE worker_turn_sources SET completed=1 WHERE native_generation=? AND logical_turn=?`, observation.NativeGeneration, observation.TurnSource.LogicalTurnID)
		return err
	}
	return nil
}

func (d *ownedDriver) Submit(ctx context.Context, sess *session.RuntimeSession, req session.SubmitRequest, events chan<- session.SessionEvent) error {
	if req.Kind != session.SubmitPrompt {
		return d.Driver.Submit(ctx, sess, req, events)
	}
	o := d.owner
	o.mu.Lock()
	source := o.candidateTurnSource
	source.NativeGeneration = o.generation
	o.mu.Unlock()
	source.NativeSessionID = sess.NativeID
	source.LogicalTurnID = req.TurnID
	if err := o.journal.BindNativeTurn(ctx, source); err != nil {
		return err
	}
	o.pinOriginalTaskContent(source)
	return d.Driver.Submit(ctx, sess, req, events)
}

// Clone before acceptance: caller-owned nested AAD pointers must not change the
// original command descriptor while a native callback commits its source.
func cloneNativeTaskSource(source *transport.NativeTaskSource) *transport.NativeTaskSource {
	if source == nil {
		return nil
	}
	var copy transport.NativeTaskSource
	_ = json.Unmarshal([]byte(taskSourceJSON(source)), &copy)
	return &copy
}
func taskSourceJSON(source *transport.NativeTaskSource) string {
	if source == nil {
		return ""
	}
	encoded, _ := json.Marshal(source)
	return string(encoded)
}
