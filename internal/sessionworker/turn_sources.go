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
	SourceInvocation  *transport.NativeInvocationSource `json:"sourceInvocation,omitempty"`
	SourceTask        *transport.NativeTaskSource       `json:"sourceTask,omitempty"`
	InputKind         string                            `json:"inputKind,omitempty"`
	Sequence          int64                             `json:"sequence"`
	LogicalTurnID     string                            `json:"logicalTurnId"`
	NativeGeneration  string                            `json:"nativeGeneration"`
	NativeSessionID   string                            `json:"nativeSessionId"`
	SourceCommandID   string                            `json:"sourceCommandId,omitempty"`
	SourceAdmissionID string                            `json:"sourceAdmissionId,omitempty"`
}

func logicalWorkerTurn(sequence int64) string { return fmt.Sprintf("pagnet-worker-turn-%d", sequence) }
func (j *Journal) initializeTurnSources() error {
	for _, query := range []string{
		`CREATE TABLE IF NOT EXISTS worker_turn_sources(sequence INTEGER NOT NULL,logical_turn TEXT NOT NULL,native_generation TEXT NOT NULL,native_session TEXT NOT NULL,source_command TEXT NOT NULL,source_admission TEXT NOT NULL,input_kind TEXT NOT NULL DEFAULT '',completed INTEGER NOT NULL DEFAULT 0,started INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(native_generation,logical_turn))`,
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
	hasKind, hasTask, hasStarted, hasInvocation := false, false, false, false
	for columns.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err = columns.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			columns.Close()
			return err
		}
		if name == "source_invocation" {
			hasInvocation = true
		}
		if name == "started" {
			hasStarted = true
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
	if !hasStarted {
		if _, err = j.db.Exec(`ALTER TABLE worker_turn_sources ADD COLUMN started INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if !hasTask {
		if _, err = j.db.Exec(`ALTER TABLE worker_turn_sources ADD COLUMN source_task TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if !hasInvocation {
		if _, err = j.db.Exec(`ALTER TABLE worker_turn_sources ADD COLUMN source_invocation TEXT NOT NULL DEFAULT ''`); err != nil {
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
	if j.isLocal() && (source.SourceTask != nil || source.SourceInvocation != nil || source.InputKind != "local-native") {
		return ErrFenced
	}
	if source.SourceTask != nil && source.SourceInvocation != nil {
		return errors.New("native turn has conflicting source authorities")
	}
	if source.SourceInvocation != nil && (source.InputKind != "invocation" || source.SourceCommandID == "" || source.SourceAdmissionID == "" || source.SourceInvocation.Validate() != nil) {
		return errors.New("invalid original invocation source descriptor")
	}
	if source.InputKind == "invocation" && source.SourceInvocation == nil {
		return errors.New("native invocation source is missing")
	}
	source.SourceInvocation = cloneNativeInvocationSource(source.SourceInvocation)
	if source.SourceTask != nil && (source.InputKind != "task" || source.SourceCommandID == "" || source.SourceTask.TaskID == "" || source.SourceTask.InputAAD.ObjectType != e2ee.ObjectTypeTask || source.SourceTask.InputAAD.ObjectID != source.SourceTask.TaskID || source.SourceTask.InputAAD.KeyEpochID == "" || source.SourceTask.InputAAD.NativeContent != nil || source.SourceTask.InputAAD.ValidateScope() != nil) {
		return errors.New("invalid original task source descriptor")
	}
	source.SourceTask = cloneNativeTaskSource(source.SourceTask)
	if (source.InputKind != "" && !ValidNativeInputKind(source.InputKind) && !(j.isLocal() && source.InputKind == "local-native")) || source.Sequence <= 0 || source.LogicalTurnID != logicalWorkerTurn(source.Sequence) || source.NativeGeneration == "" || source.NativeSessionID == "" || len(source.NativeSessionID) > 1024 || len(source.NativeGeneration) > 256 || (source.SourceCommandID == "") != (source.SourceAdmissionID == "") || len(source.SourceCommandID) > 256 || len(source.SourceAdmissionID) > 256 {
		return errors.New("invalid accepted native turn source")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if j.isLocal() {
		original, e := j.localIntentSource(ctx, tx, source.Sequence)
		if e != nil {
			return e
		}
		if original.Commitment.CommandID != source.SourceCommandID || original.Admission.ID != source.SourceAdmissionID {
			return ErrConflict
		}
	}
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
	_, err = tx.ExecContext(ctx, `DELETE FROM worker_turn_sources AS t WHERE NOT EXISTS(SELECT 1 FROM worker_invocation_streams s WHERE s.sequence=t.sequence AND s.closed=0) AND completed=1 AND sequence<=(SELECT retired FROM worker_meta WHERE singleton=1) AND NOT EXISTS(SELECT 1 FROM worker_interaction_sources i WHERE i.native_generation=t.native_generation AND i.logical_turn=t.logical_turn) AND NOT EXISTS(SELECT 1 FROM worker_observations o WHERE json_extract(o.payload,'$.nativeGeneration')=t.native_generation AND json_extract(o.payload,'$.turnSource.logicalTurnId')=t.logical_turn)`+j.localStreamRetentionPredicate())
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
	_, err = tx.ExecContext(ctx, `INSERT INTO worker_turn_sources(sequence,logical_turn,native_generation,native_session,source_command,source_admission,input_kind,source_task,source_invocation) VALUES(?,?,?,?,?,?,?,?,?)`, source.Sequence, source.LogicalTurnID, source.NativeGeneration, source.NativeSessionID, source.SourceCommandID, source.SourceAdmissionID, source.InputKind, taskSourceJSON(source.SourceTask), invocationSourceJSON(source.SourceInvocation))
	if err != nil {
		return err
	}
	return tx.Commit()
}
func readNativeTurn(ctx context.Context, tx *sql.Tx, generation, turn string) (NativeTurnSource, error) {
	return scanNativeTurn(tx.QueryRowContext(ctx, nativeTurnLookupSQL, generation, turn))
}

func scanNativeTurn(row *sql.Row) (NativeTurnSource, error) {
	var source NativeTurnSource
	var task, invocation string
	err := row.Scan(&source.Sequence, &source.LogicalTurnID, &source.NativeGeneration, &source.NativeSessionID, &source.SourceCommandID, &source.SourceAdmissionID, &source.InputKind, &task, &invocation)
	if err == nil && task != "" {
		err = json.Unmarshal([]byte(task), &source.SourceTask)
	}
	if err == nil && invocation != "" {
		err = json.Unmarshal([]byte(invocation), &source.SourceInvocation)
	}
	return source, err
}

// A resolution uses the interaction's first source, even if a vendor reports
// the newest active turn ID. Human/background events have no fabricated source.
func (j *Journal) NativeEventSource(ctx context.Context, generation string, event session.SessionEvent) (*NativeTurnSource, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	// A non-interaction event needs one immutable source row. Its SELECT is
	// already a single SQLite snapshot; a separate BEGIN/ROLLBACK adds no
	// consistency while forcing extra parser work for every tiny output delta.
	if event.Interaction == nil {
		source, err := scanNativeTurn(j.nativeTurnLookup.QueryRowContext(ctx, generation, event.TurnID))
		return nativeEventSourceResult(source, err, event.TurnID, event.SessionID)
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	turn := event.TurnID
	var original string
	err = tx.QueryRowContext(ctx, `SELECT logical_turn FROM worker_interaction_sources WHERE native_generation=? AND native_session=? AND native_id=?`, generation, event.SessionID, event.Interaction.NativeInteractionID).Scan(&original)
	if err == nil {
		turn = original
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	source, err := readNativeTurn(ctx, tx, generation, turn)
	return nativeEventSourceResult(source, err, turn, event.SessionID)
}

func nativeEventSourceResult(source NativeTurnSource, err error, turn, sessionID string) (*NativeTurnSource, bool, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return nil, strings.HasPrefix(turn, "pagnet-worker-turn-"), nil
	}
	if err != nil {
		return nil, false, err
	}
	if source.NativeSessionID != sessionID {
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
	if observation.TurnSource != nil && event.Type == session.EventTurnStarted {
		if _, err := tx.ExecContext(ctx, `UPDATE worker_turn_sources SET started=1 WHERE native_generation=? AND logical_turn=?`, observation.NativeGeneration, observation.TurnSource.LogicalTurnID); err != nil {
			return err
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
	if cancelled, e := o.journal.localCancellationRequested(source.Sequence); e != nil || cancelled {
		if e != nil {
			return e
		}
		return context.Canceled
	}
	source.NativeSessionID = sess.NativeID
	source.LogicalTurnID = req.TurnID
	o.pinOriginalTaskContent(source)
	if source.SourceTask != nil || source.SourceInvocation != nil {
		if _, available := o.originalTaskContentPin(&source); !available {
			o.releaseNativeTaskTurnPin(&source)
			return errors.New("original input crypto authority unavailable")
		}
	}
	if err := o.journal.BindNativeTurn(ctx, source); err != nil {
		o.releaseNativeTaskTurnPin(&source)
		return err
	}
	if o.journal.isLocal() && source.InputKind == "local-native" {
		if err := o.journal.BeginLocalInvocationStream(ctx, o.captureKey, source); err != nil {
			return err
		}
	}
	if source.SourceInvocation != nil {
		key, available := o.originalTaskContentPin(&source)
		if !available {
			return errors.New("original invocation crypto authority unavailable")
		}
		o.mu.Lock()
		origin := append(json.RawMessage(nil), o.origin...)
		o.mu.Unlock()
		err := o.journal.beginInvocationStream(ctx, o.captureKey, source, origin, key)
		clear(key[:])
		if err != nil {
			o.releaseNativeTaskTurnPin(&source)
			return err
		}
	}
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

// Completed native sources remain immutable journal evidence, but no longer
// impersonate a managed turn for genuine human/background endpoint calls.
// Unknown/uncertain history and failed reads never become endpoint authority.
func (j *Journal) activeNativeBridgeSource(ctx context.Context, generation, sessionID, turn string) (*NativeTurnSource, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	source, err := readNativeTurn(ctx, tx, generation, turn)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if source.NativeSessionID != sessionID {
		return nil, ErrConflict
	}
	var completed int
	var state string
	err = tx.QueryRowContext(ctx, `SELECT t.completed,COALESCE(w.state,'retired') FROM worker_turn_sources t LEFT JOIN worker_intent w ON w.sequence=t.sequence WHERE t.native_generation=? AND t.logical_turn=?`, generation, turn).Scan(&completed, &state)
	if err != nil {
		return nil, err
	}
	if state == "uncertain" {
		return nil, ErrConflict
	}
	if completed == 1 {
		return nil, nil
	}
	if completed != 0 || state == "retired" {
		return nil, ErrConflict
	}
	return &source, nil
}

func cloneNativeInvocationSource(source *transport.NativeInvocationSource) *transport.NativeInvocationSource {
	if source == nil {
		return nil
	}
	var copy transport.NativeInvocationSource
	_ = json.Unmarshal([]byte(invocationSourceJSON(source)), &copy)
	return &copy
}
func invocationSourceJSON(source *transport.NativeInvocationSource) string {
	if source == nil {
		return ""
	}
	encoded, _ := json.Marshal(source)
	return string(encoded)
}

// The source kind and full accepted descriptor remain part of a key pin. A
// completed task cannot become an invocation merely by changing input labels.
func sourceContentDescriptor(source *NativeTurnSource) string {
	if source == nil || source.SourceTask != nil && source.SourceInvocation != nil {
		return ""
	}
	if source.SourceInvocation != nil && source.InputKind == "invocation" && source.SourceInvocation.Validate() == nil {
		return "invocation:" + invocationSourceJSON(source.SourceInvocation)
	}
	if source.SourceTask != nil {
		return taskSourceJSON(source.SourceTask)
	}
	return ""
}
func sourceContentAAD(source *NativeTurnSource) (e2ee.AAD, bool) {
	if sourceContentDescriptor(source) == "" || source.SourceTask != nil && source.InputKind != "task" {
		return e2ee.AAD{}, false
	}
	if source.SourceInvocation != nil {
		return source.SourceInvocation.InputAAD, true
	}
	aad := source.SourceTask.InputAAD
	if source.SourceTask.TaskID == "" || aad.ObjectType != e2ee.ObjectTypeTask || aad.ObjectID != source.SourceTask.TaskID || aad.KeyEpochID == "" || aad.NativeContent != nil || aad.ValidateScope() != nil {
		return e2ee.AAD{}, false
	}
	return aad, true
}
