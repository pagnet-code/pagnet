package sessionworker

import (
	"context"
	"database/sql"
	"errors"
	"github.com/pagnet-code/pagnet/internal/session"
)

// One accepted native stream (20 MiB) plus its distinct maximum final source.
// Reservations occupy the EXISTING aggregate budgets, not additional queues.
const terminalCaptureReserveBytes = 42 << 20
const terminalContentReserveBytes = 64 << 20
const terminalSourceReserveRows = 384

var ErrNativeCaptureLimit = errors.New("accepted native source capture capacity reached")
var ErrNativeEventLimit = errors.New("accepted native source event capacity reached")

func (j *Journal) initializeTerminalReservations() error {
	_, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_terminal_reservations(sequence INTEGER PRIMARY KEY,observation_id TEXT NOT NULL DEFAULT '',rows_left INTEGER NOT NULL,capture_left INTEGER NOT NULL,content_left INTEGER NOT NULL)`)
	if err != nil {
		return err
	}
	var count, invalid, reservedRows, captures, content int
	if err = j.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(CASE WHEN sequence<1 OR rows_left<0 OR rows_left>384 OR capture_left<0 OR capture_left>44040192 OR content_left<0 OR content_left>67108864 THEN 1 ELSE 0 END),0),COALESCE(SUM(rows_left),0),COALESCE(SUM(capture_left),0),COALESCE(SUM(content_left),0) FROM worker_terminal_reservations`).Scan(&count, &invalid, &reservedRows, &captures, &content); err != nil {
		return err
	}
	var usedRows, usedCapture, usedContent int
	if err = j.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(size),0)+(SELECT COALESCE(SUM(size),0) FROM worker_source_captures)+(SELECT COALESCE(SUM(size),0) FROM worker_source_dispositions)+(SELECT COALESCE(SUM(size),0) FROM worker_output_spools)+(SELECT COALESCE(SUM(length(payload)),0) FROM worker_resource_interruptions),(SELECT COALESCE(SUM(size),0) FROM worker_content_fragments) FROM worker_observations`).Scan(&usedRows, &usedCapture, &usedContent); err != nil {
		return err
	}
	if invalid != 0 || count > maxCommands || usedRows+reservedRows > maxPendingObservations || usedCapture+captures > maxPendingObservationBytes || usedContent+content > maxWorkerContentBytes {
		return errors.New("accepted native reservation exceeds immutable journal bounds")
	}
	return nil
}
func terminalReservationsTx(ctx context.Context, tx *sql.Tx) (rows, captures, content int, err error) {
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(rows_left),0),COALESCE(SUM(capture_left),0),COALESCE(SUM(content_left),0) FROM worker_terminal_reservations`).Scan(&rows, &captures, &content)
	return
}
func (j *Journal) reserveTerminalTx(ctx context.Context, tx *sql.Tx, sequence int64, kind string) error {
	if kind != "prompt" {
		return nil
	}
	rows, captures, content, err := terminalReservationsTx(ctx, tx)
	if err != nil {
		return err
	}
	var count, total, unmarked, fragments int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(size),0)+(SELECT COALESCE(SUM(size),0) FROM worker_source_captures)+(SELECT COALESCE(SUM(size),0) FROM worker_source_dispositions)+(SELECT COALESCE(SUM(size),0) FROM worker_output_spools)+(SELECT COALESCE(SUM(length(payload)),0) FROM worker_resource_interruptions),(SELECT COUNT(*) FROM worker_observations o WHERE NOT EXISTS(SELECT 1 FROM worker_source_dispositions d WHERE d.observation_id=o.id)),(SELECT COALESCE(SUM(size),0) FROM worker_content_fragments) FROM worker_observations`).Scan(&count, &total, &unmarked, &fragments)
	if err != nil {
		return err
	}
	stops := j.sourceStopReservationsLocked()
	if count+stops+rows+terminalSourceReserveRows > maxPendingObservations || total+unmarked*sourceDispositionReserveBytes+stops*sourceStopReserveBytes+captures+terminalCaptureReserveBytes > maxPendingObservationBytes || fragments+content+terminalContentReserveBytes > maxWorkerContentBytes {
		return ErrFull
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO worker_terminal_reservations(sequence,rows_left,capture_left,content_left) VALUES(?,?,?,?)`, sequence, terminalSourceReserveRows, terminalCaptureReserveBytes, terminalContentReserveBytes)
	return err
}
func consumeTerminalReservationTx(ctx context.Context, tx *sql.Tx, observation NativeObservation, captureBytes, contentBytes int) (bool, error) {
	if observation.TurnSource == nil {
		return false, nil
	}
	var rows, captures, content int
	var terminal string
	err := tx.QueryRowContext(ctx, `SELECT observation_id,rows_left,capture_left,content_left FROM worker_terminal_reservations WHERE sequence=?`, observation.TurnSource.Sequence).Scan(&terminal, &rows, &captures, &content)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	isFinal := observation.Event.Type == session.EventTurnCompleted || observation.Event.Type == session.EventTurnFailed
	if terminal != "" && (isFinal || observation.Event.Type == session.EventTurnOutput || observation.Event.Type == session.EventPlanUpdated || observation.Event.Type == session.EventTurnStarted) {
		return false, ErrConflict
	}
	if terminal != "" && rows == 0 {
		return false, nil
	}
	minimumRows, minimumCapture, minimumContent := 0, 0, 0
	if !isFinal && terminal == "" {
		minimumRows, minimumCapture, minimumContent = 2, terminalCaptureReserveBytes/2, terminalContentReserveBytes/2
		if observation.outputProjection != nil {
			var interrupted bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_resource_interruptions WHERE sequence=?)`, observation.TurnSource.Sequence).Scan(&interrupted); err != nil {
				return false, err
			}
			// No terminal vendor event will be fabricated after a resource stop. Its
			// unused final capacity can finish projecting already FULL-captured tail.
			if interrupted {
				minimumRows, minimumCapture, minimumContent = 0, 0, 0
			}
		}
	}
	if rows-1 < minimumRows {
		return false, ErrNativeEventLimit
	}
	if captures-captureBytes < minimumCapture || content-contentBytes < minimumContent {
		return false, ErrNativeCaptureLimit
	}
	if observation.Event.Type == session.EventTurnCompleted || observation.Event.Type == session.EventTurnFailed {
		terminal = observation.ID
	}
	if isFinal {
		// All prior output was flushed before this complete genuine terminal
		// capture. Release UNUSED future capacity in this same FULL commit;
		// retain the terminal identity and all evidence until a real receipt.
		_, err = tx.ExecContext(ctx, `UPDATE worker_terminal_reservations SET observation_id=?,rows_left=1,capture_left=MIN(capture_left-?,?),content_left=0 WHERE sequence=?`, terminal, captureBytes, sourceStopReserveBytes, observation.TurnSource.Sequence)
	} else if terminal != "" {
		// One trailing native status/idle callback has reserved metadata space.
		_, err = tx.ExecContext(ctx, `UPDATE worker_terminal_reservations SET rows_left=0,capture_left=0,content_left=0 WHERE sequence=?`, observation.TurnSource.Sequence)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE worker_terminal_reservations SET observation_id=?,rows_left=rows_left-1,capture_left=capture_left-?,content_left=content_left-? WHERE sequence=?`, terminal, captureBytes, contentBytes, observation.TurnSource.Sequence)
	}
	return true, err
}
