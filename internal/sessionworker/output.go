package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
)

const maxOutputBytes = 2 << 20
const maxOutputRecord = 128 << 10

type OutputRecord struct {
	Sequence         int64           `json:"sequence"`
	NativeGeneration string          `json:"nativeGeneration"`
	Origin           json.RawMessage `json:"origin,omitempty"`
	Kind             string          `json:"kind"`
	Data             json.RawMessage `json:"data"`
}
type OutputPage struct {
	Records        []OutputRecord `json:"records"`
	RetiredThrough int64          `json:"retiredThrough"`
	NextSequence   int64          `json:"nextSequence"`
	Gap            bool           `json:"gap"`
}

func (j *Journal) initializeOutput() error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS worker_output_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),next_sequence INTEGER NOT NULL,retired INTEGER NOT NULL,bytes INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS worker_output(sequence INTEGER PRIMARY KEY,native_generation TEXT NOT NULL,origin BLOB,kind TEXT NOT NULL,data BLOB NOT NULL,size INTEGER NOT NULL)`,
		`INSERT OR IGNORE INTO worker_output_meta VALUES(1,1,0,0)`,
	} {
		if _, err := j.db.Exec(q); err != nil {
			return err
		}
	}
	var next, retired, bytes, count, sum int64
	if err := j.db.QueryRow(`SELECT next_sequence,retired,bytes,(SELECT COUNT(*) FROM worker_output),(SELECT COALESCE(SUM(size),0) FROM worker_output) FROM worker_output_meta WHERE singleton=1`).Scan(&next, &retired, &bytes, &count, &sum); err != nil {
		return err
	}
	if next < 1 || retired < 0 || retired >= next || bytes < 0 || bytes > maxOutputBytes || sum != bytes || next-retired-1 != count {
		return errors.New("worker output journal history is invalid")
	}
	rows, err := j.db.Query(`SELECT sequence,native_generation,origin,kind,data,size FROM worker_output ORDER BY sequence`)
	if err != nil {
		return err
	}
	defer rows.Close()
	sequence := retired + 1
	for rows.Next() {
		var actual, size int64
		var generation, kind string
		var origin, data []byte
		if err := rows.Scan(&actual, &generation, &origin, &kind, &data, &size); err != nil {
			return err
		}
		if actual != sequence || !validOutput(generation, origin, kind, data) || size != int64(len(generation)+len(origin)+len(kind)+len(data)) {
			return errors.New("worker output journal row is invalid")
		}
		sequence++
	}
	return rows.Err()
}

func validOutput(generation string, origin json.RawMessage, kind string, data json.RawMessage) bool {
	size := len(origin) + len(data) + len(generation) + len(kind)
	return generation != "" && len(generation) <= 256 && len(origin) <= 8192 && (len(origin) == 0 || json.Valid(origin)) && (kind == "terminal" || kind == "session") && json.Valid(data) && size <= maxOutputRecord
}

// AppendOutput owns the sole durable sequence. Replay trimming advances an
// explicit floor; a replacement controller can distinguish a gap from no output.
func (j *Journal) AppendOutput(ctx context.Context, generation string, origin json.RawMessage, kind string, data json.RawMessage) (int64, error) {
	size := len(origin) + len(data) + len(generation) + len(kind)
	if !validOutput(generation, origin, kind, data) {
		return 0, errors.New("invalid or oversized worker output")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var next, retired, total int64
	if err = tx.QueryRow(`SELECT next_sequence,retired,bytes FROM worker_output_meta WHERE singleton=1`).Scan(&next, &retired, &total); err != nil {
		return 0, err
	}
	if next == 9223372036854775807 {
		return 0, errors.New("worker output sequence exhausted")
	}
	if _, err = tx.Exec(`INSERT INTO worker_output VALUES(?,?,?,?,?,?)`, next, generation, []byte(origin), kind, []byte(data), size); err != nil {
		return 0, err
	}
	total += int64(size)
	for total > maxOutputBytes {
		var oldSize int64
		if err = tx.QueryRow(`SELECT size FROM worker_output WHERE sequence=?`, retired+1).Scan(&oldSize); err != nil {
			return 0, err
		}
		retired++
		total -= oldSize
	}
	if _, err = tx.Exec(`DELETE FROM worker_output WHERE sequence<=?`, retired); err != nil {
		return 0, err
	}
	if _, err = tx.Exec(`UPDATE worker_output_meta SET next_sequence=?,retired=?,bytes=? WHERE singleton=1`, next+1, retired, total); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}
func (j *Journal) ReplayOutput(ctx context.Context, after int64, limit int) (page OutputPage, err error) {
	if after < 0 || limit < 1 || limit > 64 {
		return page, errors.New("invalid replay cursor or bound")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err = j.db.QueryRowContext(ctx, `SELECT next_sequence,retired FROM worker_output_meta WHERE singleton=1`).Scan(&page.NextSequence, &page.RetiredThrough); err != nil {
		return page, err
	}
	page.Gap = after < page.RetiredThrough
	rows, err := j.db.QueryContext(ctx, `SELECT sequence,native_generation,origin,kind,data FROM worker_output WHERE sequence>? ORDER BY sequence LIMIT ?`, after, limit)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	pageBytes := 0
	for rows.Next() {
		var record OutputRecord
		var origin, data []byte
		if err = rows.Scan(&record.Sequence, &record.NativeGeneration, &origin, &record.Kind, &data); err != nil {
			return page, err
		}
		record.Origin = json.RawMessage(origin)
		record.Data = json.RawMessage(data)
		encoded, encodeErr := json.Marshal(record)
		if encodeErr != nil {
			return page, encodeErr
		}
		// Leave frame space for the response wrapper and cursor metadata.
		if pageBytes+len(encoded) > maxFrame*3/4 {
			break
		}
		pageBytes += len(encoded)
		page.Records = append(page.Records, record)
	}
	return page, rows.Err()
}
