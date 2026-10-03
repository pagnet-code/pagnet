package sessionworker

import "database/sql"

const nativeTurnLookupSQL = `SELECT sequence,logical_turn,native_generation,native_session,source_command,source_admission,input_kind,source_task FROM worker_turn_sources WHERE native_generation=? AND logical_turn=?`
const outputSpoolLookupSQL = `SELECT ciphertext FROM worker_output_spools WHERE sequence=? AND native_generation=?`
const outputSpoolReserveSQL = `UPDATE worker_terminal_reservations SET capture_left=capture_left-? WHERE sequence=? AND observation_id='' AND capture_left-?>=?`
const outputSpoolAppendSQL = `INSERT INTO worker_output_spools(sequence,native_generation,ciphertext,size) VALUES(?,?,?,?) ON CONFLICT(sequence) DO UPDATE SET ciphertext=excluded.ciphertext,size=excluded.size`

// These journal-owned statements run for each native output delta. Preparing
// once avoids repeatedly parsing identical SQL under small-delta streams. The
// DB owns their lifetime; transaction bindings keep the same FULL commits and
// atomic reserve checks. No data, authority result or plaintext is cached.
func (j *Journal) prepareNativeOutputStatements() error {
	for _, entry := range []struct {
		query       string
		destination **sql.Stmt
	}{
		{nativeTurnLookupSQL, &j.nativeTurnLookup},
		{outputSpoolLookupSQL, &j.outputSpoolLookup},
		{outputSpoolReserveSQL, &j.outputSpoolReserve},
		{outputSpoolAppendSQL, &j.outputSpoolAppend},
	} {
		stmt, err := j.db.Prepare(entry.query)
		if err != nil {
			return err
		}
		*entry.destination = stmt
	}
	return nil
}
