package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/transport"
)

// HostedSourceFinalMaxBytes bounds the daemon's retained composed final
// output. The bound is chosen against the existing 512 KiB transport budget
// (transport.EndpointInvocationResultMaxBytes): the retained output is stored
// SEALED (e2ee.EncryptedPayloadV1 + AAD, base64 ciphertext + wrapped CEK +
// fixed fields ~= 4/3 of the plaintext plus ~0.4 KiB of envelope), so 380 KiB
// of plaintext is the largest output whose sealed envelope still fits one
// endpoint invocation result. An output beyond the bound is refused before
// acceptance (capacity), never truncated — a partial raw output is never a
// truthful final.
const HostedSourceFinalMaxBytes = 380 << 10

// HostedSourceFinalMaxPages bounds the checkpointed page count (one page per
// consumed 64 KiB projection window); it mirrors the worker stream's
// bounded-rows capacity discipline for the daemon-side retention.
const HostedSourceFinalMaxPages = 16384

var ErrHostedSourceCapacity = errors.New("hosted source final output capacity reached")
var ErrHostedSourceConflict = errors.New("hosted source final output identity conflicts with its recorded state")

// HostedSourceFinalRow is the daemon-state retention of one consumed hosted
// invocation: the pinned source authority, the checkpointed sealed composed
// output, and its truthful state.
type HostedSourceFinalRow struct {
	InstanceID    string
	CommandID     string
	State         string // streaming | complete | failed | unavailable
	Profile       string // pinned fabricagent.HostedProfile JSON
	Proof         string // pinned transport.NativeDispatchProof JSON
	Source        string // retained sessionworker.NativeTurnSource JSON (first verified page)
	Origin        string // retained origin JSON (first verified page)
	AAD           string // sealed-output e2ee.AAD JSON (fixed at row creation)
	Ciphertext    []byte // sealed e2ee.EncryptedPayloadV1 JSON (nil until first checkpoint)
	DataBytes     int
	Pages         int
	CursorOrdinal int64
	CursorDigest  string
	Terminal      string // terminal sessionworker.NativeObservation JSON (final states)
	Reason        string // truthful failed/unavailable reason
	FirstAt       time.Time
	LastAt        time.Time
}

func (s *State) initHostedSourceFinals() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS hosted_source_finals (
 instance_id TEXT NOT NULL,command_id TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'streaming',
 profile TEXT NOT NULL,proof TEXT NOT NULL,
 source TEXT NOT NULL DEFAULT '',origin TEXT NOT NULL DEFAULT '',aad TEXT NOT NULL,
 ciphertext BLOB,data_bytes INTEGER NOT NULL DEFAULT 0,pages INTEGER NOT NULL DEFAULT 0,
 cursor_ordinal INTEGER NOT NULL DEFAULT 0,cursor_digest TEXT NOT NULL DEFAULT '',
 terminal TEXT NOT NULL DEFAULT '',reason TEXT NOT NULL DEFAULT '',
 first_at INTEGER NOT NULL,last_at INTEGER NOT NULL,
 PRIMARY KEY (instance_id, command_id));
 CREATE INDEX IF NOT EXISTS hosted_source_finals_inflight ON hosted_source_finals(state);`)
	return err
}

const hostedSourceFinalSelect = `SELECT instance_id,command_id,state,profile,proof,source,origin,aad,
 COALESCE(ciphertext,''),data_bytes,pages,cursor_ordinal,cursor_digest,terminal,reason,first_at,last_at
 FROM hosted_source_finals`

func scanHostedSourceFinalRow(row interface {
	Scan(dest ...any) error
}, r *HostedSourceFinalRow) error {
	var cipher []byte
	var first, last int64
	if err := row.Scan(&r.InstanceID, &r.CommandID, &r.State, &r.Profile, &r.Proof, &r.Source, &r.Origin,
		&r.AAD, &cipher, &r.DataBytes, &r.Pages, &r.CursorOrdinal, &r.CursorDigest, &r.Terminal, &r.Reason,
		&first, &last); err != nil {
		return err
	}
	r.Ciphertext = cipher
	r.FirstAt = time.UnixMilli(first).UTC()
	r.LastAt = time.UnixMilli(last).UTC()
	return nil
}

// LoadHostedSourceFinal returns the retained row for (instance, command)
// (ok=false when the daemon never consumed it).
func (s *State) LoadHostedSourceFinal(ctx context.Context, instanceID, commandID string) (HostedSourceFinalRow, bool, error) {
	var r HostedSourceFinalRow
	row := s.db.QueryRowContext(ctx, hostedSourceFinalSelect+` WHERE instance_id=? AND command_id=?`, instanceID, commandID)
	if err := scanHostedSourceFinalRow(row, &r); err == sql.ErrNoRows {
		return HostedSourceFinalRow{}, false, nil
	} else if err != nil {
		return HostedSourceFinalRow{}, false, err
	}
	return r, true, nil
}

// EnsureHostedSourceFinal persists the pinned authority row for a new
// consumption. An existing row is returned untouched: the consumer verifies
// the pinned profile/proof itself, so a re-entry can never overwrite authority
// or resume under a different one.
func (s *State) EnsureHostedSourceFinal(ctx context.Context, instanceID, commandID string, profile fabricagent.HostedProfile, proof transport.NativeDispatchProof, aad e2ee.AAD) (HostedSourceFinalRow, error) {
	if instanceID == "" || commandID == "" {
		return HostedSourceFinalRow{}, ErrHostedSourceConflict
	}
	profileJSON, err := json.Marshal(profile)
	if err != nil {
		return HostedSourceFinalRow{}, err
	}
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return HostedSourceFinalRow{}, err
	}
	aadJSON, err := json.Marshal(aad)
	if err != nil {
		return HostedSourceFinalRow{}, err
	}
	now := time.Now().UTC()
	var r HostedSourceFinalRow
	err = s.hostedSourceFinalWrite(ctx, func(conn *sql.Conn) error {
		err := scanHostedSourceFinalRow(
			conn.QueryRowContext(ctx, hostedSourceFinalSelect+` WHERE instance_id=? AND command_id=?`, instanceID, commandID), &r)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO hosted_source_finals
 (instance_id,command_id,state,profile,proof,aad,first_at,last_at)
 VALUES(?,?,?, ?, ?, ?, ?, ?)`,
			instanceID, commandID, "streaming", string(profileJSON), string(proofJSON), string(aadJSON),
			now.UnixMilli(), now.UnixMilli())
		if err != nil {
			return err
		}
		return scanHostedSourceFinalRow(
			conn.QueryRowContext(ctx, hostedSourceFinalSelect+` WHERE instance_id=? AND command_id=?`, instanceID, commandID), &r)
	})
	if err != nil {
		return HostedSourceFinalRow{}, err
	}
	return r, nil
}

// InFlightHostedSourceFinals returns the persisted in-flight (state='streaming')
// rows for startup resume, bounded so a corrupted state can never fan out
// unbounded consumers.
func (s *State) InFlightHostedSourceFinals(ctx context.Context, limit int) ([]HostedSourceFinalRow, error) {
	if limit <= 0 || limit > 64 {
		limit = 64
	}
	rows, err := s.db.QueryContext(ctx, hostedSourceFinalSelect+` WHERE state='streaming' ORDER BY instance_id,command_id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostedSourceFinalRow
	for rows.Next() {
		var r HostedSourceFinalRow
		if err := scanHostedSourceFinalRow(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CheckpointHostedSourceFinal persists the consumed page BEFORE the consumer
// acks its projection (the order is load-bearing: the worker truncates deltas
// below an acked cursor, so the daemon must already retain the page). The
// sealed ciphertext is the full composed output so far, under the row's fixed
// AAD. source/origin are pinned on the FIRST verified page and must match on
// every later one. The capacity bound is enforced before acceptance: an
// over-limit page is refused, never partially accepted.
func (s *State) CheckpointHostedSourceFinal(ctx context.Context, instanceID, commandID string, sourceJSON []byte, origin []byte, cipher e2ee.EncryptedPayloadV1, dataBytes int, ordinal int64, digest string) error {
	if dataBytes < 0 || ordinal < 1 || digest == "" {
		return ErrHostedSourceConflict
	}
	if dataBytes > HostedSourceFinalMaxBytes {
		// Over-limit is a CAPACITY refusal (the consumer finalizes it as
		// capacity_exhausted), never an identity conflict: conflating the two
		// would livelock the row instead of settling it truthfully.
		return ErrHostedSourceCapacity
	}
	cipherJSON, err := json.Marshal(cipher)
	if err != nil {
		return err
	}
	return s.hostedSourceFinalWrite(ctx, func(conn *sql.Conn) error {
		var r HostedSourceFinalRow
		err := scanHostedSourceFinalRow(
			conn.QueryRowContext(ctx, hostedSourceFinalSelect+` WHERE instance_id=? AND command_id=?`, instanceID, commandID), &r)
		if err != nil {
			return err
		}
		if r.State != "streaming" {
			return ErrHostedSourceConflict
		}
		if r.Source == "" {
			if len(sourceJSON) == 0 {
				return ErrHostedSourceConflict
			}
		} else if string(r.Source) != string(sourceJSON) {
			return ErrHostedSourceConflict
		}
		if r.Origin == "" {
			if len(origin) == 0 {
				return ErrHostedSourceConflict
			}
		} else if string(r.Origin) != string(origin) {
			return ErrHostedSourceConflict
		}
		if dataBytes < r.DataBytes || r.Pages+1 > HostedSourceFinalMaxPages || dataBytes > HostedSourceFinalMaxBytes {
			return ErrHostedSourceCapacity
		}
		_, err = conn.ExecContext(ctx, `UPDATE hosted_source_finals SET
 ciphertext=?,data_bytes=?,pages=pages+1,cursor_ordinal=?,cursor_digest=?,
 source=CASE WHEN source='' THEN ? ELSE source END,
 origin=CASE WHEN origin='' THEN ? ELSE origin END,
 last_at=?
 WHERE instance_id=? AND command_id=? AND state='streaming'`,
			cipherJSON, dataBytes, ordinal, digest, string(sourceJSON), string(origin),
			time.Now().UTC().UnixMilli(), instanceID, commandID)
		return err
	})
}

// FinalizeHostedSourceFinal is the ONE streaming→terminal transition (a single
// conditional UPDATE): a crash-restart can never compose the final output
// twice, and a re-entry over a terminal row is a no-op (idempotent). cipher
// may be nil (the last checkpoint already carries the composed output) or the
// sealed empty output when a terminal arrived with no data pages.
func (s *State) FinalizeHostedSourceFinal(ctx context.Context, instanceID, commandID, state, terminalJSON, reason string, cipher *e2ee.EncryptedPayloadV1) (bool, error) {
	switch state {
	case "complete", "failed", "unavailable":
	default:
		return false, ErrHostedSourceConflict
	}
	cipherJSON := []byte(nil)
	if cipher != nil {
		var err error
		cipherJSON, err = json.Marshal(*cipher)
		if err != nil {
			return false, err
		}
	}
	first := false
	err := s.hostedSourceFinalWrite(ctx, func(conn *sql.Conn) error {
		var stateNow string
		err := conn.QueryRowContext(ctx, `SELECT state FROM hosted_source_finals WHERE instance_id=? AND command_id=?`, instanceID, commandID).
			Scan(&stateNow)
		if err != nil {
			return err
		}
		if stateNow != "streaming" {
			return nil // already terminal: idempotent no-op
		}
		var res sql.Result
		if cipherJSON == nil {
			res, err = conn.ExecContext(ctx, `UPDATE hosted_source_finals SET state=?,terminal=?,reason=?,last_at=?
 WHERE instance_id=? AND command_id=? AND state='streaming'`,
				state, terminalJSON, reason, time.Now().UTC().UnixMilli(), instanceID, commandID)
		} else {
			res, err = conn.ExecContext(ctx, `UPDATE hosted_source_finals SET state=?,terminal=?,reason=?,ciphertext=?,last_at=?
 WHERE instance_id=? AND command_id=? AND state='streaming'`,
				state, terminalJSON, reason, cipherJSON, time.Now().UTC().UnixMilli(), instanceID, commandID)
		}
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		first = n == 1
		if !first {
			return ErrHostedSourceConflict
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return first, nil
}

func (s *State) hostedSourceFinalWrite(ctx context.Context, fn func(*sql.Conn) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(cleanup, `ROLLBACK`)
	}()
	if err = fn(conn); err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit hosted source final: %w", err)
	}
	return nil
}
