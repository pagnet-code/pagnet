// Package sessionworker provides the private ownership boundary between a
// replaceable host controller and an independently owned native session.
// Production daemon routing remains conservative until the whole boundary is
// integrated; these primitives never authorize network access themselves.
package sessionworker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pagnet-code/pagnet/transport"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

const Protocol = "pagnet-session-worker-v1"
const maxCommands = 128
const maxOutcomeBytes = 64 << 10

var (
	ErrFenced     = errors.New("controller lease is no longer current")
	ErrConflict   = errors.New("intent sequence or digest conflicts with durable history")
	ErrRetired    = errors.New("intent is older than retained durable history")
	ErrNativeBusy = errors.New("original native turn is still in flight")
	ErrFull       = errors.New("unacknowledged worker outcomes reached the bounded limit")
)

// Scope is immutable for the lifetime of a worker. Generation identifies this
// durable ownership lifetime, not a native PID, controller connection, or bridge nonce.
type Scope struct {
	ServerURL  string `json:"serverUrl"`
	TenantID   string `json:"tenantId"`
	AccountID  string `json:"accountId"`
	HostID     string `json:"hostId"`
	InstanceID string `json:"instanceId"`
	Generation string `json:"generation"`
}

type Outcome struct {
	SourceAdmission *Admission      `json:"sourceAdmission,omitempty"`
	Sequence        int64           `json:"sequence"`
	CommandID       string          `json:"commandId"`
	Kind            string          `json:"kind"`
	State           string          `json:"state"` // admitted | completed | failed | uncertain
	Result          json.RawMessage `json:"result,omitempty"`
}

// Journal stores only intent digests and outcomes. Prompt bodies, arbitrary
// runtime environments, host credentials and native approval secrets are not
// written into this journal. Every admission is committed before native effect.
type Journal struct {
	sourceRetries        map[string]*nativeSourceRetry
	sourceProducers      map[*nativeSourceProducer]bool
	strictSourceProducer bool
	observationCapacity  chan struct{}
	mu                   sync.Mutex
	db                   *sql.DB
	scope                Scope
	owner                io.Closer
	dir                  string
}

func OpenJournal(dir string, scope Scope) (*Journal, error) {
	server, serverErr := url.Parse(scope.ServerURL)
	if serverErr != nil || (server.Scheme != "https" && server.Scheme != "http") || server.Host == "" || server.User != nil || server.RawQuery != "" || server.Fragment != "" || scope.TenantID == "" || len(scope.TenantID) > 256 || len(scope.ServerURL) > 2048 {
		return nil, errors.New("worker authority scope is incomplete")
	}
	if scope.AccountID == "" || scope.HostID == "" || scope.InstanceID == "" || scope.Generation == "" || len(scope.AccountID) > 256 || len(scope.HostID) > 256 || len(scope.InstanceID) > 256 || len(scope.Generation) > 256 {
		return nil, errors.New("worker scope is incomplete")
	}
	if err := privateDirectory(dir); err != nil {
		return nil, err
	}
	owner, err := acquireOwnership(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if owner != nil {
			_ = owner.Close()
		}
	}()
	path := filepath.Join(dir, "intents.sqlite")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		err = f.Close()
	} else if os.IsExist(err) {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return nil, statErr
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return nil, errors.New("worker journal is not a private regular file")
		}
		err = nil
	}
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path}).String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	j := &Journal{db: db, scope: scope, owner: owner, dir: dir, observationCapacity: make(chan struct{})}
	fail := func(e error) (*Journal, error) { _ = db.Close(); return nil, e }
	for _, q := range []string{
		"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=5000",
		`CREATE TABLE IF NOT EXISTS worker_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), protocol TEXT NOT NULL, scope TEXT NOT NULL, lease INTEGER NOT NULL, next_sequence INTEGER NOT NULL, retired INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS worker_intent_admission(sequence INTEGER PRIMARY KEY, admission BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS worker_intent(sequence INTEGER PRIMARY KEY, command_id TEXT NOT NULL UNIQUE, digest TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, result BLOB, acknowledged INTEGER NOT NULL DEFAULT 0)`,
	} {
		if _, err = db.Exec(q); err != nil {
			return fail(err)
		}
	}
	encoded, _ := json.Marshal(scope)
	if _, err = db.Exec(`INSERT OR IGNORE INTO worker_meta VALUES(1,?,?,0,1,0)`, Protocol, string(encoded)); err != nil {
		return fail(err)
	}
	var protocol, stored string
	if err = db.QueryRow(`SELECT protocol,scope FROM worker_meta WHERE singleton=1`).Scan(&protocol, &stored); err != nil {
		return fail(err)
	}
	if protocol != Protocol || stored != string(encoded) {
		return fail(errors.New("worker journal scope or protocol mismatch"))
	}
	if err = j.initializeObservations(); err != nil {
		return fail(err)
	}
	if err = j.initializeSourceSequences(); err != nil {
		return fail(err)
	}
	if err = j.initializeCaptures(); err != nil {
		return fail(err)
	}
	if err = j.initializeContentTransfers(); err != nil {
		return fail(err)
	}
	if err = j.initializeTurnSources(); err != nil {
		return fail(err)
	}
	if err = j.initializeDispatches(); err != nil {
		return fail(err)
	}
	if err = j.validateHistory(); err != nil {
		return fail(err)
	}
	// No native mutation is repeated after a worker crash. Its completed outcome
	// may have been lost after the effect but before fsync; report that uncertainty.
	if _, err = db.Exec(`UPDATE worker_intent SET state='uncertain' WHERE state='admitted'`); err != nil {
		return fail(err)
	}
	if err = j.initializeSourceRetirement(); err != nil {
		return fail(err)
	}
	owner = nil // journal owns the lifetime lock after successful initialization
	return j, nil
}

func privateDirectory(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("worker state directory must be absolute")
	}
	// Refuse symlink components rather than allowing a private-looking leaf to
	// redirect session state into a different owner or shared location.
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("worker state path contains a symlink")
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("worker state directory must be private (0700)")
	}
	return nil
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.Close()
	lockErr := j.owner.Close()
	if err != nil {
		return err
	}
	return lockErr
}

// AdvanceLease is called only after mutual private IPC authentication. The
// durable monotonic value fences every previous controller even across crashes.
func (j *Journal) AdvanceLease(ctx context.Context) (int64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var lease int64
	err := j.db.QueryRowContext(ctx, `UPDATE worker_meta SET lease=lease+1 WHERE singleton=1 AND lease<9223372036854775807 RETURNING lease`).Scan(&lease)
	return lease, err
}

func checkLease(ctx context.Context, tx *sql.Tx, lease int64) (int64, int64, error) {
	var current, next, retired int64
	if err := tx.QueryRowContext(ctx, `SELECT lease,next_sequence,retired FROM worker_meta WHERE singleton=1`).Scan(&current, &next, &retired); err != nil {
		return 0, 0, err
	}
	if lease <= 0 || current != lease {
		return 0, 0, ErrFenced
	}
	return next, retired, nil
}

func intentDigest(kind string, payload json.RawMessage) string {
	// Length-prefixed canonical wrapper prevents kind/body boundary ambiguity.
	b, _ := json.Marshal(struct {
		Kind    string
		Payload json.RawMessage
	}{kind, payload})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Admit returns execute=false for a known intent, including unfinished or
// uncertain outcomes. A retry must retain its original ordinal and command ID.
func (j *Journal) Admit(ctx context.Context, lease, sequence int64, commandID, kind string, payload json.RawMessage) (out Outcome, execute bool, err error) {
	return j.admit(ctx, lease, sequence, commandID, kind, payload, nil)
}

// Only new effects need admission. Exact prior ordinal replay is read-only.
func (j *Journal) admit(ctx context.Context, lease, sequence int64, commandID, kind string, payload json.RawMessage, authorizeNew func() (*Admission, error)) (out Outcome, execute bool, err error) {
	return j.admitDispatch(ctx, lease, sequence, commandID, kind, payload, authorizeNew, nil)
}

func (j *Journal) admitDispatch(ctx context.Context, lease, sequence int64, commandID, kind string, payload json.RawMessage, authorizeNew func() (*Admission, error), dispatch *transport.NativeDispatchProof) (out Outcome, execute bool, err error) {
	if (sequence <= 0 && dispatch == nil) || commandID == "" || len(commandID) > 256 || kind == "" || len(kind) > 64 || len(payload) > 1<<20 || !json.Valid(payload) {
		return out, false, errors.New("invalid or oversized intent")
	}
	digest := intentDigest(kind, payload)
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return out, false, err
	}
	defer tx.Rollback()
	next, retired, err := checkLease(ctx, tx, lease)
	if err != nil {
		return out, false, err
	}
	var newDispatch bool
	if dispatch != nil {
		if sequence, newDispatch, err = j.prepareDispatchTx(ctx, tx, next, sequence, commandID, *dispatch); err != nil {
			return out, false, err
		}
	} else if kind == "activate" || kind == "prompt" {
		var bound int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_dispatch_meta`).Scan(&bound); err != nil {
			return out, false, err
		}
		if bound != 0 {
			return out, false, ErrConflict
		}
	}
	if sequence <= retired {
		return out, false, ErrRetired
	}
	var oldDigest string
	var rawResult []byte
	err = tx.QueryRowContext(ctx, `SELECT sequence,command_id,kind,state,result,digest FROM worker_intent WHERE sequence=?`, sequence).Scan(&out.Sequence, &out.CommandID, &out.Kind, &out.State, &rawResult, &oldDigest)
	if err == nil {
		out.Result = json.RawMessage(rawResult)
		if out.CommandID != commandID || out.Kind != kind || oldDigest != digest {
			return out, false, ErrConflict
		}
		var source []byte
		if readErr := tx.QueryRowContext(ctx, `SELECT admission FROM worker_intent_admission WHERE sequence=?`, sequence).Scan(&source); readErr != nil && !errors.Is(readErr, sql.ErrNoRows) {
			return out, false, readErr
		}
		if len(source) > 0 {
			if err = json.Unmarshal(source, &out.SourceAdmission); err != nil {
				return out, false, err
			}
		}
		return out, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, false, err
	}
	if sequence != next || sequence == 9223372036854775807 {
		return out, false, ErrConflict
	}
	if dispatch != nil && (kind == "prompt" || kind == "activate") {
		var active int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_intent WHERE state='admitted' AND kind IN ('prompt','activate')`).Scan(&active); err != nil {
			return out, false, err
		}
		if active > 0 {
			return out, false, ErrNativeBusy
		}
	}
	if authorizeNew != nil {
		if out.SourceAdmission, err = authorizeNew(); err != nil {
			return out, false, err
		}
	}
	if dispatch != nil {
		if !newDispatch || out.SourceAdmission == nil || out.SourceAdmission.Scope != j.scope {
			return out, false, ErrConflict
		}
		original := *out.SourceAdmission
		original.NativeAdmissionID = dispatch.SourceAdmissionID
		original.RunnerID = dispatch.SourceRunnerID
		original.RunnerEpoch = dispatch.SourceRunnerEpoch
		original.BootID = dispatch.SourceBootID
		out.SourceAdmission = &original
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_intent`).Scan(&count); err != nil {
		return out, false, err
	}
	if count >= maxCommands {
		return out, false, ErrFull
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_intent(sequence,command_id,digest,kind,state) VALUES(?,?,?,?,'admitted')`, sequence, commandID, digest, kind); err != nil {
		return out, false, fmt.Errorf("intent identity conflict: %w", err)
	}
	if out.SourceAdmission != nil {
		source, marshalErr := json.Marshal(out.SourceAdmission)
		if marshalErr != nil {
			return out, false, marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO worker_intent_admission(sequence,admission) VALUES(?,?)`, sequence, source); err != nil {
			return out, false, err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE worker_meta SET next_sequence=? WHERE singleton=1`, sequence+1); err != nil {
		return out, false, err
	}
	if err = tx.Commit(); err != nil {
		return out, false, err
	}
	return Outcome{Sequence: sequence, CommandID: commandID, Kind: kind, State: "admitted", SourceAdmission: out.SourceAdmission}, true, nil
}

// Settle does not require the original controller lease: an already admitted
// native turn remains worker-owned and can finish after controller replacement.
func (j *Journal) Settle(ctx context.Context, sequence int64, state string, result json.RawMessage) error {
	if state != "completed" && state != "failed" && state != "uncertain" {
		return errors.New("invalid terminal outcome")
	}
	if len(result) > maxOutcomeBytes || (len(result) > 0 && !json.Valid(result)) {
		return errors.New("invalid or oversized outcome")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	res, err := j.db.ExecContext(ctx, `UPDATE worker_intent SET state=?,result=? WHERE sequence=? AND state='admitted'`, state, []byte(result), sequence)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

func (j *Journal) Outcome(ctx context.Context, sequence int64) (out Outcome, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var rawResult []byte
	err = j.db.QueryRowContext(ctx, `SELECT sequence,command_id,kind,state,result FROM worker_intent WHERE sequence=?`, sequence).Scan(&out.Sequence, &out.CommandID, &out.Kind, &out.State, &rawResult)
	out.Result = json.RawMessage(rawResult)
	if err != nil {
		return
	}
	var source []byte
	err = j.db.QueryRowContext(ctx, `SELECT admission FROM worker_intent_admission WHERE sequence=?`, sequence).Scan(&source)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
		return
	}
	if err == nil {
		err = json.Unmarshal(source, &out.SourceAdmission)
	}
	return
}

// Acknowledge is a durable receipt from the current controller, sent only
// after that controller has durably stored/projected the outcome. Pruning is
// contiguous and cannot make an old uncertain input look like new work.
func (j *Journal) Acknowledge(ctx context.Context, lease, sequence int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, floor, err := checkLease(ctx, tx, lease)
	if err != nil {
		return err
	}
	if sequence <= floor {
		return tx.Commit()
	}
	res, err := tx.ExecContext(ctx, `UPDATE worker_intent SET acknowledged=1 WHERE sequence=? AND state!='admitted'`, sequence)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	for {
		var ack int
		err = tx.QueryRowContext(ctx, `SELECT acknowledged FROM worker_intent WHERE sequence=?`, floor+1).Scan(&ack)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && ack != 1) {
			break
		}
		if err != nil {
			return err
		}
		floor++
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_intent_admission WHERE sequence<=?`, floor); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_intent WHERE sequence<=?`, floor); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE worker_meta SET retired=? WHERE singleton=1`, floor); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return j.reclaimSourceStreamsLocked(ctx)
}

// validateHistory refuses partial/mixed journal generations. A valid SQLite
// file with a lost intent or invalid cursor is still unsafe replay history.
func (j *Journal) validateHistory() error {
	var integrity string
	if err := j.db.QueryRow(`PRAGMA quick_check`).Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return errors.New("worker journal integrity check failed")
	}
	var lease, next, retired, count int64
	if err := j.db.QueryRow(`SELECT lease,next_sequence,retired,(SELECT COUNT(*) FROM worker_intent) FROM worker_meta WHERE singleton=1`).Scan(&lease, &next, &retired, &count); err != nil {
		return err
	}
	if lease < 0 || next < 1 || retired < 0 || retired >= next || count < 0 || count > maxCommands || next-retired-1 != count {
		return errors.New("worker journal sequence history is incomplete")
	}
	rows, err := j.db.Query(`SELECT sequence,command_id,digest,kind,state,result,acknowledged FROM worker_intent ORDER BY sequence`)
	if err != nil {
		return err
	}
	defer rows.Close()
	expected := retired + 1
	for rows.Next() {
		var sequence, ack int64
		var id, digest, kind, state string
		var result []byte
		if err := rows.Scan(&sequence, &id, &digest, &kind, &state, &result, &ack); err != nil {
			return err
		}
		_, digestErr := hex.DecodeString(digest)
		validState := state == "admitted" || state == "completed" || state == "failed" || state == "uncertain"
		if sequence != expected || id == "" || len(id) > 256 || kind == "" || len(kind) > 64 || len(digest) != 64 || digestErr != nil || !validState || len(result) > maxOutcomeBytes || (len(result) > 0 && !json.Valid(result)) || (ack != 0 && ack != 1) || (state == "admitted" && (ack != 0 || len(result) > 0)) {
			return errors.New("worker journal contains an invalid intent")
		}
		expected++
	}
	return rows.Err()
}

func (j *Journal) CurrentLease(ctx context.Context, lease int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var current int64
	if err := j.db.QueryRowContext(ctx, `SELECT lease FROM worker_meta WHERE singleton=1`).Scan(&current); err != nil {
		return err
	}
	if lease <= 0 || lease != current {
		return ErrFenced
	}
	return nil
}
