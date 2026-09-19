// Package daemon implements the outbound host daemon. It keeps a
// single WSS to the control plane (one per host, all agents multiplexed),
// reports heartbeats and inventory, executes structured commands
// idempotently (SQLite-remembered CommandIDs), and runs runtime adapters.
package daemon

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/pagnet-code/pagnet/domain"
)

// State is the daemon's local persistent state (SQLite). It survives daemon
// restarts so commands are processed at-most-once even if the server
// re-sends them before seeing the ack.
type State struct {
	db *sql.DB
}

// OpenState opens (and migrates) the daemon state database at path.
func OpenState(path string) (*State, error) {
	// _busy_timeout: a prior daemon instance (or a test) may still hold a
	// write when this one opens; retry up to 5s instead of failing with
	// SQLITE_BUSY (Phase 12 hardening). Applied at connection-open, before
	// the migration below.
	db, err := sql.Open("sqlite", path+"?_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open state: %w", err)
	}
	if _, err := db.Exec(`
		PRAGMA journal_mode = WAL;
		CREATE TABLE IF NOT EXISTS processed_commands (
			command_id   TEXT PRIMARY KEY,
			type         TEXT NOT NULL,
			processed_at TEXT NOT NULL,
			result       TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS instances (
			instance_id   TEXT PRIMARY KEY,
			definition_id TEXT NOT NULL,
			runtime       TEXT NOT NULL,
			workspace     TEXT NOT NULL DEFAULT '',
			profile       TEXT NOT NULL DEFAULT '',
			status        TEXT NOT NULL DEFAULT 'starting',
			session_id    TEXT NOT NULL DEFAULT '',
			pid           INTEGER,
			updated_at    TEXT NOT NULL,
			access        TEXT NOT NULL DEFAULT 'read_write',
			agent_name    TEXT NOT NULL DEFAULT '',
			network_id    TEXT NOT NULL DEFAULT '',
			kind          TEXT NOT NULL DEFAULT 'worker',
			model         TEXT NOT NULL DEFAULT '',
			instruction   TEXT NOT NULL DEFAULT '',
			agent_md_path TEXT NOT NULL DEFAULT '',
			config_fingerprint TEXT NOT NULL DEFAULT '',
			agent_principal_id TEXT NOT NULL DEFAULT '',
			capabilities TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS kv (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate state: %w", err)
	}
	// Best-effort ALTERs for state dirs created before these columns
	// existed (a fresh CREATE TABLE already has them).
	for _, col := range []string{
		`ALTER TABLE processed_commands ADD COLUMN result TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE instances ADD COLUMN access TEXT NOT NULL DEFAULT 'read_write'`,
		`ALTER TABLE instances ADD COLUMN agent_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE instances ADD COLUMN network_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE instances ADD COLUMN kind TEXT NOT NULL DEFAULT 'worker'`,
		`ALTER TABLE instances ADD COLUMN model TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE instances ADD COLUMN instruction TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE instances ADD COLUMN agent_md_path TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE instances ADD COLUMN config_fingerprint TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE instances ADD COLUMN agent_principal_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE instances ADD COLUMN capabilities TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := db.Exec(col); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("migrate state: %w", err)
		}
	}
	return &State{db: db}, nil
}

func (s *State) Close() error { return s.db.Close() }

// IsProcessed reports whether a CommandID was already executed.
func (s *State) IsProcessed(commandID string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM processed_commands WHERE command_id = ?`, commandID).Scan(&n)
	return n > 0, err
}

// GetProcessedResult returns the ack result that was persisted when
// commandID was executed ("" when the command carried no result, e.g. a
// non-crypto command). ok is false when the command was never processed.
// The result is the verbatim JSON the daemon acked, so a re-send of an
// already-processed command re-acks the SAME result (F8: a lost ack + server
// re-send must not yield a zero-value result that the server misreads).
func (s *State) GetProcessedResult(commandID string) (string, bool) {
	var result string
	err := s.db.QueryRow(`SELECT result FROM processed_commands WHERE command_id = ?`, commandID).Scan(&result)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		return "", false
	}
	return result, true
}

// MarkProcessed records command execution (idempotent), persisting the ack
// result (JSON, "" when the command carries none) so a re-send of the command
// can re-ack the stored result verbatim.
func (s *State) MarkProcessed(commandID, msgType string, result []byte) error {
	_, err := s.db.Exec(`
		INSERT INTO processed_commands (command_id, type, processed_at, result)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (command_id) DO NOTHING`,
		commandID, msgType, time.Now().UTC().Format(time.RFC3339), string(result))
	return err
}

// PruneProcessed drops processed-command rows older than before (spec §91:
// keep the dedup set only for a bounded period). RFC3339 UTC strings sort
// chronologically, so a string comparison is safe.
func (s *State) PruneProcessed(before time.Time) error {
	_, err := s.db.Exec(
		`DELETE FROM processed_commands WHERE processed_at < ?`,
		before.UTC().Format(time.RFC3339))
	return err
}

// InstanceRow is the daemon's local view of a managed instance.
type InstanceRow struct {
	InstanceID   string
	DefinitionID string
	Runtime      string
	Workspace    string
	Profile      string
	Status       string
	SessionID    string
	PID          *int
	UpdatedAt    string
	Access       string // read_write (default) | read_only (§29)
	AgentName    string
	NetworkID    string
	Kind         string // worker (default) | representative
	// Model is the resolved model for this instance (launch request >
	// definition default; "" = the runtime's own default).
	Model string
	// Instruction is the standing instruction (AGENT.md-style) for this
	// instance ("" = none).
	Instruction string
	// AgentMDPath is the daemon-state-dir file holding Instruction ("" =
	// none); claude points --append-system-prompt-file at it.
	AgentMDPath string
	// ConfigFingerprint is the fingerprint of the runtime-injected config
	// (MCP bridge + identity env + daemon version, P6 configStale) that
	// the instance's last PTY was started with. "" = the instance never
	// had a PTY (never stale).
	ConfigFingerprint string
	// AgentPrincipalID is the agent principal this instance runs (V2,
	// from the launch command): the daemon reports it in every
	// host.endpoint_status and resolves the instance's network
	// operations against it (bridge relay).
	AgentPrincipalID string
	// Capabilities is the instance's self-declared capability set (V2):
	// what the agent declared through network_register_capabilities
	// (version 1). The daemon carries it in host.endpoint_status so the
	// control plane can upsert endpoint_capabilities. Nil = none declared.
	Capabilities []domain.Capability
}

// UpsertInstance records/updates a local instance.
func (s *State) UpsertInstance(r InstanceRow) error {
	if r.UpdatedAt == "" {
		r.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	caps := ""
	if len(r.Capabilities) > 0 {
		if b, err := json.Marshal(r.Capabilities); err == nil {
			caps = string(b)
		}
	}
	_, err := s.db.Exec(`
		INSERT INTO instances (instance_id, definition_id, runtime, workspace, profile, status, session_id, pid, updated_at, access, agent_name, network_id, kind, model, instruction, agent_md_path, config_fingerprint, agent_principal_id, capabilities)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (instance_id) DO UPDATE SET
			definition_id = excluded.definition_id,
			runtime = excluded.runtime,
			workspace = excluded.workspace,
			profile = excluded.profile,
			status = excluded.status,
			session_id = excluded.session_id,
			pid = excluded.pid,
			updated_at = excluded.updated_at,
			access = excluded.access,
			agent_name = excluded.agent_name,
			network_id = excluded.network_id,
			kind = excluded.kind,
			model = excluded.model,
			instruction = excluded.instruction,
			agent_md_path = excluded.agent_md_path,
			config_fingerprint = excluded.config_fingerprint,
			agent_principal_id = excluded.agent_principal_id,
			capabilities = excluded.capabilities`,
		r.InstanceID, r.DefinitionID, r.Runtime, r.Workspace, r.Profile, r.Status, r.SessionID, r.PID, r.UpdatedAt,
		r.Access, r.AgentName, r.NetworkID, r.Kind, r.Model, r.Instruction, r.AgentMDPath, r.ConfigFingerprint,
		r.AgentPrincipalID, caps)
	return err
}

// SetInstanceStatus patches the local status (and optionally session).
func (s *State) SetInstanceStatus(instanceID, status, sessionID string) error {
	if sessionID != "" {
		_, err := s.db.Exec(`
			UPDATE instances SET status=?, session_id=?, updated_at=? WHERE instance_id=?`,
			status, sessionID, time.Now().UTC().Format(time.RFC3339), instanceID)
		return err
	}
	_, err := s.db.Exec(`
		UPDATE instances SET status=?, updated_at=? WHERE instance_id=?`,
		status, time.Now().UTC().Format(time.RFC3339), instanceID)
	return err
}

// SetInstanceCapabilities updates ONLY the instance's self-declared
// capability set (the agent's network_register_capabilities declaration,
// version 1), leaving every other column (status, session, principal, ...)
// untouched. A full UpsertInstance here would clobber concurrent status
// writes (the row the bridge holds was loaded at auth time), so this is a
// targeted single-column update.
func (s *State) SetInstanceCapabilities(instanceID string, caps []domain.Capability) error {
	capsJSON := ""
	if len(caps) > 0 {
		if b, err := json.Marshal(caps); err == nil {
			capsJSON = string(b)
		}
	}
	_, err := s.db.Exec(`
		UPDATE instances SET capabilities = ?, updated_at = ?
		WHERE instance_id = ?`,
		capsJSON, time.Now().UTC().Format(time.RFC3339), instanceID)
	return err
}

// SetInstanceSession explicitly sets the local session id; "" clears it
// (cold start after a restart or a lost session).
func (s *State) SetInstanceSession(instanceID, sessionID string) error {
	_, err := s.db.Exec(`
		UPDATE instances SET session_id=?, updated_at=? WHERE instance_id=?`,
		sessionID, time.Now().UTC().Format(time.RFC3339), instanceID)
	return err
}

// SetInstanceConfigFingerprint records the runtime-injected-config
// fingerprint (P6 configStale) the instance's PTY was (re)started with.
func (s *State) SetInstanceConfigFingerprint(instanceID, fingerprint string) error {
	_, err := s.db.Exec(`
		UPDATE instances SET config_fingerprint=?, updated_at=? WHERE instance_id=?`,
		fingerprint, time.Now().UTC().Format(time.RFC3339), instanceID)
	return err
}

// instanceSelectCols is the shared column list of GetInstance /
// ListInstances (the new V2 columns default to empty on old rows).
const instanceSelectCols = `
		SELECT instance_id, definition_id, runtime, workspace, profile, status,
		       COALESCE(session_id,''), pid, updated_at,
		       COALESCE(access,'read_write'), COALESCE(agent_name,''), COALESCE(network_id,''),
		       COALESCE(kind,'worker'), COALESCE(model,''), COALESCE(instruction,''), COALESCE(agent_md_path,''),
		       COALESCE(config_fingerprint,''), COALESCE(agent_principal_id,''), COALESCE(capabilities,'')`

// scanInstanceRow scans one instance row (instanceSelectCols order).
func scanInstanceRow(row interface {
	Scan(dest ...any) error
}, r *InstanceRow) error {
	var pid sql.NullInt64
	var capsJSON string
	if err := row.Scan(&r.InstanceID, &r.DefinitionID, &r.Runtime, &r.Workspace, &r.Profile,
		&r.Status, &r.SessionID, &pid, &r.UpdatedAt, &r.Access, &r.AgentName, &r.NetworkID, &r.Kind,
		&r.Model, &r.Instruction, &r.AgentMDPath, &r.ConfigFingerprint, &r.AgentPrincipalID, &capsJSON); err != nil {
		return err
	}
	if pid.Valid {
		v := int(pid.Int64)
		r.PID = &v
	}
	if capsJSON != "" {
		var caps []domain.Capability
		if err := json.Unmarshal([]byte(capsJSON), &caps); err == nil {
			r.Capabilities = caps
		}
	}
	return nil
}

// GetInstance fetches a local instance row.
func (s *State) GetInstance(instanceID string) (*InstanceRow, bool, error) {
	row := s.db.QueryRow(instanceSelectCols+`
		FROM instances WHERE instance_id = ?`, instanceID)
	var r InstanceRow
	if err := scanInstanceRow(row, &r); err == sql.ErrNoRows {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	return &r, true, nil
}

// ListInstances returns all locally known instances.
func (s *State) ListInstances() ([]InstanceRow, error) {
	rows, err := s.db.Query(instanceSelectCols + ` FROM instances ORDER BY instance_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InstanceRow
	for rows.Next() {
		var r InstanceRow
		if err := scanInstanceRow(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteInstance drops a local instance row (forget command: the
// control plane deleted the instance).
func (s *State) DeleteInstance(instanceID string) error {
	_, err := s.db.Exec(`DELETE FROM instances WHERE instance_id = ?`, instanceID)
	return err
}

// ReconcileRestart fixes local statuses that a dead process left behind:
// a process-per-turn turn cannot survive a daemon restart, so 'working'
// at startup is stale. Rows keep their session (resumable) and become
// hibernated, or idle when they never had one. The control plane re-sends
// the un-acked command, which re-wakes the instance and re-runs the turn.
func (s *State) ReconcileRestart() (int64, error) {
	res, err := s.db.Exec(`
		UPDATE instances
		SET status = CASE WHEN COALESCE(session_id, '') <> '' THEN 'hibernated' ELSE 'idle' END,
		    updated_at = ?
		WHERE status = 'working'`,
		time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// KVGet / KVSet are a small persistent key-value store (e.g. last host id).
func (s *State) KVGet(key string) (string, bool) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM kv WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		return "", false
	}
	return v, true
}

func (s *State) KVSet(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO kv (key, value) VALUES (?,?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// NetworkCryptoKVKey is the KV key under which the daemon persists the
// server-announced E2EE lifecycle state for a network (host.network_crypto,
// plan §12 / D6). Persisting it (in addition to the in-memory cache) is what
// lets the CLI reuse the host's crypto path for client-side encryption
// (pagnet invoke / event publish): the CLI reads the announced status +
// epoch + tenant id and the network keyring from the same state dir.
func NetworkCryptoKVKey(networkID string) string { return "netcrypto:" + networkID }

// SaveNetworkCrypto persists the announced E2EE lifecycle state for a
// network (idempotent — a re-push overwrites). The row's shape is
// NetworkCryptoState's JSON tags (the CLI reads it back).
func (s *State) SaveNetworkCrypto(networkID string, st NetworkCryptoState) error {
	st.NetworkID = networkID
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.KVSet(NetworkCryptoKVKey(networkID), string(b))
}

// LoadNetworkCrypto returns the persisted announced E2EE lifecycle state
// for a network (ok=false when the daemon has never received one for it).
func (s *State) LoadNetworkCrypto(networkID string) (NetworkCryptoState, bool) {
	v, ok := s.KVGet(NetworkCryptoKVKey(networkID))
	if !ok {
		return NetworkCryptoState{}, false
	}
	var st NetworkCryptoState
	if err := json.Unmarshal([]byte(v), &st); err != nil {
		return NetworkCryptoState{}, false
	}
	st.NetworkID = networkID
	return st, true
}
