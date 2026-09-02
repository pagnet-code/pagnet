// Package daemon implements agentnetd: the outbound host daemon. It keeps a
// single WSS to the control plane (one per host, all agents multiplexed),
// reports heartbeats and inventory, executes structured commands
// idempotently (SQLite-remembered CommandIDs), and runs runtime adapters.
package daemon

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// State is the daemon's local persistent state (SQLite). It survives daemon
// restarts so commands are processed at-most-once even if the server
// re-sends them before seeing the ack.
type State struct {
	db *sql.DB
}

// OpenState opens (and migrates) the daemon state database at path.
func OpenState(path string) (*State, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open state: %w", err)
	}
	if _, err := db.Exec(`
		PRAGMA journal_mode = WAL;
		CREATE TABLE IF NOT EXISTS processed_commands (
			command_id   TEXT PRIMARY KEY,
			type         TEXT NOT NULL,
			processed_at TEXT NOT NULL
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
			network_id    TEXT NOT NULL DEFAULT ''
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
		`ALTER TABLE instances ADD COLUMN access TEXT NOT NULL DEFAULT 'read_write'`,
		`ALTER TABLE instances ADD COLUMN agent_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE instances ADD COLUMN network_id TEXT NOT NULL DEFAULT ''`,
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

// MarkProcessed records command execution (idempotent).
func (s *State) MarkProcessed(commandID, msgType string) error {
	_, err := s.db.Exec(`
		INSERT INTO processed_commands (command_id, type, processed_at)
		VALUES (?, ?, ?)
		ON CONFLICT (command_id) DO NOTHING`,
		commandID, msgType, time.Now().UTC().Format(time.RFC3339))
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
}

// UpsertInstance records/updates a local instance.
func (s *State) UpsertInstance(r InstanceRow) error {
	if r.UpdatedAt == "" {
		r.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := s.db.Exec(`
		INSERT INTO instances (instance_id, definition_id, runtime, workspace, profile, status, session_id, pid, updated_at, access, agent_name, network_id)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
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
			network_id = excluded.network_id`,
		r.InstanceID, r.DefinitionID, r.Runtime, r.Workspace, r.Profile, r.Status, r.SessionID, r.PID, r.UpdatedAt,
		r.Access, r.AgentName, r.NetworkID)
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

// SetInstanceSession explicitly sets the local session id; "" clears it
// (cold start after a restart or a lost session).
func (s *State) SetInstanceSession(instanceID, sessionID string) error {
	_, err := s.db.Exec(`
		UPDATE instances SET session_id=?, updated_at=? WHERE instance_id=?`,
		sessionID, time.Now().UTC().Format(time.RFC3339), instanceID)
	return err
}

// GetInstance fetches a local instance row.
func (s *State) GetInstance(instanceID string) (*InstanceRow, bool, error) {
	row := s.db.QueryRow(`
		SELECT instance_id, definition_id, runtime, workspace, profile, status,
		       COALESCE(session_id,''), pid, updated_at,
		       COALESCE(access,'read_write'), COALESCE(agent_name,''), COALESCE(network_id,'')
		FROM instances WHERE instance_id = ?`, instanceID)
	var r InstanceRow
	var pid sql.NullInt64
	err := row.Scan(&r.InstanceID, &r.DefinitionID, &r.Runtime, &r.Workspace, &r.Profile,
		&r.Status, &r.SessionID, &pid, &r.UpdatedAt, &r.Access, &r.AgentName, &r.NetworkID)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if pid.Valid {
		v := int(pid.Int64)
		r.PID = &v
	}
	return &r, true, nil
}

// ListInstances returns all locally known instances.
func (s *State) ListInstances() ([]InstanceRow, error) {
	rows, err := s.db.Query(`
		SELECT instance_id, definition_id, runtime, workspace, profile, status,
		       COALESCE(session_id,''), pid, updated_at,
		       COALESCE(access,'read_write'), COALESCE(agent_name,''), COALESCE(network_id,'')
		FROM instances ORDER BY instance_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InstanceRow
	for rows.Next() {
		var r InstanceRow
		var pid sql.NullInt64
		if err := rows.Scan(&r.InstanceID, &r.DefinitionID, &r.Runtime, &r.Workspace,
			&r.Profile, &r.Status, &r.SessionID, &pid, &r.UpdatedAt,
			&r.Access, &r.AgentName, &r.NetworkID); err != nil {
			return nil, err
		}
		if pid.Valid {
			v := int(pid.Int64)
			r.PID = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
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
