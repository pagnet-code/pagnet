package proc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ownershipRecord is the persisted process-ownership record (§39). It
// is the ONLY cross-restart memory of a live process tree: enough to
// prove ownership (never to guess it) after a hard crash.
type ownershipRecord struct {
	InstanceID string `json:"instance_id"`
	TurnID     string `json:"turn_id"`
	Runtime    string `json:"runtime"`
	PID        int    `json:"pid"`
	PGID       int    `json:"pgid"`
	// Identity is the platform start-time marker captured at launch
	// (Linux: /proc starttime ticks; Darwin: P_starttime). A reused PID
	// has a different identity — the record is then cleared, never
	// acted on (§39: PID REUSE EXISTS).
	Identity  string    `json:"identity"`
	StartedAt time.Time `json:"started_at"`
	PTY       bool      `json:"pty"`
	// Marker is the full ownership-marker env pair (PAGNET_TURN_ID=…)
	// for group-member proof when the leader is already gone (Linux).
	Marker string `json:"marker"`
}

func (s *Supervisor) recordDir() string {
	if s.cfg.StateDir == "" {
		return ""
	}
	return filepath.Join(s.cfg.StateDir, "proc-ownership")
}

func recordPath(dir string, t *managedTurn) string {
	// Instance/turn ids are daemon-validated UUIDs (or "pty"); sanitize
	// anyway — this path is built from data that must never escape the
	// state dir (SEC-407 discipline).
	safe := func(s string) string {
		return strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
				r == '-', r == '_':
				return r
			default:
				return '_'
			}
		}, s)
	}
	return filepath.Join(dir, safe(t.InstanceID)+"--"+safe(t.TurnID)+".json")
}

// writeRecord persists the ownership record DURABLY and ATOMICALLY:
// temp file in the SAME directory as the final path → write →
// fsync(file) → close → rename (same-directory rename is atomic) →
// fsync(directory, best-effort, like the keyring writer). A crash at any
// point leaves either the previous complete record or no record — never
// a torn file that Reconcile cannot parse (a torn record would strand
// the tree without ownership proof). os.CreateTemp uses 0600 (the record
// names pids of user-visible processes) regardless of umask.
//
// The post-Start launch site fails closed on the returned error (a
// process without a durable record is a process the supervisor cannot
// own after a crash, §39); there is no other call site.
//
// Note: the repo has no SHARED atomic-write helper — internal/runtime,
// internal/crypto, and internal/config each carry their own unexported
// copy (this follows that pattern; runtime cannot be imported here —
// it imports proc).
func (s *Supervisor) writeRecord(t *managedTurn) error {
	dir := s.recordDir()
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	rec := ownershipRecord{
		InstanceID: t.InstanceID,
		TurnID:     t.TurnID,
		Runtime:    t.Runtime,
		PID:        int(t.pid.Load()),
		PGID:       int(t.pgid.Load()),
		Identity:   t.identity,
		StartedAt:  t.startedAt,
		PTY:        t.Class == ClassPTY,
		Marker:     t.Marker,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".rec-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, recordPath(dir, t)); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	// Directory fsync (best-effort): persist the rename itself, so the
	// record survives a crash after the rename returns.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (s *Supervisor) removeRecord(t *managedTurn) {
	dir := s.recordDir()
	if dir == "" {
		return
	}
	_ = os.Remove(recordPath(dir, t))
}

// Reconcile handles stale ownership records left by a hard crash
// (§39). For each record:
//
//   - leader alive AND identity matches  → terminate the group (proven
//     ours);
//   - leader alive AND identity MISMATCH → PID reuse: NEVER kill,
//     clear/flag the record;
//   - leader gone, group alive, a member carries the ownership marker
//     (Linux) → terminate the group (proven by marker);
//   - leader gone, group alive, no proof  → leave the processes alone
//     (ownership unprovable), clear the record;
//   - leader gone, group gone            → clean, clear the record.
//
// It never kills on a bare PID and never kills by executable name
// (§56).
func (s *Supervisor) Reconcile() {
	dir := s.recordDir()
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.log.Warn("reconcile: cannot read ownership records", "err", err)
		}
		return
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var rec ownershipRecord
		if err := json.Unmarshal(b, &rec); err != nil || rec.PID <= 0 || rec.PGID <= 0 {
			_ = os.Remove(path) // unparseable: nothing to act on
			continue
		}
		s.reconcileRecord(rec)
		_ = os.Remove(path)
	}
}

func (s *Supervisor) reconcileRecord(rec ownershipRecord) {
	label := fmt.Sprintf("instance=%s turn=%s", rec.InstanceID, rec.TurnID)
	if ProcessAlive(rec.PID) {
		id, err := StartIdentity(rec.PID)
		if err != nil {
			// The process died between the liveness probe and the
			// identity read: ownership unprovable — do not kill.
			s.log.Warn("reconcile: leader vanished during verification; record cleared, no kill",
				"record", label, "pid", rec.PID)
			return
		}
		if rec.Identity != "" && id == rec.Identity {
			s.log.Warn("reconcile: terminating stale process group from previous run",
				"record", label, "pid", rec.PID, "pgid", rec.PGID)
			s.killGroup(rec.PGID, "restart_reconcile")
			s.orphanReconciled.Add(1)
			return
		}
		// PID reuse (or identity unreadable at launch): the live process
		// is NOT provably ours. Never kill it.
		s.log.Warn("reconcile: PID identity mismatch (possible reuse) — NOT killing",
			"record", label, "pid", rec.PID, "recorded", rec.Identity, "actual", id)
		return
	}
	// Leader gone: the group may still hold our descendants.
	if !GroupAlive(rec.PGID) {
		return // clean
	}
	if rec.Marker != "" {
		for _, pid := range GroupMembers(rec.PGID) {
			if ok, err := EnvHasMarker(pid, rec.Marker); err == nil && ok {
				s.log.Warn("reconcile: stale group proven by ownership marker — terminating",
					"record", label, "pgid", rec.PGID, "member", pid)
				s.killGroup(rec.PGID, "restart_reconcile")
				s.orphanReconciled.Add(1)
				return
			}
		}
	}
	s.log.Warn("reconcile: stale group survived without provable ownership — left running",
		"record", label, "pgid", rec.PGID)
}

// killGroup runs the TERM → grace → KILL sequence on a group from
// reconciliation (no managedTurn to publish to).
func (s *Supervisor) killGroup(pgid int, reason string) {
	if err := SignalGroup(pgid, syscall.SIGTERM); err != nil && !errors.Is(err, ErrGroupGone) {
		s.log.Warn("reconcile: group TERM failed", "pgid", pgid, "err", err)
	}
	select {
	case <-time.After(s.cfg.TermGrace):
		if err := SignalGroup(pgid, syscall.SIGKILL); err == nil {
			s.forceKillTotal.Add(1)
		} else if !errors.Is(err, ErrGroupGone) {
			s.log.Warn("reconcile: group KILL failed", "pgid", pgid, "err", err)
		}
	case <-s.reconcileGroupGone(pgid):
	}
}

// reconcileGroupGone polls until the group is empty (the reaper here is
// init/launchd — the crashed daemon's children were reparented).
func (s *Supervisor) reconcileGroupGone(pgid int) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		timeout := time.After(15 * time.Second)
		for {
			select {
			case <-timeout:
				return
			case <-ticker.C:
				if !GroupAlive(pgid) {
					return
				}
			}
		}
	}()
	return done
}
