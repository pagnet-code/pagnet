//go:build linux || darwin

package sessionworker

import (
	"errors"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/internal/session"
)

func TestDirectSubmissionAtomicClaimAndRecovery(t *testing.T) {
	o, l, s, wire, snap, now := directASKFixture(t)
	if _, err := o.directASK(t.Context(), &directASKController{owner: o, lease: l}, s, wire, true, now, func() NativeSnapshot { return snap }); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for range 12 {
		wg.Go(func() {
			status, started, err := o.beginDirectASKSubmissionAt(t.Context(), l, s, wire, now, func() NativeSnapshot { return snap })
			if err != nil || status == nil || status.State != "submitted" {
				t.Errorf("claim status: %v %v", status, err)
			}
			if started {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("winners: %d", winners)
	}
	event := session.SessionEvent{TurnID: logicalDirectTurn(s.AdmissionID), SessionID: s.NativeSessionID, Type: session.EventTurnStarted}
	source, unavailable, err := o.journal.NativeEventSource(t.Context(), s.NativeGeneration, event)
	if err != nil || unavailable || source == nil || !validDirectTurn(*source) {
		t.Fatalf("source: %v %v %v", source, unavailable, err)
	}
	if NativeSourceType(NativeObservation{TurnSource: source, Event: event}) != "" {
		t.Fatal("direct source entered Cloud delivery")
	}
	var intents, dispatches, next, reserves int
	if err = o.journal.db.QueryRow(`SELECT (SELECT COUNT(*) FROM worker_intent),(SELECT COUNT(*) FROM worker_dispatches),next_sequence,(SELECT COUNT(*) FROM worker_direct_terminal_reservations) FROM worker_meta`).Scan(&intents, &dispatches, &next, &reserves); err != nil || intents != 0 || dispatches != 0 || next != 1 || reserves != 1 {
		t.Fatalf("Cloud state: %d %d %d %d %v", intents, dispatches, next, reserves, err)
	}
	dir := o.journal.dir
	if err = o.journal.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir, s.Scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	o.journal = j
	status, started, err := o.beginDirectASKSubmissionAt(t.Context(), lease(t, j), s, wire, now, func() NativeSnapshot { return snap })
	if err != nil || started || status == nil || status.State != "unknown" {
		t.Fatalf("recovery: %v %v %v", status, started, err)
	}
}

func TestDirectSubmissionRollback(t *testing.T) {
	for _, failure := range []string{"capacity", "persistence"} {
		t.Run(failure, func(t *testing.T) {
			o, l, s, wire, snap, now := directASKFixture(t)
			if _, err := o.directASK(t.Context(), &directASKController{owner: o, lease: l}, s, wire, true, now, func() NativeSnapshot { return snap }); err != nil {
				t.Fatal(err)
			}
			if failure == "capacity" {
				if _, err := o.journal.db.Exec(`INSERT INTO worker_terminal_reservations(sequence,rows_left,capture_left,content_left) VALUES(1,384,44040192,67108864),(2,384,44040192,67108864),(3,384,44040192,67108864)`); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := o.journal.db.Exec(`CREATE TRIGGER fail_direct BEFORE UPDATE ON worker_direct_admissions BEGIN SELECT RAISE(ABORT,'test persistence'); END`); err != nil {
					t.Fatal(err)
				}
			}
			_, started, err := o.beginDirectASKSubmissionAt(t.Context(), l, s, wire, now, func() NativeSnapshot { return snap })
			if err == nil || started {
				t.Fatal("failed transaction authorized submission")
			}
			if failure == "capacity" && !errors.Is(err, ErrFull) {
				t.Fatal(err)
			}
			var state string
			var turns, reserves int
			if err = o.journal.db.QueryRow(`SELECT state,(SELECT COUNT(*) FROM worker_direct_turn_sources),(SELECT COUNT(*) FROM worker_direct_terminal_reservations) FROM worker_direct_admissions`).Scan(&state, &turns, &reserves); err != nil || state != "reserved" || turns != 0 || reserves != 0 {
				t.Fatalf("partial transaction: %s %d %d %v", state, turns, reserves, err)
			}
		})
	}
}

func TestDirectSubmissionHistoryValidation(t *testing.T) {
	for name, query := range map[string]string{
		"orphan-reservation":  `DELETE FROM worker_direct_turn_sources`,
		"missing-reservation": `DELETE FROM worker_direct_terminal_reservations`,
		"mismatched-session":  `UPDATE worker_direct_turn_sources SET native_session='other'`,
		"altered-capacity":    `UPDATE worker_direct_terminal_reservations SET rows_left=383`,
		"over-capacity":       `UPDATE worker_direct_terminal_reservations SET capture_left=999999999`,
		"missing-admission":   `DELETE FROM worker_direct_admissions`,
	} {
		t.Run(name, func(t *testing.T) {
			o, l, s, wire, snap, now := directASKFixture(t)
			if _, err := o.directASK(t.Context(), &directASKController{owner: o, lease: l}, s, wire, true, now, func() NativeSnapshot { return snap }); err != nil {
				t.Fatal(err)
			}
			if _, started, err := o.beginDirectASKSubmissionAt(t.Context(), l, s, wire, now, func() NativeSnapshot { return snap }); err != nil || !started {
				t.Fatalf("claim: %v %v", started, err)
			}
			if _, err := o.journal.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			dir := o.journal.dir
			if err := o.journal.Close(); err != nil {
				t.Fatal(err)
			}
			if j, err := OpenJournal(dir, s.Scope); err == nil {
				j.Close()
				t.Fatal("accepted corrupt direct submission history")
			}
		})
	}
}

func TestDirectSubmissionSourceUnionAndUniqueIdentity(t *testing.T) {
	o, l, s, wire, snap, now := directASKFixture(t)
	if _, err := o.directASK(t.Context(), &directASKController{owner: o, lease: l}, s, wire, true, now, func() NativeSnapshot { return snap }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.beginDirectASKSubmissionAt(t.Context(), l, s, wire, now, func() NativeSnapshot { return snap }); err != nil {
		t.Fatal(err)
	}
	source := NativeTurnSource{SourceDirectASK: &s, InputKind: "direct_ask", LogicalTurnID: logicalDirectTurn(s.AdmissionID), NativeGeneration: s.NativeGeneration, NativeSessionID: s.NativeSessionID}
	if !validDirectTurn(source) {
		t.Fatal("invalid direct turn")
	}
	source.SourceCommandID = "cloud"
	if validDirectTurn(source) {
		t.Fatal("direct turn accepted Cloud identity")
	}
	if err := o.journal.BindNativeTurn(t.Context(), source); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	if _, err := o.journal.db.Exec(`INSERT INTO worker_direct_turn_sources SELECT 'other',native_generation,logical_turn,native_session,source FROM worker_direct_turn_sources`); err == nil {
		t.Fatal("duplicate native direct identity accepted")
	}
}

func TestDirectSubmissionLegacyMigration(t *testing.T) {
	o, l, s, wire, snap, now := directASKFixture(t)
	if _, err := o.directASK(t.Context(), &directASKController{owner: o, lease: l}, s, wire, true, now, func() NativeSnapshot { return snap }); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`ALTER TABLE worker_direct_admissions RENAME TO old_admissions`,
		`CREATE TABLE worker_direct_admissions(admission_id TEXT PRIMARY KEY,delivery_key TEXT NOT NULL UNIQUE,digest TEXT NOT NULL,record BLOB NOT NULL CHECK(length(record)<=98304),state TEXT NOT NULL CHECK(state IN ('reserved','unknown')))`,
		`INSERT INTO worker_direct_admissions SELECT * FROM old_admissions`,
		`DROP TABLE old_admissions`,
	} {
		if _, err := o.journal.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	dir := o.journal.dir
	if err := o.journal.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir, s.Scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	var state string
	if err = j.db.QueryRow(`SELECT state FROM worker_direct_admissions`).Scan(&state); err != nil || state != "unknown" {
		t.Fatalf("legacy recovery: %s %v", state, err)
	}
	if _, err = j.db.Exec(`UPDATE worker_direct_admissions SET state='submitted'`); err != nil {
		t.Fatal("submitted CHECK migration:", err)
	}
}

func TestDirectSubmissionBlocksCloudCapacity(t *testing.T) {
	o, l, s, wire, snap, now := directASKFixture(t)
	if _, err := o.directASK(t.Context(), &directASKController{owner: o, lease: l}, s, wire, true, now, func() NativeSnapshot { return snap }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.beginDirectASKSubmissionAt(t.Context(), l, s, wire, now, func() NativeSnapshot { return snap }); err != nil {
		t.Fatal(err)
	}
	tx, err := o.journal.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = o.journal.reserveTerminalTx(t.Context(), tx, 1, "prompt"); !errors.Is(err, ErrFull) {
		t.Fatalf("Cloud ignored direct capacity: %v", err)
	}
}

func TestDirectSubmissionConflictAndFences(t *testing.T) {
	o, l, s, wire, snap, now := directASKFixture(t)
	if _, _, err := o.beginDirectASKSubmissionAt(t.Context(), l, s, wire, now, func() NativeSnapshot { return snap }); !errors.Is(err, ErrFenced) {
		t.Fatalf("missing reservation: %v", err)
	}
	if _, err := o.directASK(t.Context(), &directASKController{owner: o, lease: l}, s, wire, true, now, func() NativeSnapshot { return snap }); err != nil {
		t.Fatal(err)
	}
	changed := s
	changed.InputDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, _, err := o.beginDirectASKSubmissionAt(t.Context(), l, changed, wire, now, func() NativeSnapshot { return snap }); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed provenance: %v", err)
	}
	if _, _, err := o.beginDirectASKSubmissionAt(t.Context(), l, s, wire, s.Deadline, func() NativeSnapshot { return snap }); !errors.Is(err, ErrFenced) {
		t.Fatalf("deadline: %v", err)
	}
	if _, _, err := o.beginDirectASKSubmissionAt(t.Context(), l, s, wire, now, func() NativeSnapshot { snap.NativeStartIdentity = "other"; return snap }); err == nil {
		t.Fatal("changed process accepted")
	}
	lease(t, o.journal)
	if _, _, err := o.beginDirectASKSubmissionAt(t.Context(), l, s, wire, now, func() NativeSnapshot { return snap }); err == nil {
		t.Fatal("stale lease accepted")
	}
}
