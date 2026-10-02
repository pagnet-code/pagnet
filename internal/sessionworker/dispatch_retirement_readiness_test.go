//go:build linux || darwin

package sessionworker

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestDispatchRetirementReadinessRetainsOriginalEvidenceUntilDrained(t *testing.T) {
	for name, sql := range map[string]string{
		"pending_observation": `INSERT INTO worker_observations(id,digest,payload,size) VALUES('original-observation','original-digest','{"turnSource":{"sequence":1}}',32)`,
		"original_turn":       `INSERT INTO worker_turn_sources(sequence,logical_turn,native_generation,native_session,source_command,source_admission) VALUES(1,'original-turn','original-generation','original-session','original-command','original-admission')`,
		"encrypted_tail":      `INSERT INTO worker_output_spools(sequence,native_generation,ciphertext,size) VALUES(1,'original-generation',X'0102',2)`,
		"terminal_capacity":   `INSERT INTO worker_terminal_reservations(sequence,rows_left,capture_left,content_left) VALUES(1,1,1,1)`,
		"resource_marker":     `INSERT INTO worker_resource_interruptions(sequence,native_generation,payload) VALUES(1,'original-generation','{}')`,
	} {
		t.Run(name, func(t *testing.T) {
			j, _ := testJournal(t)
			l := lease(t, j)
			o := dispatchOwnership(t, j, l)
			p := dispatchProof(o, 1)
			out, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "activate", json.RawMessage(`{}`), func() (*Admission, error) { return &Admission{Scope: j.scope}, nil }, &p)
			if err != nil || !run {
				t.Fatal(run, err)
			}
			if err = j.CheckDispatchRetirement(t.Context(), l, 1); !errors.Is(err, ErrConflict) {
				t.Fatal("admitted effect ready", err)
			}
			if err = j.Settle(t.Context(), out.Sequence, "completed", nil); err != nil {
				t.Fatal(err)
			}
			if err = j.CheckDispatchRetirement(t.Context(), l, 1); !errors.Is(err, ErrConflict) {
				t.Fatal("unacknowledged effect ready", err)
			}
			if err = j.Acknowledge(t.Context(), l, out.Sequence); err != nil {
				t.Fatal(err)
			}
			if _, err = j.db.Exec(sql); err != nil {
				t.Fatal(err)
			}
			if err = j.CheckDispatchRetirement(t.Context(), l, 1); !errors.Is(err, ErrConflict) {
				t.Fatal("pending original evidence ready", err)
			}
			var floor, count int
			if err = j.db.QueryRow(`SELECT retired,(SELECT count(*) FROM worker_dispatches) FROM worker_dispatch_meta`).Scan(&floor, &count); err != nil || floor != 0 || count != 1 {
				t.Fatal("readiness erased original history", floor, count, err)
			}
			// Simulates source receipt ACK/collector COMMIT, never a readiness side effect.
			for _, table := range []string{"worker_observations", "worker_turn_sources", "worker_output_spools", "worker_terminal_reservations", "worker_resource_interruptions"} {
				if _, err = j.db.Exec("DELETE FROM " + table); err != nil {
					t.Fatal(err)
				}
			}
			// Reopen after an acknowledgement-loss window: the cloud has not
			// advanced yet, and the exact original mapping must remain retryable.
			dir, scope := j.dir, j.scope
			if err = j.Close(); err != nil {
				t.Fatal(err)
			}
			j, err = OpenJournal(dir, scope)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			b := lease(t, j)
			if err = j.CheckDispatchRetirement(t.Context(), l, 1); !errors.Is(err, ErrFenced) {
				t.Fatal("old controller ready", err)
			}
			if err = j.CheckDispatchRetirement(t.Context(), b, 2); !errors.Is(err, ErrConflict) {
				t.Fatal("unknown ordinal ready", err)
			}
			for range 2 {
				if err = j.CheckDispatchRetirement(t.Context(), b, 1); err != nil {
					t.Fatal("lost reply cannot replay readiness", err)
				}
			}
			records, err := j.DispatchRecords(t.Context(), b)
			if err != nil || len(records) != 1 || records[0].Proof.SourceCommandID != p.SourceCommandID {
				t.Fatal("readiness lost immutable proof", err)
			}
			if err = j.RetireDispatches(t.Context(), b, 1); err != nil {
				t.Fatal(err)
			}
		})
	}
}
