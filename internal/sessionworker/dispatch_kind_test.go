//go:build linux || darwin

package sessionworker

import (
	"context"
	"encoding/json"
	"testing"
)

func TestOriginalDispatchKindSurvivesOutcomeACKAndReopen(t *testing.T) {
	j, dir := testJournal(t)
	ctx := context.Background()
	current := lease(t, j)
	owner := dispatchOwnership(t, j, current)
	proof := dispatchProof(owner, 1)
	source := Admission{Scope: j.scope, NativeAdmissionID: proof.SourceAdmissionID, RunnerID: proof.SourceRunnerID, RunnerEpoch: proof.SourceRunnerEpoch, BootID: proof.SourceBootID}
	out, run, err := j.admitDispatch(ctx, current, 0, proof.SourceCommandID, "stop", json.RawMessage(`{}`), func() (*Admission, error) { copy := source; return &copy, nil }, &proof)
	if err != nil || !run {
		t.Fatal(err)
	}
	if err = j.Settle(ctx, out.Sequence, "completed", nil); err != nil {
		t.Fatal(err)
	}
	if err = j.Acknowledge(ctx, current, out.Sequence); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Outcome(ctx, out.Sequence); err == nil {
		t.Fatal("outcome retained instead of testing lost ACK mapping")
	}
	if _, err = j.db.Exec(`UPDATE worker_dispatches SET operation_kind='activate'`); err == nil {
		t.Fatal("immutable original kind could be relabelled")
	}
	scope := j.scope
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	current = lease(t, reopened)
	records, err := reopened.DispatchRecords(ctx, current)
	if err != nil || len(records) != 1 || records[0].Kind != "stop" || records[0].State != "completed" || records[0].OperationSequence != out.Sequence {
		t.Fatal("ACK/reopen lost exact original stop kind", records, err)
	}
	if err = reopened.RetireDispatches(ctx, current, 1); err != nil {
		t.Fatal(err)
	}
	records, err = reopened.DispatchRecords(ctx, current)
	if err != nil || len(records) != 0 {
		t.Fatal("retirement leaked operation-kind lifetime tombstone", err)
	}
}

func TestLegacyDispatchKindOnlyRecoversStillRetainedOriginalIntent(t *testing.T) {
	for _, pruned := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained", true: "already_pruned"}[pruned], func(t *testing.T) {
			j, dir := testJournal(t)
			ctx := context.Background()
			current := lease(t, j)
			owner := dispatchOwnership(t, j, current)
			proof := dispatchProof(owner, 1)
			source := Admission{Scope: j.scope, NativeAdmissionID: proof.SourceAdmissionID}
			out, _, err := j.admitDispatch(ctx, current, 0, proof.SourceCommandID, "stop", json.RawMessage(`{}`), func() (*Admission, error) { return &source, nil }, &proof)
			if err != nil {
				t.Fatal(err)
			}
			if err = j.Settle(ctx, out.Sequence, "completed", nil); err != nil {
				t.Fatal(err)
			}
			if pruned {
				if err = j.Acknowledge(ctx, current, out.Sequence); err != nil {
					t.Fatal(err)
				}
			}
			// Simulate the pre-field schema without rewriting any source/cipher/proof.
			if _, err = j.db.Exec(`DROP TRIGGER worker_dispatch_kind_immutable`); err != nil {
				t.Fatal(err)
			}
			if _, err = j.db.Exec(`ALTER TABLE worker_dispatches DROP COLUMN operation_kind`); err != nil {
				t.Fatal(err)
			}
			scope := j.scope
			if err = j.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenJournal(dir, scope)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			current = lease(t, reopened)
			records, err := reopened.DispatchRecords(ctx, current)
			if err != nil || len(records) != 1 {
				t.Fatal(err)
			}
			want := "stop"
			if pruned {
				want = ""
			}
			if records[0].Kind != want {
				t.Fatal("legacy unknown kind guessed instead of original-intent recovery", records[0].Kind)
			}
		})
	}
}

func TestDispatchKindAdmissionRollbackKeepsBothOrdinalNamespaces(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	current := lease(t, j)
	owner := dispatchOwnership(t, j, current)
	proof := dispatchProof(owner, 1)
	if _, err := j.db.Exec(`CREATE TRIGGER fail_original_kind BEFORE UPDATE OF operation_kind ON worker_dispatches BEGIN SELECT RAISE(ABORT,'kind binding rollback fixture'); END`); err != nil {
		t.Fatal(err)
	}
	source := Admission{Scope: j.scope, NativeAdmissionID: proof.SourceAdmissionID}
	if _, run, err := j.admitDispatch(ctx, current, 0, proof.SourceCommandID, "stop", json.RawMessage(`{}`), func() (*Admission, error) { return &source, nil }, &proof); err == nil || run {
		t.Fatal("failed metadata binding admitted native effect")
	}
	var next, last, intents, records int
	if err := j.db.QueryRow(`SELECT (SELECT next_sequence FROM worker_meta),(SELECT last_sequence FROM worker_dispatch_meta),(SELECT COUNT(*) FROM worker_intent),(SELECT COUNT(*) FROM worker_dispatches)`).Scan(&next, &last, &intents, &records); err != nil {
		t.Fatal(err)
	}
	if next != 1 || last != 0 || intents != 0 || records != 0 {
		t.Fatal("kind rollback left sequence gap or native intent", next, last, intents, records)
	}
}
