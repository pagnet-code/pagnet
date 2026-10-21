//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/transport"
)

func recoveryBootstrap(t *testing.T, dir string) {
	t.Helper()
	raw, err := json.Marshal(Bootstrap{Protocol: Protocol, Scope: testScope()})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "bootstrap.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "control.key"), bytes.Repeat([]byte{7}, 32), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDeletionRecoveryRequiresOriginalJournalAndExclusiveOwner(t *testing.T) {
	j, dir := testJournal(t)
	recoveryBootstrap(t, dir)
	if _, err := OpenDeletionRecovery(t.Context(), dir, testScope()); !errors.Is(err, ErrWorkerOwned) {
		t.Fatal("live owner not fenced", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "intents.sqlite")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDeletionRecovery(t.Context(), dir, testScope()); err == nil {
		t.Fatal("missing history accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "intents.sqlite")); !os.IsNotExist(err) {
		t.Fatal("recovery created replacement journal", err)
	}
}

func TestDeletionRecoverySettlesOriginalStopBeforePrivateRetirement(t *testing.T) {
	j, dir := testJournal(t)
	recoveryBootstrap(t, dir)
	l := lease(t, j)
	owned := dispatchOwnership(t, j, l)
	stop := dispatchProof(owned, 1)
	admission := &Admission{Scope: j.scope}
	out, _, err := j.admitDispatch(t.Context(), l, 0, stop.SourceCommandID, "stop", json.RawMessage(`{}`), func() (*Admission, error) { return admission, nil }, &stop)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Settle(t.Context(), out.Sequence, "completed", nil); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err := OpenDeletionRecovery(t.Context(), dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = recovery.Close() }()
	foreign := owned
	foreign.ID = "foreign"
	if _, _, err = recovery.Prepare(t.Context(), foreign, nil); err == nil {
		t.Fatal("foreign ownership accepted")
	}
	floor, unstarted, err := recovery.Prepare(t.Context(), owned, nil)
	if err != nil || floor != 1 || unstarted == nil || !transport.SameNativeDispatchProof(*unstarted, stop) {
		t.Fatal("original stop lost", floor, err)
	}
	// Backend floor COMMIT can precede local pruning and the GC marker.
	// The original retained dispatch must replay with the old registry floor.
	if err = recovery.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err = OpenDeletionRecovery(t.Context(), dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	if floor, unstarted, err = recovery.Prepare(t.Context(), owned, nil); err != nil || floor != 1 || unstarted == nil {
		t.Fatal("backend floor commit replay", floor, err)
	}
	retired := owned
	retired.State = "retired"
	retired.LastDispatchSequence, retired.RetiredFloor = 1, 1
	if err = recovery.CommitRetirement(t.Context(), retired); err == nil {
		t.Fatal("private receipt bypassed dispatch retirement")
	}
	if err = recovery.RetireDispatches(t.Context(), floor); err != nil {
		t.Fatal(err)
	}
	// Pruning is allowed only after the daemon records the prepared floor.
	// Reopening with that prepared ownership needs no vanished stop mapping.
	if err = recovery.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err = OpenDeletionRecovery(t.Context(), dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	// The live proxy may have pruned after cloud COMMIT but died before the
	// deletion marker advanced. A stale waiting floor must reconcile using
	// the original journal's durable retired cursor and backend confirmation.
	if floor, unstarted, err = recovery.Prepare(t.Context(), owned, nil); err != nil || floor != 1 || unstarted != nil {
		t.Fatal("stale waiting floor replay", floor, err)
	}
	prepared := retired
	prepared.State = "active"
	if floor, unstarted, err = recovery.Prepare(t.Context(), prepared, nil); err != nil || floor != 1 || unstarted != nil {
		t.Fatal("prepared floor replay", floor, err)
	}
	if err = recovery.CommitRetirement(t.Context(), retired); err != nil {
		t.Fatal(err)
	}
	if _, err = recovery.SourceCall(t.Context(), Request{Type: "dispatch"}); err == nil {
		t.Fatal("recovery admitted effects")
	}
}

func TestDeletionRecoveryKeepsUncertainOriginalEffect(t *testing.T) {
	j, dir := testJournal(t)
	recoveryBootstrap(t, dir)
	l := lease(t, j)
	owned := dispatchOwnership(t, j, l)
	proof := dispatchProof(owned, 1)
	if _, _, err := j.admitDispatch(t.Context(), l, 0, proof.SourceCommandID, "stop", json.RawMessage(`{}`), func() (*Admission, error) { return &Admission{Scope: j.scope}, nil }, &proof); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err := OpenDeletionRecovery(t.Context(), dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	if _, _, err = recovery.Prepare(t.Context(), owned, nil); err == nil {
		t.Fatal("uncertain effect discarded")
	}
	out, err := recovery.journal.Outcome(t.Context(), 1)
	if err != nil || out.State != "uncertain" {
		t.Fatal("original uncertainty lost", out, err)
	}
}

func TestDeletionRecoveryMaterializedRequiresExactStoppedReceipt(t *testing.T) {
	f, proof := originalDeleteFixture(t, false)
	j := f.journal
	// Build the already-settled variant of the original captured turn fixture.
	if _, err := j.db.Exec(`UPDATE worker_intent SET state='completed' WHERE sequence=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.Exec(`UPDATE worker_turn_sources SET completed=1 WHERE sequence=1`); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := j.db.QueryRow(`SELECT ownership FROM worker_dispatch_meta`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var owned transport.NativeWorkerOwnership
	if err := json.Unmarshal([]byte(raw), &owned); err != nil {
		t.Fatal(err)
	}
	recoveryBootstrap(t, f.dir)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err := OpenDeletionRecovery(t.Context(), f.dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	if _, _, err = recovery.Prepare(t.Context(), owned, nil); err == nil {
		t.Fatal("materialized runtime accepted without stop receipt")
	}
	bad := *proof
	bad.StoppedDigest = "foreign"
	if _, _, err = recovery.Prepare(t.Context(), owned, &bad); err == nil {
		t.Fatal("foreign stopped receipt accepted")
	}
	floor, unstarted, err := recovery.Prepare(t.Context(), owned, proof)
	if err != nil || floor != 2 || unstarted != nil {
		t.Fatal("settled materialized deletion blocked", floor, err)
	}
	if err = recovery.RetireDispatches(t.Context(), floor); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, recovery.journal, "worker_stopped_receipts") != 1 {
		t.Fatal("dispatch floor lost latest stop witness")
	}
	// Crash after backend floor/pruning and before local ownership retirement.
	if err = recovery.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err = OpenDeletionRecovery(t.Context(), f.dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	if _, _, err = recovery.Prepare(t.Context(), owned, proof); err != nil {
		t.Fatal("reopened stop proof lost", err)
	}
	owned.State, owned.LastDispatchSequence, owned.RetiredFloor, owned.DeletionProof = "retired", floor, floor, proof
	if err = recovery.CommitRetirement(t.Context(), owned); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, recovery.journal, "worker_stopped_receipts") != 0 || sourceCount(t, recovery.journal, "worker_source_registration") != 0 {
		t.Fatal("ownership retirement retained stop witness")
	}
}

func TestExistingJournalRejectsEmptyHistory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "worker")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "intents.sqlite"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if j, err := OpenExistingJournal(dir, testScope()); err == nil {
		_ = j.Close()
		t.Fatal("empty journal became fresh history")
	}
	info, err := os.Stat(filepath.Join(dir, "intents.sqlite"))
	if err != nil || info.Size() != 0 {
		t.Fatal("empty history mutated", err)
	}
}
