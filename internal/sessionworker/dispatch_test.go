//go:build linux || darwin

package sessionworker

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func dispatchOwnership(t *testing.T, j *Journal, l int64) transport.NativeWorkerOwnership {
	t.Helper()
	o := transport.NativeWorkerOwnership{ID: domain.NewID().String(), InstanceID: j.scope.InstanceID, OwnershipGeneration: j.scope.Generation, Runtime: "fake-persistent", OriginalAdmissionID: domain.NewID().String(), State: "active", ProfileFingerprint: strings.Repeat("a", 64)}
	if err := j.BindDispatchOwnership(t.Context(), l, o, o.Runtime, o.ProfileFingerprint); err != nil {
		t.Fatal(err)
	}
	return o
}
func dispatchProof(o transport.NativeWorkerOwnership, n int64) transport.NativeDispatchProof {
	return transport.NativeDispatchProof{OwnershipID: o.ID, OwnershipGeneration: o.OwnershipGeneration, DispatchSequence: n, SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String(), SourceRunnerID: domain.NewID().String(), SourceRunnerEpoch: time.Now().UTC(), SourceBootID: domain.NewID().String()}
}

func TestDispatchOriginalSourceAndOrdinalSurviveReplacementAndReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "worker")
	j, err := OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	a := lease(t, j)
	// A local resize occupies operation1 but is not a server dispatch ordinal.
	if _, run, err := j.Admit(t.Context(), a, 1, "local-resize", "resize", json.RawMessage(`{}`)); err != nil || !run {
		t.Fatal(run, err)
	}
	o := dispatchOwnership(t, j, a)
	p := dispatchProof(o, 1)
	current := &Admission{Scope: j.scope, NativeAdmissionID: domain.NewID().String(), RunnerID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), BootID: "controller-B", Kind: "worker", NetworkID: "network"}
	payload := json.RawMessage(`{"input":"private source body"}`)
	out, run, err := j.admitDispatch(t.Context(), a, 0, p.SourceCommandID, "prompt", payload, func() (*Admission, error) { return current, nil }, &p)
	if err != nil || !run || out.Sequence != 2 || out.SourceAdmission.NativeAdmissionID != p.SourceAdmissionID || out.SourceAdmission.BootID != p.SourceBootID {
		t.Fatal("wrong operation/source", out.Sequence, run, err)
	}
	b := lease(t, j)
	for _, mutation := range []string{"runner", "command", "body", "gap", "scope"} {
		bad := p
		input := payload
		switch mutation {
		case "runner":
			bad.SourceRunnerID = domain.NewID().String()
		case "command":
			bad.SourceCommandID = domain.NewID().String()
		case "body":
			input = json.RawMessage(`{"input":"different"}`)
		case "gap":
			bad.DispatchSequence = 3
		case "scope":
			bad.OwnershipGeneration = "another"
		}
		if _, run, err := j.admitDispatch(t.Context(), b, 0, bad.SourceCommandID, "prompt", input, func() (*Admission, error) { return current, nil }, &bad); err == nil || run {
			t.Fatal("changed dispatch accepted", mutation)
		}
	}
	if _, _, err = j.admitDispatch(t.Context(), a, 0, p.SourceCommandID, "prompt", payload, nil, &p); !errors.Is(err, ErrFenced) {
		t.Fatal("A not fenced", err)
	}
	for _, kind := range []string{"prompt", "activate", "attach", "stop", "hibernate", "restart"} {
		if _, _, err = j.Admit(t.Context(), b, 3, "unbound-"+kind, kind, payload); err == nil {
			t.Fatal("bound ownership permitted ordinal-free lifecycle", kind)
		}
	}
	if err = j.Acknowledge(t.Context(), b, 1); err == nil {
		t.Fatal("unsettled local intent acked")
	}
	if err = j.Settle(t.Context(), 1, "completed", nil); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	l := lease(t, j)
	out, run, err = j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", payload, func() (*Admission, error) { t.Fatal("retry invoked native admission"); return nil, nil }, &p)
	if err != nil || run || out.State != "uncertain" || out.Sequence != 2 || out.SourceAdmission.RunnerID != p.SourceRunnerID {
		t.Fatal("reopen replay lost original", out.State, run, err)
	}
	if err = j.Acknowledge(t.Context(), l, 1); err != nil {
		t.Fatal(err)
	}
	if err = j.Acknowledge(t.Context(), l, 2); err != nil {
		t.Fatal(err)
	}
	if err = j.RetireDispatches(t.Context(), l, 1); err == nil {
		t.Fatal("uncertain effect was retired")
	}
	if _, run, err = j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", payload, nil, &p); err == nil || run {
		t.Fatal("uncertain acknowledged dispatch replayed")
	}
}

func TestDispatchRetirementIsBoundedWithoutLifetimeLimit(t *testing.T) {
	j, _ := testJournal(t)
	l := lease(t, j)
	o := dispatchOwnership(t, j, l)
	for n := int64(1); n <= 2*maxCommands+1; n++ {
		p := dispatchProof(o, n)
		out, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "activate", json.RawMessage(`{}`), func() (*Admission, error) { return &Admission{Scope: j.scope}, nil }, &p)
		if err != nil || !run {
			t.Fatal(n, run, err)
		}
		if err = j.RetireDispatches(t.Context(), l, n); err == nil {
			t.Fatal("retired before outcome", n)
		}
		if err = j.Settle(t.Context(), out.Sequence, "completed", nil); err != nil {
			t.Fatal(err)
		}
		if err = j.RetireDispatches(t.Context(), l, n); err == nil {
			t.Fatal("retired before receipt", n)
		}
		if err = j.Acknowledge(t.Context(), l, out.Sequence); err != nil {
			t.Fatal(err)
		}
		if err = j.RetireDispatches(t.Context(), l, n); err != nil {
			t.Fatal(err)
		}
		if _, run, err = j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "activate", json.RawMessage(`{}`), nil, &p); !errors.Is(err, ErrRetired) || run {
			t.Fatal("retired command resurrected", n, run, err)
		}
	}
	var count int
	if err := j.db.QueryRow(`SELECT COUNT(*) FROM worker_dispatches`).Scan(&count); err != nil || count != 0 {
		t.Fatal("lifetime tombstones retained", count, err)
	}
}

func TestDispatchAdmissionRollbackAndConcurrentReplay(t *testing.T) {
	j, _ := testJournal(t)
	l := lease(t, j)
	o := dispatchOwnership(t, j, l)
	p := dispatchProof(o, 1)
	authorize := func() (*Admission, error) { return &Admission{Scope: j.scope}, nil }
	if _, err := j.db.Exec(`CREATE TRIGGER fail_dispatch_effect BEFORE INSERT ON worker_intent BEGIN SELECT RAISE(ABORT,'test admission rollback'); END`); err != nil {
		t.Fatal(err)
	}
	if _, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "activate", json.RawMessage(`{}`), authorize, &p); err == nil || run {
		t.Fatal("failed atomic admission looked accepted")
	}
	var next, last, count int64
	if err := j.db.QueryRow(`SELECT next_sequence,(SELECT last_sequence FROM worker_dispatch_meta),(SELECT COUNT(*) FROM worker_dispatches) FROM worker_meta`).Scan(&next, &last, &count); err != nil || next != 1 || last != 0 || count != 0 {
		t.Fatal("allocation escaped rollback", next, last, count, err)
	}
	if _, err := j.db.Exec(`DROP TRIGGER fail_dispatch_effect`); err != nil {
		t.Fatal(err)
	}
	gap := dispatchProof(o, 2)
	if _, run, err := j.admitDispatch(t.Context(), l, 0, gap.SourceCommandID, "activate", json.RawMessage(`{}`), authorize, &gap); !errors.Is(err, ErrDispatchGap) || run {
		t.Fatal("gap wasn't deferred", run, err)
	}
	var runs atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			out, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "activate", json.RawMessage(`{}`), authorize, &p)
			if err != nil || out.Sequence != 1 {
				t.Error("same dispatch couldn't replay", out.Sequence, err)
			}
			if run {
				runs.Add(1)
			}
		})
	}
	wg.Wait()
	if runs.Load() != 1 {
		t.Fatal("effect admitted more than once", runs.Load())
	}
	if err := j.Settle(t.Context(), 1, "completed", nil); err != nil {
		t.Fatal(err)
	}
	if _, run, err := j.admitDispatch(t.Context(), l, 0, gap.SourceCommandID, "activate", json.RawMessage(`{}`), authorize, &gap); err != nil || !run {
		t.Fatal("deferred original ordinal lost", run, err)
	}
}

func TestDispatchCanonicalInputBindsOriginalTaskAndAdmission(t *testing.T) {
	p := transport.NativeDispatchProof{SourceCommandID: "command-A", SourceAdmissionID: "admission-A", TaskSource: &transport.NativeTaskSource{TaskID: "task-A"}}
	body := json.RawMessage(`{"input":"original private body","inputKind":"event"}`)
	req := Request{Type: "intent", Kind: "prompt", Payload: body, NativeDispatch: &p}
	raw, err := prepareDispatchOperation(req)
	if err != nil {
		t.Fatal(err)
	}
	var op Operation
	if err = json.Unmarshal(raw, &op); err != nil {
		t.Fatal(err)
	}
	if op.Input != "original private body" || op.InputKind != "task" || op.SourceCommandID != "command-A" || op.SourceAdmissionID != "admission-A" || op.SourceTask.TaskID != "task-A" {
		t.Fatal("original accepted source changed")
	}
	p.TaskSource.TaskID = "changed-after-prepare"
	if op.SourceTask.TaskID != "task-A" {
		t.Fatal("source aliases mutable proof")
	}
	for _, bad := range []json.RawMessage{json.RawMessage(`{"input":"private","sourceCommandId":"command-B"}`), json.RawMessage(`{"input":"private","sourceAdmissionId":"admission-B"}`), json.RawMessage(`{"input":"private","sourceTask":{"taskId":"other"}}`), json.RawMessage(`{"input":"","inputKind":"task"}`)} {
		req.Payload = bad
		if _, err = prepareDispatchOperation(req); err == nil {
			t.Fatal("conflicting or empty source accepted")
		}
	}
	req.NativeDispatch = &transport.NativeDispatchProof{SourceCommandID: "command-A", SourceAdmissionID: "admission-A"}
	for _, tc := range []struct{ input, expected string }{{"event", "notice"}, {"channel", "user_input"}, {"ask", "ask"}} {
		req.Payload = json.RawMessage(`{"input":"original private body","inputKind":"` + tc.input + `"}`)
		raw, err = prepareDispatchOperation(req)
		if err != nil {
			t.Fatal(err)
		}
		op = Operation{}
		if err = json.Unmarshal(raw, &op); err != nil || op.InputKind != tc.expected || op.SourceTask != nil {
			t.Fatal("bad input normalization", tc, err)
		}
	}
}

func TestDispatchRecordsRetainSettledMappingUntilBackendRetirement(t *testing.T) {
	j, err := OpenJournal(filepath.Join(t.TempDir(), "worker"), testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	a := lease(t, j)
	o := dispatchOwnership(t, j, a)
	p := dispatchProof(o, 1)
	out, _, err := j.admitDispatch(t.Context(), a, 0, p.SourceCommandID, "prompt", json.RawMessage(`{"input":"original"}`), func() (*Admission, error) {
		return &Admission{Scope: j.scope, NativeAdmissionID: p.SourceAdmissionID, RunnerID: p.SourceRunnerID, RunnerEpoch: p.SourceRunnerEpoch, BootID: p.SourceBootID}, nil
	}, &p)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Settle(t.Context(), out.Sequence, "completed", nil); err != nil {
		t.Fatal(err)
	}
	if err = j.Acknowledge(t.Context(), a, out.Sequence); err != nil {
		t.Fatal(err)
	}
	records, err := j.DispatchRecords(t.Context(), a)
	if err != nil || len(records) != 1 || records[0].Proof != p || records[0].OperationSequence != out.Sequence || records[0].State != "completed" {
		t.Fatal("settled original mapping lost", records, err)
	}
	b := lease(t, j)
	if _, err = j.DispatchRecords(t.Context(), a); !errors.Is(err, ErrFenced) {
		t.Fatal("old controller read retained records", err)
	}
	if err = j.RetireDispatches(t.Context(), b, 1); err != nil {
		t.Fatal(err)
	}
	if records, err = j.DispatchRecords(t.Context(), b); err != nil || len(records) != 0 {
		t.Fatal("retired mapping remains", err)
	}
}

func TestOriginalNativeDispatchDefersNextTurnButReacknowledgesAcceptedWork(t *testing.T) {
	j, err := OpenJournal(filepath.Join(t.TempDir(), "worker"), testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	l := lease(t, j)
	o := dispatchOwnership(t, j, l)
	a := dispatchProof(o, 1)
	b := dispatchProof(o, 2)
	authorize := func() (*Admission, error) {
		return &Admission{Scope: j.scope, NativeAdmissionID: a.SourceAdmissionID, RunnerID: a.SourceRunnerID, RunnerEpoch: a.SourceRunnerEpoch, BootID: a.SourceBootID}, nil
	}
	payload := json.RawMessage(`{"input":"original private turn"}`)
	first, run, err := j.admitDispatch(t.Context(), l, 0, a.SourceCommandID, "prompt", payload, authorize, &a)
	if err != nil || !run {
		t.Fatal(run, err)
	}
	duplicate, run, err := j.admitDispatch(t.Context(), l, 0, a.SourceCommandID, "prompt", payload, authorize, &a)
	if err != nil || run || duplicate.Sequence != first.Sequence {
		t.Fatal("accepted work not reacknowledged", run, err)
	}
	if _, run, err = j.admitDispatch(t.Context(), l, 0, b.SourceCommandID, "prompt", payload, authorize, &b); !errors.Is(err, ErrNativeBusy) || run {
		t.Fatal("overlapping native turn admitted", run, err)
	}
	records, err := j.DispatchRecords(t.Context(), l)
	if err != nil || len(records) != 1 {
		t.Fatal("deferred work allocated ordinal", records, err)
	}
	if err = j.Settle(t.Context(), first.Sequence, "completed", nil); err != nil {
		t.Fatal(err)
	}
	next, run, err := j.admitDispatch(t.Context(), l, 0, b.SourceCommandID, "prompt", payload, authorize, &b)
	if err != nil || !run || next.Sequence != first.Sequence+1 {
		t.Fatal("deferred next work lost", next.Sequence, run, err)
	}
}
