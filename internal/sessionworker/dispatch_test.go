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
	if _, _, err = j.Admit(t.Context(), b, 3, "unbound-prompt", "prompt", payload); err == nil {
		t.Fatal("bound ownership permitted ordinal-free prompt")
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
	if _, run, err := j.admitDispatch(t.Context(), l, 0, gap.SourceCommandID, "activate", json.RawMessage(`{}`), authorize, &gap); err != nil || !run {
		t.Fatal("deferred original ordinal lost", run, err)
	}
}
