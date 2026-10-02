//go:build linux || darwin

package sessionworker

import (
	"encoding/json"
	"github.com/pagnet-code/pagnet/domain"
	"testing"
)

func TestOriginalAttachRetainedUntilViewCompletesAcrossReopen(t *testing.T) {
	j, dir := testJournal(t)
	l := lease(t, j)
	o := dispatchOwnership(t, j, l)
	p := dispatchProof(o, 1)
	payload := json.RawMessage(`{}`)
	out, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "attach", payload, func() (*Admission, error) { return &Admission{Scope: j.scope}, nil }, &p)
	if err != nil || !run {
		t.Fatal(err)
	}
	if err = j.Settle(t.Context(), out.Sequence, "completed", nil); err != nil {
		t.Fatal(err)
	}
	if err = j.Acknowledge(t.Context(), l, out.Sequence); err == nil {
		t.Fatal("PTY completion retired pending view")
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	l = lease(t, j)
	rows, err := j.DispatchRecords(t.Context(), l)
	if err != nil || len(rows) != 1 || rows[0].State != "view_pending" {
		t.Fatal("view retry history lost", rows, err)
	}
	replay, effect, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "attach", payload, nil, &p)
	if err != nil || effect || replay.Sequence != out.Sequence {
		t.Fatal("original retry reactivated or retired", err)
	}
	foreign := p
	foreign.SourceCommandID = domain.NewID().String()
	if err = j.CommitTerminalView(t.Context(), l, &foreign); err == nil {
		t.Fatal("foreign view finalized")
	}
	if err = j.CommitTerminalView(t.Context(), l, &p); err != nil {
		t.Fatal(err)
	}
	if err = j.Acknowledge(t.Context(), l, out.Sequence); err != nil {
		t.Fatal(err)
	}
	if err = j.RetireDispatches(t.Context(), l, p.DispatchSequence); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_terminal_view_commits`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("view receipts leak lifetime state", remaining, err)
	}
}
