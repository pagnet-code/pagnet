//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"testing"
	"time"
)

func TestOutputBoundedReplayAndWorkerSequence(t *testing.T) {
	replay := NewOutputReplay()
	payload, _ := json.Marshal(string(bytes.Repeat([]byte{'x'}, 120<<10)))
	for i := int64(1); i <= 30; i++ {
		seq, err := replay.Append("actual-generation", json.RawMessage(`{"id":"original-source"}`), "terminal", payload)
		if err != nil || seq != i {
			t.Fatalf("append %d: %d %v", i, seq, err)
		}
	}
	page, err := replay.Replay("", 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(page)
	if !page.Gap || page.RetiredThrough == 0 || page.NextSequence != 31 || len(page.Records) == 0 || len(encoded) >= maxFrame {
		t.Fatal("unbounded or gapless replay")
	}
	last := page.RetiredThrough
	for _, record := range page.Records {
		if record.Sequence != last+1 {
			t.Fatal("noncontiguous replay")
		}
		last = record.Sequence
	}
	// A new controller reads the exact same in-memory sequence without disk.
	again, err := replay.Replay(page.ReplayGeneration, page.RetiredThrough, 64)
	if err != nil || again.Gap || again.NextSequence != page.NextSequence {
		t.Fatal("controller replacement reset output")
	}
	replacement := NewOutputReplay()
	replacementPage, err := replacement.Replay(page.ReplayGeneration, page.NextSequence-1, 64)
	if err != nil || !replacementPage.Gap || replacementPage.ReplayGeneration == page.ReplayGeneration {
		t.Fatal("worker replacement hid missing terminal replay")
	}
}

func TestTerminalReplayCannotWaitForSQLiteIntentLock(t *testing.T) {
	j, _ := testJournal(t)
	owner := &SessionOwner{journal: j}
	j.mu.Lock()
	defer j.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 1000; i++ {
			owner.record("terminal", []byte("native output"), "generation", nil)
		}
		_, err := owner.outputReplay().Replay("", 0, 64)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal stream blocked on durable journal")
	}
	// The output path must not create a plaintext terminal table.
	var exists int
	if err := j.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE name='worker_output'`).Scan(&exists); err != nil || exists != 0 {
		t.Fatalf("terminal output persisted: %d %v", exists, err)
	}
}

func TestLargeDurableNativeAnswerFitsBoundedEphemeralReplay(t *testing.T) {
	j, _ := testJournal(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := session.NewManager()
	manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	owner := &SessionOwner{ctx: ctx, journal: j, manager: manager, generation: "actual-generation", origin: json.RawMessage(`{"id":"original-source"}`), pending: map[string]*nativeApproval{}}
	answer := string(bytes.Repeat([]byte{'x'}, 700<<10))
	event := session.SessionEvent{Type: session.EventTurnOutput, SessionID: "native-session", Output: answer}
	if err := owner.nativeEventObserver(j.scope.InstanceID)(event); err != nil {
		t.Fatal(err)
	}
	if owner.fatal != nil {
		t.Fatalf("valid large native answer poisoned worker: %v", owner.fatal)
	}
	observations, err := j.PendingObservations(ctx, 32)
	if err != nil || len(observations) != 1 || observations[0].Event.Output != answer {
		t.Fatal("exact durable answer lost")
	}
	page, err := owner.outputReplay().Replay("", 0, 64)
	if err != nil || len(page.Records) != 1 {
		t.Fatal("large answer lost in replay")
	}
	var replayed session.SessionEvent
	if err := json.Unmarshal(page.Records[0].Data, &replayed); err != nil || replayed.Output != answer {
		t.Fatal("large replay truncated")
	}
	encoded, _ := json.Marshal(Response{Output: &page})
	if len(encoded) > maxFrame {
		t.Fatal("large replay exceeded bounded wire frame")
	}
}

func TestMaximumAcceptedEncodedReplayRecordAlwaysAdvancesCursor(t *testing.T) {
	generation := "generation"
	origin := json.RawMessage(`{"id":"source"}`)
	lower, upper := 0, maxOutputRecord
	for lower < upper {
		mid := (lower + upper + 1) / 2
		raw, _ := json.Marshal(string(bytes.Repeat([]byte{'x'}, mid)))
		if validOutput(generation, origin, "terminal", raw) {
			lower = mid
		} else {
			upper = mid - 1
		}
	}
	maximum, _ := json.Marshal(string(bytes.Repeat([]byte{'x'}, lower)))
	replay := NewOutputReplay()
	if _, err := replay.Append(generation, origin, "terminal", maximum); err != nil {
		t.Fatal(err)
	}
	tooLarge, _ := json.Marshal(string(bytes.Repeat([]byte{'x'}, lower+1)))
	if _, err := replay.Append(generation, origin, "terminal", tooLarge); err == nil {
		t.Fatal("oversized encoded replay accepted")
	}
	page, err := replay.Replay("", 0, 1)
	if err != nil || len(page.Records) != 1 || page.Records[0].Sequence != 1 {
		t.Fatalf("maximum admitted record stuck behind page budget: %+v %v", page, err)
	}
	encoded, _ := json.Marshal(Response{Output: &page})
	if len(encoded) > maxFrame {
		t.Fatal("maximum admitted output exceeded response frame")
	}
}
