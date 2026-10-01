//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestOutputBoundedReplayAndDurableSequence(t *testing.T) {
	j, dir := testJournal(t)
	ctx := context.Background()
	payload, _ := json.Marshal(string(bytes.Repeat([]byte{'x'}, 120<<10)))
	for i := int64(1); i <= 30; i++ {
		seq, err := j.AppendOutput(ctx, "actual-generation", json.RawMessage(`{"id":"original-source"}`), "terminal", payload)
		if err != nil || seq != i {
			t.Fatalf("append %d: %d %v", i, seq, err)
		}
	}
	page, err := j.ReplayOutput(ctx, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(page)
	if !page.Gap || page.RetiredThrough == 0 || page.NextSequence != 31 || len(page.Records) == 0 || len(encoded) >= maxFrame {
		t.Fatalf("unbounded/gapless replay: records=%d bytes=%d %+v", len(page.Records), len(encoded), page.RetiredThrough)
	}
	last := page.RetiredThrough
	for _, r := range page.Records {
		if r.Sequence != last+1 {
			t.Fatal("noncontiguous output")
		}
		last = r.Sequence
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	seq, err := reopened.AppendOutput(ctx, "actual-generation", nil, "session", json.RawMessage(`{}`))
	if err != nil || seq != 31 {
		t.Fatalf("sequence after restart %d %v", seq, err)
	}
}

func TestOutputRejectsCorruptRetainedHistory(t *testing.T) {
	for _, corrupt := range []string{`UPDATE worker_output SET sequence=3 WHERE sequence=1`, `UPDATE worker_output SET kind='unknown'`, `UPDATE worker_output SET data='not-json'`} {
		t.Run(corrupt, func(t *testing.T) {
			j, dir := testJournal(t)
			if _, err := j.AppendOutput(context.Background(), "generation", nil, "session", json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
			if _, err := j.db.Exec(corrupt); err != nil {
				t.Fatal(err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenJournal(dir, testScope())
			if err == nil {
				reopened.Close()
				t.Fatal("corrupt output trusted after restart")
			}
		})
	}
}
