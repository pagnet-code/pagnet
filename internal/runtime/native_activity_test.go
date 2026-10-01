package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"testing"
	"time"
)

func TestQwenHumanActivityPreventsHibernate(t *testing.T) {
	state, _ := newFixtureState(false, "")
	feedLines(t, state, validHandshakeLine(t, fixtureSID, fixtureCWD), userTextLine(t, fixtureSID, "human begins work"))
	driver := NewQwenPersistent("")
	driver.endpoints["agent"] = &qwenEndpoint{state: state}
	if !driver.ActiveWork("agent") {
		t.Fatal("human turn was invisible to lifecycle")
	}
	if err := driver.Hibernate(context.Background(), &session.RuntimeSession{InstanceID: "agent"}); !errors.Is(err, session.ErrBusy) {
		t.Fatalf("native human turn could be killed: %v", err)
	}
	feedLines(t, state, messageStopLine(t, fixtureSID), assistantLine(t, fixtureSID, "test", 1, 1, 0))
	if driver.ActiveWork("agent") || !driver.Materialised("agent") {
		t.Fatal("human completion failed to settle resumable activity")
	}
}

func TestCodexExternalTurnActivityAndStaleCompletion(t *testing.T) {
	state := newCodexTurnState(false, "")
	state.setThread("thread", "model")
	if ev := state.processTurnStarted("thread", codexTurn{ID: "human"}); len(ev) != 0 {
		t.Fatal("human work leaked onto machine stream")
	}
	if !state.activeWork() {
		t.Fatal("human turn was invisible")
	}
	state.processTurnCompleted("thread", codexTurn{ID: "old", Status: "completed"})
	if !state.activeWork() {
		t.Fatal("stale completion cleared current work")
	}
	state.processTurnCompleted("thread", codexTurn{ID: "human", Status: "completed"})
	if state.activeWork() || !state.materialised {
		t.Fatal("completed human conversation not preserved")
	}
	state.processNotification("thread/status/changed", json.RawMessage(`{"threadId":"thread","status":{"type":"active"}}`))
	if !state.activeWork() {
		t.Fatal("native active status ignored")
	}
	state.processNotification("thread/status/changed", json.RawMessage(`{"threadId":"foreign","status":{"type":"idle"}}`))
	if !state.activeWork() {
		t.Fatal("foreign status cleared native activity")
	}
	state.processNotification("thread/status/changed", json.RawMessage(`{"threadId":"thread","status":{"type":"idle"}}`))
	if state.activeWork() {
		t.Fatal("native idle status never settled")
	}
}

func TestCodexNativeHumanExchangeHibernateResumeRealProcess(t *testing.T) {
	_, m, driver := newCodexFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := m.Session("native-human", domain.RuntimeCodex, t.TempDir())
	s.Env = codexMCPEnv(s.InstanceID)
	if _, err := m.EnsureActive(ctx, s, nil); err != nil {
		t.Fatal(err)
	}
	original, _ := m.NativeID(s.InstanceID)
	driver.mu.Lock()
	ep := driver.endpoints[s.InstanceID]
	driver.mu.Unlock()
	// Native RPC bypasses Manager.Submit exactly as an independently initiated
	// runtime turn does. The real fixture records its actual exchange on disk.
	if _, err := ep.request(ctx, "turn/start", map[string]any{"threadId": original, "input": []map[string]string{{"type": "text", "text": "native human exchange"}}}); err != nil {
		t.Fatal(err)
	}
	for !driver.Materialised(s.InstanceID) {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	if err := m.Hibernate(ctx, s); err != nil {
		t.Fatal(err)
	}
	resumeEvents := make(chan session.SessionEvent, 16)
	if _, err := m.EnsureActive(ctx, s, resumeEvents); err != nil {
		t.Fatal(err)
	}
	close(resumeEvents)
	resumedEvent := false
	for ev := range resumeEvents {
		if ev.Type == session.EventSessionResumed {
			resumedEvent = true
		}
		if ev.Type == session.EventSessionStarted {
			t.Fatal("native human conversation cold-started")
		}
	}
	if !resumedEvent {
		t.Fatal("no native resume was performed")
	}
	resumed, _ := m.NativeID(s.InstanceID)
	if resumed != original {
		t.Fatal("native human exchange cold-started on wake")
	}
}
