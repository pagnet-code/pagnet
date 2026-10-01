package runtime

import (
	"encoding/json"
	"github.com/pagnet-code/pagnet/internal/session"
	"strings"
	"testing"
)

func TestCodexPlanExactTurnAndSnapshot(t *testing.T) {
	s := newCodexTurnState(false, "")
	s.setThread("thread", "model")
	s.beginMachineTurn("logical")
	s.processTurnStarted("thread", codexTurn{ID: "native"})
	frames := []string{`{"turnId":"other","plan":[{"step":"wrong","status":"pending"}]}`, `{"turnId":"native","plan":[{"step":"invalid","status":"running"}]}`, `{"turnId":"native","plan":null}`, `{"turnId":"native","plan":[{"step":" ","status":"pending"}]}`}
	for _, frame := range frames {
		if ev := s.processNotification("turn/plan/updated", json.RawMessage(frame)); len(ev) != 0 {
			t.Fatalf("invalid frame produced plan: %s", frame)
		}
	}
	ev := s.processNotification("turn/plan/updated", json.RawMessage(`{"turnId":"native","plan":[{"step":"first","status":"inProgress"},{"step":"second","status":"pending"}]}`))
	if len(ev) != 1 || ev[0].Type != session.EventPlanUpdated || ev[0].SessionID != "thread" || ev[0].TurnID != "logical" || ev[0].Plan.Entries[0].Status != "in_progress" {
		t.Fatalf("wrong binding: %+v", ev)
	}
	empty := s.processNotification("turn/plan/updated", json.RawMessage(`{"turnId":"native","plan":[]}`))
	if len(empty) != 1 || len(empty[0].Plan.Entries) != 0 {
		t.Fatal("explicit empty snapshot lost")
	}
	s.clearMachineTurn()
	if ev := s.processNotification("turn/plan/updated", json.RawMessage(`{"turnId":"native","plan":[]}`)); len(ev) != 0 {
		t.Fatal("finished turn accepted a plan")
	}
}
func TestCodexPlanRejectsOversizeAndExternalTurns(t *testing.T) {
	s := newCodexTurnState(false, "")
	s.setThread("thread", "model")
	s.processTurnStarted("thread", codexTurn{ID: "human"})
	if ev := s.processNotification("turn/plan/updated", json.RawMessage(`{"turnId":"human","plan":[]}`)); len(ev) != 0 {
		t.Fatal("external plan attributed to task")
	}
	s.beginMachineTurn("logical")
	s.processTurnStarted("thread", codexTurn{ID: "native"})
	raw, _ := json.Marshal(map[string]any{"turnId": "native", "plan": []map[string]string{{"step": strings.Repeat("a", session.MaxPlanBytes), "status": "pending"}}})
	if ev := s.processNotification("turn/plan/updated", raw); len(ev) != 0 {
		t.Fatal("oversized plan accepted")
	}
}
