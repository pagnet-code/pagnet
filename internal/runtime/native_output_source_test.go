package runtime

import (
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/internal/session"
)

func TestOnlyGenuineNativeParserTextClaimsOutputSource(t *testing.T) {
	q, _ := newFixtureState(false, "")
	feedLines(t, q, validHandshakeLine(t, fixtureSID, fixtureCWD))
	q.beginMachineTurn("logical", "input")
	feedLines(t, q, userTextLine(t, fixtureSID, "input"))
	events := feedLines(t, q, streamDeltaLine(t, fixtureSID, "actual text"))
	if len(events) != 1 || !events[0].NativeOutput || events[0].Output != "actual text" {
		t.Fatal("genuine Qwen text not identified")
	}
	c := newCodexTurnState(false, "")
	c.setThread("thread", "model")
	c.beginMachineTurn("logical")
	c.processTurnStarted("thread", codexTurn{ID: "native"})
	events = c.processNotification("item/agentMessage/delta", json.RawMessage(`{"turnId":"native","delta":"actual text"}`))
	if len(events) != 1 || !events[0].NativeOutput || events[0].Output != "actual text" {
		t.Fatal("genuine Codex text not identified")
	}
	if events = c.processAgentMessageDelta("foreign", "text"); len(events) != 0 {
		t.Fatal("foreign text acquired original turn")
	}
	genuine := normalizePersist(persistWireEvent{Event: session.EventTurnOutput, Output: "actual text"})
	diagnostic := normalizePersist(persistWireEvent{Event: "future unknown event", Output: "diagnostic"})
	if !genuine.NativeOutput || diagnostic.NativeOutput {
		t.Fatal("fake diagnostic masqueraded as genuine native output")
	}
}
