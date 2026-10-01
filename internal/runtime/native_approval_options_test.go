package runtime

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCodexNativeApprovalAllowlistDoesNotGuess(t *testing.T) {
	method := "item/commandExecution/requestApproval"
	params := json.RawMessage(`{"command":"private shell command","availableDecisions":["decline",{"acceptWithExecpolicyAmendment":{"execpolicy_amendment":["secret"]}}]}`)
	options := codexApprovalOptions(method, params)
	if len(options) != 1 || options[0].ID != "decline" || options[0].Kind != "reject_once" {
		t.Fatalf("unexpected options %+v", options)
	}
	state := newCodexTurnState(false, "")
	state.setThread("thread", "")
	state.processServerRequest("3", method, params)
	if _, _, found := state.resolveInteraction("3", "resolved", "accept"); found {
		t.Fatal("unadvertised approval accepted")
	}
	result, _, found := state.resolveInteraction("3", "resolved", "decline")
	if !found || string(result) != `{"decision":"decline"}` {
		t.Fatalf("valid refusal lost after invalid choice: %s %v", result, found)
	}
	for _, raw := range []string{`{"availableDecisions":[]}`, `{"availableDecisions":null}`, `{"availableDecisions":"accept"}`} {
		if len(codexApprovalOptions(method, json.RawMessage(raw))) != 0 {
			t.Fatalf("invented options for %s", raw)
		}
	}
	_, summary := classifyCodexServerRequest(method, params)
	if strings.Contains(summary, "private") || strings.Contains(summary, "shell") {
		t.Fatal("private tool content in public summary")
	}
}
