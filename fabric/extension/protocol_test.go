package extension

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDecisionControlsNeverAmbiguous(t *testing.T) {
	now := time.Now()
	req := interceptRequest()
	valid := []Decision{{Action: Continue}, {Action: Modify, Patch: json.RawMessage(`[{"op":"add","path":"/payload/a","value":1}]`)}, {Action: Respond, Response: json.RawMessage(`{"cached":true}`)}, {Action: Defer, Deferral: &Deferral{ExpiresAt: now.Add(time.Hour), ResumePrincipals: []string{"approval-user"}, Durable: true}}}
	for _, d := range valid {
		if err := ValidateDecision(req, d, false, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateDecision(req, Decision{Action: Continue, Response: json.RawMessage(`{}`)}, false, now); err == nil {
		t.Fatal("ambiguous continue")
	}
	for _, d := range valid[2:] {
		if err := ValidateDecision(req, d, true, now); err == nil {
			t.Fatal("response started control accepted")
		}
	}
	req.Phase = PhaseChunk
	if err := ValidateDecision(req, valid[3], false, now); err == nil {
		t.Fatal("chunk deferred")
	}
	req = interceptRequest()
	req.Operation = "discover"
	if err := ValidateDecision(req, valid[3], false, now); err == nil {
		t.Fatal("read operation created continuation")
	}
}
