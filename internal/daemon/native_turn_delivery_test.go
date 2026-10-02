package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeTurnWirePreservesOriginalAcceptedSourceWithoutProtectedBody(t *testing.T) {
	_, o := deliveryFixture(t, nil)
	o.SourceSequence = 7
	o.Event = session.SessionEvent{Type: session.EventTurnFailed, SessionID: o.NativeSessionID, TurnID: "pagnet-worker-turn-11", Error: "private native error body", Output: "private result body", FailureKind: "rate_limited", Model: "private model label"}
	originalRetry := "2026-10-02T10:00:00.123Z"
	o.Event.RetryAt = &originalRetry
	tokens := 42
	o.Event.OutputTokens = &tokens
	o.TurnSource = &sessionworker.NativeTurnSource{Sequence: 11, LogicalTurnID: o.Event.TurnID, NativeGeneration: o.NativeGeneration, NativeSessionID: o.NativeSessionID, SourceCommandID: "original-command-A", SourceAdmissionID: "original-admission-A", InputKind: "task"}
	a, err := NativeWorkerWireObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NativeWorkerWireObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	var parsed transport.NativeTurnSourcePayload
	if json.Unmarshal(a.Payload, &parsed) != nil || parsed.SourceAdmissionID != "original-admission-A" || parsed.SourceCommandID != "original-command-A" || parsed.SourceSequence != 7 || parsed.NativeTurnSequence != 11 || parsed.InputKind != "task" || parsed.Kind != "rate_limited" || parsed.RetryAt != originalRetry || parsed.OutputTokens == nil || *parsed.OutputTokens != 42 {
		t.Fatal("turn source metadata was rewritten")
	}
	if a.Digest != b.Digest || !bytes.Equal(a.Payload, b.Payload) {
		t.Fatal("turn retry changed immutable wire commitment")
	}
	for _, private := range []string{"private native error body", "private result body", "private model label", "taskId", "turnId", "inputSummary"} {
		if bytes.Contains(a.Payload, []byte(private)) {
			t.Fatal("protected/caller-selected turn fields entered server payload")
		}
	}
	o.Event.FailureKind = "private vendor failure sentence"
	badRetry := "2026-10-02T10:00:00+01:00"
	o.Event.RetryAt = &badRetry
	a, err = NativeWorkerWireObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(a.Payload, []byte("private vendor")) || bytes.Contains(a.Payload, []byte("retryAt")) {
		t.Fatal("unclassified failure body or guessed retry escaped")
	}
	o.SourceUnavailable = true
	if _, err = NativeWorkerWireObservation(o); !errors.Is(err, ErrNativeSourceUnsupported) {
		t.Fatal("unbound turn synthesized an accepted source")
	}
}
