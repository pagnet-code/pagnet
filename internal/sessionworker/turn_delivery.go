package sessionworker

import (
	"fmt"

	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// This is the actual session.SubmitRequest input classification, copied from
// the original accepted operation. Empty legacy sources are never relabelled.
func ValidNativeInputKind(kind string) bool {
	switch kind {
	case "task", "ask", "notice", "status", "wake", "user_input":
		return true
	default:
		return false
	}
}

// NativeSourceType decides eligibility before allocating a durable sequence.
// A human turn or an unsupported old capture cannot create a stream gap.
func NativeSourceType(o NativeObservation) string {
	if typ := LifecycleSourceType(o.Event.Type); typ != "" {
		return typ
	}
	var typ string
	switch o.Event.Type {
	case session.EventTurnStarted:
		typ = transport.MsgRuntimeTurnStarted
	case session.EventTurnCompleted:
		typ = transport.MsgRuntimeTurnCompleted
	case session.EventTurnFailed:
		typ = transport.MsgRuntimeTurnFailed
	default:
		return ""
	}
	source := o.TurnSource
	if source == nil || o.SourceUnavailable || source.Sequence <= 0 || source.LogicalTurnID != fmt.Sprintf("pagnet-worker-turn-%d", source.Sequence) || source.LogicalTurnID != o.Event.TurnID || source.NativeGeneration != o.NativeGeneration || source.NativeSessionID != o.NativeSessionID || source.NativeSessionID != o.Event.SessionID || source.SourceCommandID == "" || source.SourceAdmissionID == "" || !ValidNativeInputKind(source.InputKind) {
		return ""
	}
	return typ
}
