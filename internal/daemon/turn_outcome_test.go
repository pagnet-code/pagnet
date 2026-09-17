package daemon

// D4: the persistent turn path must mirror the legacy process-per-turn
// error taxonomy EXACTLY. The supervisor's operational errors keep their
// distinct semantics instead of being collapsed into a generic
// process_error — collapsing them would brick the instance on an ordinary
// daemon restart mid-turn (ErrShuttingDown) or hide the host protecting
// itself (ErrHostPressure / ErrLimitRefused).
//
// This is a focused test of the PURE classification (classifyTurnError),
// which the persistent path (runTurnPersistent) applies to the settled
// turn's (submitErr, completed, sessionLost, failedKind).

import (
	"context"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/internal/proc"
)

func TestClassifyTurnError_Taxonomy(t *testing.T) {
	tests := []struct {
		name        string
		submitErr   error
		completed   bool
		sessionLost bool
		failedKind  string
		wantOutcome turnOutcome
		wantKind    launchRefusedKind
	}{
		{
			name:        "session lost blocks the instance",
			submitErr:   nil,
			completed:   false,
			sessionLost: true,
			wantOutcome: outcomeSessionLost,
		},
		{
			name:        "runtime turn failure (rate_limited) is a turn failure",
			submitErr:   nil,
			completed:   false,
			failedKind:  "rate_limited",
			wantOutcome: outcomeTurnFailed,
		},
		{
			name:        "shutdown cancel: no failure, work stays queued",
			submitErr:   context.Canceled,
			completed:   false,
			wantOutcome: outcomeNoFailureQueued,
		},
		{
			name:        "supervisor shutting down: NO failure, work stays queued",
			submitErr:   proc.ErrShuttingDown,
			completed:   false,
			wantOutcome: outcomeNoFailureQueued,
		},
		{
			name:        "instance busy: deferred (stays queued, not acked)",
			submitErr:   proc.ErrInstanceBusy,
			completed:   false,
			wantOutcome: outcomeDeferred,
		},
		{
			name:        "host pressure: its OWN operational kind",
			submitErr:   proc.ErrHostPressure,
			completed:   false,
			wantOutcome: outcomeLaunchRefused,
			wantKind:    kindHostPressure,
		},
		{
			name:        "limit refused: its OWN operational kind",
			submitErr:   proc.ErrLimitRefused,
			completed:   false,
			wantOutcome: outcomeLaunchRefused,
			wantKind:    kindLimitRefused,
		},
		{
			name:        "generic driver error: process_error",
			submitErr:   errors.New("spawn failed"),
			completed:   false,
			wantOutcome: outcomeProcessError,
		},
		{
			name:        "cut off between events: no failure, work stays queued",
			submitErr:   nil,
			completed:   false,
			wantOutcome: outcomeNoFailureQueued,
		},
		{
			name:        "completed: the instance settles",
			submitErr:   nil,
			completed:   true,
			wantOutcome: outcomeCompleted,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOutcome, gotKind := classifyTurnError(tt.submitErr, tt.completed, tt.sessionLost, tt.failedKind)
			if gotOutcome != tt.wantOutcome {
				t.Fatalf("outcome = %v, want %v (err=%v)", gotOutcome, tt.wantOutcome, tt.submitErr)
			}
			if gotKind != tt.wantKind {
				t.Fatalf("refused kind = %q, want %q", gotKind, tt.wantKind)
			}
		})
	}
}

// TestClassifyTurnError_OperationalNotProcessError is the regression the
// D4 fix guards: the supervisor's operational errors must NEVER be
// classified as a generic process_error (which would mark the instance
// failed). Before the fix, runTurnPersistent collapsed every non-nil
// submitErr into process_error.
func TestClassifyTurnError_OperationalNotProcessError(t *testing.T) {
	for _, err := range []error{
		proc.ErrShuttingDown,
		proc.ErrInstanceBusy,
		proc.ErrHostPressure,
		proc.ErrLimitRefused,
		context.Canceled,
	} {
		outcome, _ := classifyTurnError(err, false, false, "")
		if outcome == outcomeProcessError {
			t.Fatalf("%v classified as process_error (would brick the instance); want a distinct operational outcome", err)
		}
	}
}
