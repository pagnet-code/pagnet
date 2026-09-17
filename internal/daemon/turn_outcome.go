package daemon

import (
	"context"
	"errors"

	"github.com/pagnet-code/pagnet/internal/proc"
)

// turnOutcome is the DECISION for a settled turn: what the daemon does with
// it. The side effects (send the failure event, set the instance status,
// roll back the claimed session) are applied by the caller based on the
// outcome. This is a PURE classification (no side effects) so the
// supervisor error taxonomy can be tested in isolation.
//
// It exists so the PERSISTENT turn path (runTurnPersistent) mirrors the
// legacy process-per-turn path's error taxonomy EXACTLY (D4): the
// supervisor's operational errors (ErrShuttingDown / ErrInstanceBusy /
// ErrHostPressure / ErrLimitRefused) must keep their distinct semantics
// instead of being collapsed into a generic process_error — collapsing them
// would brick the instance on an ordinary daemon restart mid-turn.
type turnOutcome int

const (
	// outcomeCompleted: the turn completed; the instance settles (idle for
	// the persistent path).
	outcomeCompleted turnOutcome = iota
	// outcomeNoFailureQueued: no failure recorded; the work stays queued for
	// the control plane's re-send (a shutdown cancel, a supervisor shutdown
	// refusal, or a turn cut off between events). The claimed session is
	// rolled back.
	outcomeNoFailureQueued
	// outcomeDeferred: the command cannot run now but must stay queued (the
	// instance is busy). Not acked.
	outcomeDeferred
	// outcomeLaunchRefused: a pagnet-owned safety ceiling or host pressure
	// refused the launch — a clean OPERATIONAL condition, not a runtime
	// failure. Reported with its distinct kind.
	outcomeLaunchRefused
	// outcomeProcessError: an adapter/driver-level failure (spawn/IO); no
	// turn events were produced.
	outcomeProcessError
	// outcomeSessionLost: the resume failed; the instance is blocked until a
	// human explicitly restarts.
	outcomeSessionLost
	// outcomeTurnFailed: the turn failed at the runtime level (rate_limited,
	// auth_required, ...).
	outcomeTurnFailed
)

// launchRefusedKind is the operational kind reported for a launch refusal
// (outcomeLaunchRefused). The distinct kind lets the control plane and the
// operator see the host protecting itself.
type launchRefusedKind string

const (
	kindHostPressure launchRefusedKind = "host_resource_pressure"
	kindLimitRefused launchRefusedKind = "runtime_launch_refused"
)

// classifyTurnError maps a settled turn's (submitErr, completed,
// sessionLost, failedKind) to an outcome. It is a PURE function (no side
// effects) so the mapping can be tested in isolation. The order of the
// cases mirrors the legacy process-per-turn path exactly:
//
//	sessionLost → turnFailed → shutdown-cancel → supervisor-shutdown →
//	busy-defer → host-pressure → limit-refused → process-error →
//	no-completion → completed.
func classifyTurnError(submitErr error, completed, sessionLost bool, failedKind string) (turnOutcome, launchRefusedKind) {
	switch {
	case sessionLost:
		return outcomeSessionLost, ""
	case failedKind != "":
		return outcomeTurnFailed, ""
	case errors.Is(submitErr, context.Canceled):
		// Daemon shutdown mid-turn: NOT an instance failure; the work stays
		// queued for the re-send.
		return outcomeNoFailureQueued, ""
	case errors.Is(submitErr, proc.ErrShuttingDown):
		// The supervisor is shutting down and refused the launch. Same
		// semantics as a shutdown cancel: no failure recorded, work stays
		// queued (a daemon restart mid-turn must not brick the instance).
		return outcomeNoFailureQueued, ""
	case errors.Is(submitErr, proc.ErrInstanceBusy):
		// Defense-in-depth: the session core serializes prompt turns, but if
		// the supervisor sees a live endpoint, defer — the command stays
		// queued and is re-sent.
		return outcomeDeferred, ""
	case errors.Is(submitErr, proc.ErrHostPressure):
		// A host process-pressure refusal: a clean operational condition,
		// reported with its OWN kind (never collapsed into process_error).
		return outcomeLaunchRefused, kindHostPressure
	case errors.Is(submitErr, proc.ErrLimitRefused):
		// A pagnet-owned safety ceiling (active turns, owned processes,
		// circuit) refused the launch: a clean operational condition,
		// reported with its OWN kind.
		return outcomeLaunchRefused, kindLimitRefused
	case submitErr != nil:
		// Adapter/driver-level failure (spawn/IO), no turn events produced.
		return outcomeProcessError, ""
	case !completed:
		// The turn produced neither a completion nor a failure event (the
		// endpoint was cut off between events). The turn consumed no work:
		// roll back the claimed session, record no failure, keep the work
		// queued.
		return outcomeNoFailureQueued, ""
	default:
		return outcomeCompleted, ""
	}
}
