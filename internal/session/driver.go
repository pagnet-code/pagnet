package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/pagnet-code/pagnet/domain"
)

// ErrNotMaterialised is returned by Activate when a resume is requested for
// a session that has never had a real exchange. A started-but-unmaterialised
// session has nothing durable to resume (Codex thread/start persists
// nothing; Hermes DB rows appear on first prompt) — offering "resume"
// before that would advertise a session that cannot be resumed. The caller
// must treat this as an honest refusal, NOT as a signal to start a fresh
// session silently.
var ErrNotMaterialised = errors.New("session not materialised: no resume before the first exchange")

// ErrSessionLost is returned by Activate when a resume was requested but no
// usable native session existed (the vendor's "no rollout" / "no saved
// session" condition). The Manager maps it to EventSessionLost and the
// StateLost lifecycle — never a silent fresh session (addendum invariant F).
var ErrSessionLost = errors.New("session lost: no resumable native session")

// ErrBusy is returned by Submit when the session is busy and the requested
// BusyPolicy cannot be satisfied by this integration (e.g. steer requested
// but NativeSteer is false). The caller decides whether to queue or fail.
var ErrBusy = errors.New("session busy")

// ErrEndpointGone is returned by Submit when the session's endpoint is no
// longer live (it died after EnsureActive confirmed it live — a narrow
// window, or the endpoint record was already dropped by the driver's EOF
// path). It is DISTINCT from a runtime turn failure: the turn consumed no
// work, so the Manager re-activates (resuming the materialised session or
// cold-starting) and retries the submit once, instead of failing the
// instance. An endpoint death must never wedge the session or mark the
// instance failed.
var ErrEndpointGone = errors.New("session endpoint gone")

// Driver is the contract a persistent runtime integration implements. It is
// the generic replacement for the process-per-turn Adapter.StartTurn path:
// a Driver owns a LIVE endpoint per instance and services many logical
// submits through it.
//
// A Driver is stateful per instance (it owns the endpoint process handle),
// but the SESSION STATE (lifecycle phase, materialised flag, native id) is
// owned by the Manager, which calls the Driver. The Driver reads/writes the
// session's NativeID and Materialised fields as the native exchange
// happens; the Manager owns the State transitions and the resume gate.
//
// Concurrency contract: Submit calls for one session are serialized by the
// Manager's per-session submit lock EXCEPT interaction resolutions, which
// may be delivered while a prompt turn is in flight (the busy/idle +
// interaction round-trip). A Driver must therefore tolerate a
// SubmitInteraction arriving while a SubmitPrompt is blocked on a native
// interaction.
type Driver interface {
	// Name is the canonical runtime name.
	Name() domain.RuntimeName

	// Capabilities is the probed capability set for this integration.
	Capabilities() Capabilities

	// Activate starts (cold) or resumes the endpoint for the session and
	// returns the live endpoint. It is idempotent: when the endpoint is
	// already live it returns it unchanged.
	//
	// Resume gate (enforced by the Manager, mirrored here for standalone
	// use): a resume of a non-materialised session returns
	// ErrNotMaterialised; a resume with no usable native session returns
	// ErrSessionLost. On success the Driver sets sess.NativeID (minted on
	// cold start, restored on resume) and emits EventSessionStarted /
	// EventSessionResumed on the returned endpoint's event stream.
	//
	// The events channel (when non-nil) receives the activation events
	// (session.started / session.resumed / session.lost). The Driver sends
	// the events and returns when activation settles; it does NOT close
	// the channel — the caller owns its lifecycle (the Manager closes it
	// in the Submit path; a standalone caller closes it after Activate
	// returns).
	Activate(ctx context.Context, sess *RuntimeSession, events chan<- SessionEvent) (*RuntimeEndpoint, error)

	// Submit delivers one logical input (a prompt or an interaction
	// resolution) into the session's live endpoint and streams normalized
	// events into events until the submit settles. For a prompt, "settles"
	// is the turn's terminal event (completed / failed / session.lost);
	// for an interaction resolution, it is the acknowledgement that the
	// answer was delivered (the in-flight turn's own stream then carries
	// the interaction.resolved + terminal events).
	//
	// The Driver sends the events and returns when the submit settles; it
	// does NOT close the channel — the caller owns its lifecycle (the
	// Manager closes it). It returns an error only for delivery failures
	// (endpoint gone, busy refusal, ...); a turn that fails at the runtime
	// level is reported via EventTurnFailed, not an error.
	Submit(ctx context.Context, sess *RuntimeSession, req SubmitRequest, events chan<- SessionEvent) error

	// Hibernate stops the endpoint, PRESERVING the session (addendum
	// invariant F: stopping the endpoint must not delete the session).
	// After a successful hibernate the session is inactive but resumable
	// (iff materialised). It is a no-op when no endpoint is live.
	Hibernate(ctx context.Context, sess *RuntimeSession) error

	// Stop terminates the endpoint unconditionally (daemon shutdown,
	// explicit instance stop). Unlike Hibernate it does not promise the
	// session stays resumable (a hard kill may lose in-memory state the
	// runtime never persisted).
	Stop(instanceID string) error

	// PID is the endpoint's process id for the instance (nil when no
	// endpoint is live).
	PID(instanceID string) *int

	// Live reports whether the instance's endpoint process is still alive.
	// The Manager consults it before trusting a live session state: an
	// endpoint that died unexpectedly (crash, SIGKILL, OOM, a supervisor
	// explosion-kill) must not wedge the session — the next turn
	// transparently resumes the same session (when materialised) or cold-
	// starts it (when not). A Driver whose endpoint is not a local process
	// (an external service) reports liveness from its own health probe.
	Live(instanceID string) bool
}

// DriverName is the subset of Driver the daemon needs to route a turn to
// the persistent path (as opposed to the legacy process-per-turn
// Adapter.StartTurn path).
type DriverName interface {
	Name() domain.RuntimeName
}

// CapableDriver is a Driver that also reports its capabilities (all
// Drivers do; the split exists so the daemon's inventory code can query
// capabilities without the full Driver surface).
type CapableDriver interface {
	DriverName
	Capabilities() Capabilities
}

// ValidateSubmitRequest reports whether req is well-formed for its Kind.
// A prompt needs an Input; an interaction resolution needs an
// InteractionID and a Decision.
func ValidateSubmitRequest(req SubmitRequest) error {
	switch req.Kind {
	case SubmitPrompt:
		if req.Input == "" {
			return errors.New("session: prompt submit requires Input")
		}
	case SubmitInteraction:
		if req.InteractionID == "" {
			return errors.New("session: interaction submit requires InteractionID")
		}
		if req.Decision == "" {
			return errors.New("session: interaction submit requires Decision")
		}
	default:
		return fmt.Errorf("session: unknown submit kind %d", int(req.Kind))
	}
	return nil
}
