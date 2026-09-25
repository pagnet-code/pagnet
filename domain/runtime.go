package domain

import (
	"context"
	"go.opentelemetry.io/otel/trace"
	"time"
)

// traceSpan returns the span from ctx (noop-safe).
func traceSpan(ctx context.Context) trace.Span { return trace.SpanFromContext(ctx) }

// RuntimeSessionState is the lifecycle of a resumable runtime session.
type RuntimeSessionState string

const (
	RuntimeSessionNew        RuntimeSessionState = "new"
	RuntimeSessionActive     RuntimeSessionState = "active"
	RuntimeSessionHibernated RuntimeSessionState = "hibernated"
	RuntimeSessionInvalid    RuntimeSessionState = "invalid" // resume failed; needs human decision
	RuntimeSessionLost       RuntimeSessionState = "lost"    // runtime reports it no longer exists
)

// RuntimeSession persists the runtime-native session identity so the daemon
// can resume conversations on subsequent turns. A session is initially
// pinned to (host, workspace); waking happens on that host with that
// workspace. Cross-host migration is a future feature. The central server
// stores only the session id + resume metadata — never the session content
// (which may contain sensitive material).
type RuntimeSession struct {
	ID         ID
	InstanceID ID
	Runtime    RuntimeName
	// SessionID is the runtime-native (external) session id used for resume.
	SessionID            string
	HostID               *ID
	WorkspaceID          *ID
	Model                string
	ResumeSupported      bool
	State                RuntimeSessionState
	Metadata             map[string]any // RuntimeMetadata: runtime-specific, generic bag
	CreatedAt            time.Time
	UpdatedAt            time.Time
	LastUsedAt           *time.Time
	LastSuccessfulTurnAt *time.Time
}

// RuntimeFailureKind classifies runtime failures. NOT every CLI failure is
// "failed": rate limits and auth issues are availability states with their
// own recovery semantics.
type RuntimeFailureKind string

const (
	RuntimeFailureRateLimited     RuntimeFailureKind = "rate_limited"
	RuntimeFailureQuotaExhausted  RuntimeFailureKind = "quota_exhausted"
	RuntimeFailureAuthRequired    RuntimeFailureKind = "auth_required"
	RuntimeFailureContextLimit    RuntimeFailureKind = "context_limit"
	RuntimeFailureNetworkError    RuntimeFailureKind = "network_error"
	RuntimeFailureProcessError    RuntimeFailureKind = "process_error"
	RuntimeFailurePermissionError RuntimeFailureKind = "permission_error"
	RuntimeFailureUnknown         RuntimeFailureKind = "unknown"
	// RuntimeFailureInterrupted: the runtime ACCEPTED the turn and its
	// endpoint died before a terminal result — the outcome may be
	// partially applied. It is an availability state, not a terminal
	// failure: the session and workspace are preserved, the work stays
	// queued, and an explicit human retry is the only re-run path (it is
	// never automatically re-delivered).
	RuntimeFailureInterrupted RuntimeFailureKind = "interrupted"
)

// RuntimeFailure is a classified runtime failure. RetryAt is set ONLY when
// the runtime/provider supplied a reliable recovery time; otherwise it must
// be nil and the state must honestly report "recovery time unknown".
type RuntimeFailure struct {
	Kind      RuntimeFailureKind
	Retryable bool
	RetryAt   *time.Time
	Message   string
	Metadata  map[string]any
}

// RuntimeTurn records one executed turn of a managed runtime.
type RuntimeTurn struct {
	ID           ID
	InstanceID   ID
	SessionID    string
	InputKind    string // user | network_ask | network_task | network_notice | network_status
	InputSummary string
	Status       string // running | completed | failed
	Error        string
	StartedAt    time.Time
	EndedAt      *time.Time
	InputTokens  *int
	OutputTokens *int
	CachedTokens *int
	Model        string
	DurationMS   *int64
	Metadata     map[string]any
}

// RuntimeMetadata is the generic bag for runtime-specific information that
// must be preserved (e.g. a runtime's session state or hook state). Core
// domain entities never gain runtime-specific fields; adapters write here.
type RuntimeMetadata = map[string]any
