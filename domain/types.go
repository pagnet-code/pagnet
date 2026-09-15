package domain

import "errors"

// ResourceKind classifies a logical Resource.
type ResourceKind string

const (
	ResourceKindGitRepository ResourceKind = "git_repository"
	ResourceKindDomain        ResourceKind = "domain"
	ResourceKindService       ResourceKind = "service"
	ResourceKindStandard      ResourceKind = "standard"
	ResourceKindGeneric       ResourceKind = "generic"
)

func (k ResourceKind) Valid() bool {
	switch k {
	case ResourceKindGitRepository, ResourceKindDomain, ResourceKindService, ResourceKindStandard, ResourceKindGeneric:
		return true
	}
	return false
}

// HostStatus is the observed lifecycle state of a host.
type HostStatus string

const (
	HostStatusOnline   HostStatus = "online"
	HostStatusOffline  HostStatus = "offline"
	HostStatusDegraded HostStatus = "degraded"
	HostStatusRevoked  HostStatus = "revoked"
)

func (s HostStatus) Valid() bool {
	switch s {
	case HostStatusOnline, HostStatusOffline, HostStatusDegraded, HostStatusRevoked:
		return true
	}
	return false
}

// AgentStatus is the lifecycle state of an Agent Instance.
//
// A hibernated instance is HEALTHY: its runtime process is intentionally
// gone, its session is preserved, and it is wakeable. Never treat it as a
// failure. Hibernated ≠ offline: offline means the host is unreachable.
type AgentStatus string

const (
	AgentStatusStarting     AgentStatus = "starting"
	AgentStatusIdle         AgentStatus = "idle"
	AgentStatusWorking      AgentStatus = "working"
	AgentStatusHibernating  AgentStatus = "hibernating"
	AgentStatusHibernated   AgentStatus = "hibernated"
	AgentStatusWaking       AgentStatus = "waking"
	AgentStatusRateLimited  AgentStatus = "rate_limited"
	AgentStatusAuthRequired AgentStatus = "auth_required"
	AgentStatusBlocked      AgentStatus = "blocked"
	AgentStatusStopping     AgentStatus = "stopping"
	AgentStatusStopped      AgentStatus = "stopped"
	AgentStatusFailed       AgentStatus = "failed"
	AgentStatusUnreachable  AgentStatus = "unreachable"
)

func (s AgentStatus) Valid() bool {
	switch s {
	case AgentStatusStarting, AgentStatusIdle, AgentStatusWorking,
		AgentStatusHibernating, AgentStatusHibernated, AgentStatusWaking,
		AgentStatusRateLimited, AgentStatusAuthRequired, AgentStatusBlocked,
		AgentStatusStopping, AgentStatusStopped, AgentStatusFailed, AgentStatusUnreachable:
		return true
	}
	return false
}

// Active reports whether the instance is usable for routing (online and not
// stopped). Hibernated instances are wakeable candidates, not failures.
func (s AgentStatus) Active() bool {
	return s == AgentStatusIdle || s == AgentStatusWorking || s == AgentStatusBlocked ||
		s == AgentStatusStarting || s == AgentStatusHibernated || s == AgentStatusWaking
}

// Availability is the externally-facing availability of an instance,
// derived from status + host liveness + resumable session.
type AgentAvailability string

const (
	AvailAvailable      AgentAvailability = "available" // idle, process up
	AvailWakeable       AgentAvailability = "wakeable"  // hibernated, session resumable, host online
	AvailWorking        AgentAvailability = "working"   // busy but queueable
	AvailRateLimited    AgentAvailability = "rate_limited"
	AvailAuthRequired   AgentAvailability = "auth_required"
	AvailWaitingForHost AgentAvailability = "waiting_for_host"
	AvailUnavailable    AgentAvailability = "unavailable" // stopped/failed
	AvailOffline        AgentAvailability = "offline"     // host unreachable
)

// Availability derives routing/discovery availability.
func (s AgentStatus) Availability(hostOnline, sessionResumable bool) AgentAvailability {
	if s == AgentStatusUnreachable || !hostOnline {
		if s == AgentStatusHibernated || s == AgentStatusWaking {
			return AvailWaitingForHost
		}
		return AvailOffline
	}
	switch s {
	case AgentStatusIdle, AgentStatusStarting:
		return AvailAvailable
	case AgentStatusHibernated:
		if sessionResumable {
			return AvailWakeable
		}
		return AvailUnavailable
	case AgentStatusWorking, AgentStatusWaking, AgentStatusBlocked:
		return AvailWorking
	case AgentStatusRateLimited:
		return AvailRateLimited
	case AgentStatusAuthRequired:
		return AvailAuthRequired
	default:
		return AvailUnavailable
	}
}

// AgentKind distinguishes worker agents (single-network) from
// representatives (tenant/user-scoped, multi-network via grants) and system
// agents.
type AgentKind string

const (
	AgentKindWorker         AgentKind = "worker"
	AgentKindRepresentative AgentKind = "representative"
	AgentKindSystem         AgentKind = "system"
)

func (k AgentKind) Valid() bool {
	return k == AgentKindWorker || k == AgentKindRepresentative || k == AgentKindSystem
}

// Channel permission levels for representative_network_grants.
// Effective authority is always: human access ∩ representative grant.
const (
	PermObserve     = "observe"     // read agents/tasks/status/messages/history
	PermCommunicate = "communicate" // ask/reply/message agents
	PermDelegate    = "delegate"    // create/delegate tasks
	PermOperate     = "operate"     // launch/wake/stop/restart agents
)

// GrantPermissions is the default full grant set.
var GrantPermissions = []string{PermObserve, PermCommunicate, PermDelegate, PermOperate}

func HasPermission(perms []string, p string) bool {
	for _, x := range perms {
		if x == p {
			return true
		}
	}
	return false
}

// Wake reasons.
const (
	WakeReasonMessage       = "message"
	WakeReasonTask          = "task"
	WakeReasonHumanInput    = "human_input"
	WakeReasonAttach        = "attach"
	WakeReasonExplicit      = "explicit"
	WakeReasonScheduleRetry = "schedule_retry"
	WakeReasonWorkQueued    = "work_queued"
	WakeReasonManualRetry   = "manual_retry" // human "Retry now" (§46)
)

// TaskStatus is the lifecycle state of a Task.
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusOffered   TaskStatus = "offered"
	TaskStatusAccepted  TaskStatus = "accepted"
	TaskStatusWorking   TaskStatus = "working"
	TaskStatusBlocked   TaskStatus = "blocked"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCancelled TaskStatus = "cancelled"
)

func (s TaskStatus) Valid() bool {
	switch s {
	case TaskStatusPending, TaskStatusOffered, TaskStatusAccepted, TaskStatusWorking,
		TaskStatusBlocked, TaskStatusCompleted, TaskStatusFailed, TaskStatusCancelled:
		return true
	}
	return false
}

// Terminal reports whether no further transitions are possible.
func (s TaskStatus) Terminal() bool {
	return s == TaskStatusCompleted || s == TaskStatusFailed || s == TaskStatusCancelled
}

// CanTransitionTo encodes the task state machine.
func (s TaskStatus) CanTransitionTo(t TaskStatus) bool {
	switch s {
	case TaskStatusPending:
		return t == TaskStatusOffered || t == TaskStatusCancelled
	case TaskStatusOffered:
		return t == TaskStatusAccepted || t == TaskStatusPending || t == TaskStatusCancelled
	case TaskStatusAccepted:
		return t == TaskStatusWorking || t == TaskStatusBlocked || t == TaskStatusCancelled
	case TaskStatusWorking:
		return t == TaskStatusBlocked || t == TaskStatusCompleted || t == TaskStatusFailed
	case TaskStatusBlocked:
		return t == TaskStatusWorking || t == TaskStatusCancelled
	}
	return false
}

// MessageKind classifies durable network messages.
type MessageKind string

const (
	MessageKindAsk    MessageKind = "ASK"
	MessageKindReply  MessageKind = "REPLY"
	MessageKindNotice MessageKind = "NOTICE"
	MessageKindStatus MessageKind = "STATUS"
)

func (k MessageKind) Valid() bool {
	switch k {
	case MessageKindAsk, MessageKindReply, MessageKindNotice, MessageKindStatus:
		return true
	}
	return false
}

// ClaimScopeType classifies what a Claim owns.
type ClaimScopeType string

const (
	ClaimScopeTask     ClaimScopeType = "task"
	ClaimScopeResource ClaimScopeType = "resource"
	ClaimScopePath     ClaimScopeType = "path"
	ClaimScopeIssue    ClaimScopeType = "issue"
)

func (t ClaimScopeType) Valid() bool {
	switch t {
	case ClaimScopeTask, ClaimScopeResource, ClaimScopePath, ClaimScopeIssue:
		return true
	}
	return false
}

// ArtifactType classifies published artifacts.
type ArtifactType string

const (
	ArtifactPullRequest ArtifactType = "pull_request"
	ArtifactCommit      ArtifactType = "commit"
	ArtifactPackage     ArtifactType = "package"
	ArtifactTestReport  ArtifactType = "test_report"
	ArtifactDocument    ArtifactType = "document"
	ArtifactFile        ArtifactType = "file"
	ArtifactJSON        ArtifactType = "json"
	ArtifactOther       ArtifactType = "other"
)

// RuntimeName identifies an agent runtime.
type RuntimeName string

const (
	RuntimeClaudeCode RuntimeName = "claude-code"
	RuntimeQwenCode   RuntimeName = "qwen-code"
	RuntimeOpenCode   RuntimeName = "opencode"
	RuntimeGeneric    RuntimeName = "generic"
	RuntimeFake       RuntimeName = "fake"
)

// Short aliases accepted in CLI/config (e.g. --runtime qwen).
var runtimeAliases = map[string]RuntimeName{
	"claude":   RuntimeClaudeCode,
	"qwen":     RuntimeQwenCode,
	"opencode": RuntimeOpenCode,
	"generic":  RuntimeGeneric,
	"fake":     RuntimeFake,
}

// CanonicalRuntime resolves aliases to canonical runtime names.
func CanonicalRuntime(name string) RuntimeName {
	if r, ok := runtimeAliases[name]; ok {
		return r
	}
	return RuntimeName(name)
}

// Capabilities are routing metadata (v1: not a permission system).
const (
	CapAnswer      = "answer"
	CapAnalyze     = "analyze"
	CapImplement   = "implement"
	CapTest        = "test"
	CapReview      = "review"
	CapRelease     = "release"
	CapStandardize = "standardize"
	CapCoordinate  = "coordinate"
	CapDelegate    = "delegate"
)

// Event types. pagnet Events are domain observations of the agent network;
// OpenTelemetry handles infrastructure telemetry separately.
const (
	EventNetworkCreated = "network.created"

	EventHostRegistered   = "host.registered"
	EventHostConnected    = "host.connected"
	EventHostDisconnected = "host.disconnected"
	EventHostHeartbeat    = "host.heartbeat"
	EventHostRevoked      = "host.revoked"
	EventHostDeleted      = "host.deleted"

	EventWorkspaceRegistered = "workspace.registered"

	EventAgentCreated = "agent.created"
	EventAgentStarted = "agent.started"
	EventAgentIdle    = "agent.idle"
	EventAgentWorking = "agent.working"
	EventAgentStopped = "agent.stopped"
	EventAgentFailed  = "agent.failed"

	EventMessageSent      = "message.sent"
	EventMessageDelivered = "message.delivered"
	EventMessageReplied   = "message.replied"

	EventTaskCreated   = "task.created"
	EventTaskOffered   = "task.offered"
	EventTaskAccepted  = "task.accepted"
	EventTaskStarted   = "task.started"
	EventTaskBlocked   = "task.blocked"
	EventTaskCompleted = "task.completed"
	EventTaskFailed    = "task.failed"
	EventTaskCancelled = "task.cancelled"

	EventClaimCreated  = "claim.created"
	EventClaimExpired  = "claim.expired"
	EventClaimReleased = "claim.released"

	EventArtifactPublished = "artifact.published"

	// Generic, runtime-neutral events. Runtime-specific details stay in the
	// adapter layer and in RuntimeMetadata; names must never become
	// runtime-specific. Tool-level events (runtime.tool.*) are reserved for
	// optional future plugin enrichment and are NOT emitted today.
	EventRuntimeSessionCreated = "runtime.session.created"
	EventRuntimeSessionResumed = "runtime.session.resumed"
	EventRuntimeSessionInvalid = "runtime.session.invalid"
	EventRuntimeTurnStarted    = "runtime.turn.started"
	EventRuntimeTurnCompleted  = "runtime.turn.completed"
	EventRuntimeTurnFailed     = "runtime.turn.failed"
	EventRuntimeRateLimited    = "runtime.rate_limited"
	EventRuntimeAvailable      = "runtime.available"

	// Wake / hibernation lifecycle.
	EventAgentWakeRequested = "agent.wake.requested"
	EventAgentWoken         = "agent.woken"
	EventAgentHibernated    = "agent.hibernated"

	// Work queuing (durable delivery precedes wake).
	EventWorkQueued              = "work.queued"
	EventWorkWaitingForHost      = "work.waiting_for_host"
	EventWorkWaitingForCapacity  = "work.waiting_for_capacity"
	EventWorkWaitingForPlacement = "work.waiting_for_placement"

	// External channels + representatives.
	EventChannelMessageReceived        = "channel.message.received"
	EventChannelMessageSent            = "channel.message.sent"
	EventChannelBindingCreated         = "channel.binding.created"
	EventRepresentativeWoken           = "representative.woken"
	EventRepresentativeNetworkSwitched = "representative.network.switched"

	// User notifications (Phase 6): pushed on the SSE stream when a
	// notification row is created, so the web badge updates live.
	EventNotificationCreated = "notification.created"

	// Private Network E2EE lifecycle (Phase 8, plan §11.6/§11.7/§11.8).
	// These are domain observations of the crypto lifecycle; the key material
	// itself never crosses to the control plane (the events carry routing
	// metadata only — host/epoch ids, never keys or ciphertext).
	EventNetworkPrivacyActivated     = "network.privacy_activated"
	EventNetworkCryptoRotated        = "network.crypto_rotated"
	EventNetworkCryptoRotationFailed = "network.crypto_rotation_failed"
	EventHostCryptoReady             = "host.crypto_ready"
	EventHostCryptoEnrollmentFailed  = "host.crypto_enrollment_failed"
)

// Actor types for events.
const (
	ActorUser   = "user"
	ActorHost   = "host"
	ActorAgent  = "agent_instance"
	ActorSystem = "system"
)

// ErrInvalidTransition is returned when a task status change violates the
// task state machine.
var ErrInvalidTransition = errors.New("invalid task status transition")

// ErrReasonRequired is returned when a status that carries evidence
// (blocked/completed/failed) is set without a reason (spec §18).
var ErrReasonRequired = errors.New("a reason is required for this status change")

// ErrorIsInvalidTransition reports whether err wraps ErrInvalidTransition.
func ErrorIsInvalidTransition(err error) bool { return errors.Is(err, ErrInvalidTransition) }
