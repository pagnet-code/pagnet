package domain

import (
	"encoding/json"
	"time"
)

// AgentExecutionMode selects how an agent's work is executed.
type AgentExecutionMode string

const (
	// ExecutionModeManaged: pagnet launches and supervises the runtime on
	// a host (the managed-agent model).
	ExecutionModeManaged AgentExecutionMode = "managed"
	// ExecutionModeExternal: the agent runs outside pagnet's hosts and
	// participates through its own endpoints (no pagnet runtime required).
	ExecutionModeExternal AgentExecutionMode = "external"
)

// Valid reports whether m is a known execution mode.
func (m AgentExecutionMode) Valid() bool {
	return m == ExecutionModeManaged || m == ExecutionModeExternal
}

// AgentDefinition is the agent-specific configuration bound to an agent
// principal. Canonical identity (name, description, ownership, visibility)
// lives on the Principal; network access lives on NetworkMembership; the
// capability surface lives on the capability descriptors + endpoints.
// Nothing here is network-scoped: one definition serves every network the
// principal is a member of.
type AgentDefinition struct {
	ID          ID
	PrincipalID ID
	// OwnerUserID is the user who owns the agent (personal agents); nil
	// for organization-owned agents.
	OwnerUserID   *ID
	ExecutionMode AgentExecutionMode
	// DefaultRuntime is the runtime for managed instances.
	DefaultRuntime RuntimeName
	// DefaultModel is the model for managed instances ("" = the runtime's
	// own default). A launch may override it per-launch.
	DefaultModel string
	// Mission is the optional INITIAL TASK for a launched agent
	// (north-star §15): it becomes the runtime's first turn — a real
	// user/turn message — on a fresh launch. A launch with no mission
	// establishes the runtime/session and idles; no first chat message is
	// fabricated. Editing it changes FUTURE launches — a running/resumed
	// session is untouched.
	Mission string
	// Instruction is the STANDING agent instruction: always-on context
	// defining who the agent is, unlike Mission (the optional one-shot
	// first turn). It is standing context, never a chat message: the
	// daemon folds it into the one managed standing document (with the
	// pagnet runtime/network overlay) that each runtime delivers through
	// its native surface — claude --append-system-prompt-file, qwen
	// --append-system-prompt, opencode's instance config — WITHOUT writing
	// into the user's workspace. "" = none.
	Instruction string
	// TemplateID is the agent template this definition was created from
	// (nil when created without a template).
	TemplateID *ID
	// ExecutionSettings: maxConcurrentTurns (default 1), transcript level
	// (metadata|network|full, default network), execution_policy
	// (cold|warm, default cold), etc.
	ExecutionSettings map[string]any
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// TranscriptLevel controls how much runtime output is persisted.
const (
	TranscriptMetadata = "metadata"
	TranscriptNetwork  = "network" // default: pagnet-level comms + operational events
	TranscriptFull     = "full"
)

// Workspace access modes (§29 git work isolation): read_write agents get
// exclusive checkouts (second+ on the same repo are moved to a git
// worktree); read_only agents share the checkout.
const (
	AccessReadWrite = "read_write" // default
	AccessReadOnly  = "read_only"
)

// AccessFromSettings returns the definition's workspace access mode
// (default read_write).
func AccessFromSettings(executionSettings map[string]any) string {
	if v, ok := executionSettings["access"].(string); ok && v == AccessReadOnly {
		return AccessReadOnly
	}
	return AccessReadWrite
}

// DefaultExecutionSettings returns the default execution settings map.
func DefaultExecutionSettings() map[string]any {
	return map[string]any{
		"maxConcurrentTurns": 1,
		"transcriptLevel":    TranscriptNetwork,
	}
}

// WorkspaceAccess describes how an agent may use its workspace. In v2 this
// is enforced by the daemon/runtime configuration, not by prompts.
type WorkspaceAccess string

const (
	WorkspaceAccessReadOnly  WorkspaceAccess = "read-only"
	WorkspaceAccessReadWrite WorkspaceAccess = "read-write"
)

// AgentInstance is a schedulable execution identity bound to a definition,
// host, runtime and (optional) workspace. It is NOT the same thing as a
// process: an instance can be hibernated (process gone, session preserved)
// and still be fully registered and wakeable.
//
// An instance is NOT network identity: the principal is. The instance's
// live presence is a managed_agent PrincipalEndpoint.
type AgentInstance struct {
	ID           ID
	NetworkID    ID
	DefinitionID ID
	// PrincipalID is the agent principal this instance executes for.
	PrincipalID ID
	HostID      ID
	// ReplicaSlot is the explicit instance slot within the
	// (definition, host) pair. Slot 0 is the instance that launch
	// manages — launch is idempotent per (definition, host, slot 0) and
	// a duplicate launch NEVER creates slot 1. Slots 1..N are reserved
	// for a future explicit scaling operation (a distinct intent, not
	// repeated launches); until it exists, only slot 0 is ever created.
	ReplicaSlot int
	WorkspaceID *ID
	Runtime     RuntimeName
	Status      AgentStatus
	// AvailabilityRetryAt is set only when the runtime/provider supplied a
	// reliable recovery time (e.g. Retry-After). Never guessed.
	AvailabilityRetryAt *time.Time
	PID                 *int
	RuntimeSessionID    *string
	CurrentTaskID       *ID
	Metadata            map[string]any
	StartedAt           *time.Time
	StoppedAt           *time.Time
	LastActivityAt      time.Time
	CreatedAt           time.Time
	// CurrentContext is the current turn's delivery context (representatives):
	// {conversationId, triggerSource: channel|network|web|api,
	// triggerNetworkId, initiatorUserId, sourceRef}. Set when a turn is
	// delivered, cleared when it completes. Empty for workers.
	CurrentContext json.RawMessage
}

// RepContext is the decoded shape of AgentInstance.CurrentContext.
type RepContext struct {
	ConversationID   string `json:"conversationId,omitempty"`
	TriggerSource    string `json:"triggerSource,omitempty"`
	TriggerNetworkID string `json:"triggerNetworkId,omitempty"`
	InitiatorUserID  string `json:"initiatorUserId,omitempty"`
	SourceRef        string `json:"sourceRef,omitempty"`
}

// ParseContext decodes the instance's current turn context (empty when the
// instance has none).
func (i AgentInstance) ParseContext() RepContext {
	var c RepContext
	if len(i.CurrentContext) > 0 {
		_ = json.Unmarshal(i.CurrentContext, &c)
	}
	return c
}

// Responsibility maps a principal to a Resource and the actions it is
// expected to handle. resource_id nil = any resource in the network.
type Responsibility struct {
	ID          ID
	NetworkID   ID
	PrincipalID ID
	ResourceID  *ID
	Actions     []string
	Priority    int
	CreatedAt   time.Time
}

// Candidate is a routing result from deterministic discovery: an agent
// matched against (resource, action) with enough information for a model to
// decide.
type Candidate struct {
	AgentDefinitionID ID
	InstanceID        ID
	AgentName         string
	Status            AgentStatus
	Availability      AgentAvailability
	Wakeable          bool // hibernated with a resumable session
	Runtime           RuntimeName
	Host              string
	ResourceMatches   []string
	MatchingActions   []string
	Groups            []string
	ActiveTasks       int
}
