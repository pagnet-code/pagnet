package domain

import (
	"encoding/json"
	"time"
)

// Capability is a verb describing what an agent can generally do. In v1 it
// is routing/discovery metadata, not a permission system. It carries enough
// metadata to be exported later as an external agent "skill" (A2A alignment).
//
// Capability ("can implement") is deliberately kept separate from
// Responsibility ("implements on github.com/xemahq/dsl").
type Capability struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

var capabilityDescriptions = map[string]string{
	CapAnswer:      "Answers questions about code, design and behavior.",
	CapAnalyze:     "Analyzes code, architecture and change impact.",
	CapImplement:   "Implements code changes.",
	CapTest:        "Writes and runs tests.",
	CapReview:      "Reviews code and pull requests.",
	CapRelease:     "Prepares and executes releases.",
	CapStandardize: "Standardizes code and conventions across repositories.",
	CapCoordinate:  "Coordinates work across agents.",
	CapDelegate:    "Delegates work to other agents.",
}

// Cap builds a Capability from a verb name with its default description.
func Cap(name string) Capability {
	return Capability{ID: name, Name: name, Description: capabilityDescriptions[name]}
}

// CapabilityNames extracts the names from a capability list.
func CapabilityNames(caps []Capability) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		out = append(out, c.Name)
	}
	return out
}

// AgentDefinition is a persistent logical identity describing an agent role.
// It survives process restarts and is the stable external identity: future
// protocol adapters expose the definition (e.g. "dsl-coder"), never a
// transient instance/PID.
//
// Kind invariants (enforced by CHECK constraint):
//   - worker:         NetworkID != nil
//   - representative: NetworkID == nil, OwnerUserID != nil (tenant/user-
//     scoped; network access only through RepresentativeGrant)
//   - system:         NetworkID != nil
type AgentDefinition struct {
	ID   ID
	Kind AgentKind
	// NetworkID is nil for representatives (multi-network via grants).
	NetworkID   *ID
	Name        string // unique per network (workers) / per owner (reps)
	OwnerUserID *ID
	Description string
	// Mission is the initial instruction for a launched agent (north-star
	// §15): it becomes the runtime's first turn on a fresh launch. Editing
	// it changes FUTURE launches — a running/resumed session is untouched.
	Mission string
	// Instruction is the standing AGENT.md-style instruction for the agent:
	// always-on context, unlike Mission (the one-shot first turn). It
	// reaches the runtime WITHOUT writing into the user's workspace —
	// claude via --append-system-prompt-file, other runtimes appended to a
	// fresh session's first turn (exactly how the coordination contract
	// reaches them). "" = none.
	Instruction string
	// DefaultRuntime is the runtime for managed instances.
	DefaultRuntime RuntimeName
	// DefaultModel is the model for managed instances ("" = the runtime's
	// own default). A launch may override it per-launch.
	DefaultModel string
	Profile      string
	Capabilities []Capability
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

// AgentInstance is a schedulable execution identity bound to a definition,
// host, runtime and (optional) workspace. It is NOT the same thing as a
// process: an instance can be hibernated (process gone, session preserved)
// and still be fully registered and wakeable.
type AgentInstance struct {
	ID           ID
	NetworkID    ID
	DefinitionID ID
	HostID       ID
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
	// SelfCapabilities are capabilities THIS instance declared about itself
	// (network_register_capabilities), scoped to the launch/mission. They
	// merge with the definition's user-set Capabilities in discovery and
	// never replace them; the agent can read but never mutate the
	// definition's set.
	SelfCapabilities []Capability
	Metadata         map[string]any
	StartedAt        *time.Time
	StoppedAt        *time.Time
	LastActivityAt   time.Time
	CreatedAt        time.Time
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

// Responsibility maps an Agent Definition to a Resource and the actions it is
// expected to handle. resource_id nil = any resource in the network.
type Responsibility struct {
	ID                ID
	NetworkID         ID
	AgentDefinitionID ID
	ResourceID        *ID
	Actions           []string
	Priority          int
	CreatedAt         time.Time
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
