package domain

import "time"

// Task is a durable piece of delegated work. Delegated work is NEVER modeled
// as a chat message.
type Task struct {
	ID                 ID
	NetworkID          ID
	Title              string
	Objective          string
	AcceptanceCriteria []string
	CreatorInstanceID  *ID
	CreatorAgentName   string
	TargetInstanceID   *ID
	TargetGroupID      *ID
	TargetAgentName    string
	ResourceID         *ID
	Status             TaskStatus
	AssignedInstanceID *ID
	AssignedAgentName  string
	CorrelationID      *ID
	FailureReason      string
	CreatedAt          time.Time
	AcceptedAt         *time.Time
	StartedAt          *time.Time
	CompletedAt        *time.Time
	UpdatedAt          time.Time
	// Human provenance (§10): when a representative created this task on a
	// human's behalf, InitiatorUserID is that human and Source/SourceRef
	// record the path (channel:fake / network / web / api + origin ref).
	InitiatorUserID *ID
	Source          string
	SourceRef       string
}

// TaskDependency expresses task -> task dependencies.
type TaskDependency struct {
	TaskID          ID
	DependsOnTaskID ID
}

// TaskStatusHistory is an immutable record of task status changes.
type TaskStatusHistory struct {
	ID              ID
	TaskID          ID
	Status          TaskStatus
	Reason          string
	ActorInstanceID *ID
	At              time.Time
}

// TaskFilter narrows ListTasks.
type TaskFilter struct {
	Status        *TaskStatus
	DefinitionID  *ID
	InstanceID    *ID
	ResourceID    *ID
	CorrelationID *ID
	Limit         int
}
