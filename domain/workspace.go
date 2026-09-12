package domain

import "time"

// Workspace is a physical checkout/directory on a particular host. The same
// logical Resource can have multiple Workspaces on different (or the same)
// hosts.
type Workspace struct {
	ID         ID
	HostID     ID
	ResourceID *ID // nil when no logical resource is associated
	Path       string
	Branch     string
	Metadata   map[string]any
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// WorkspaceSummary is the compact form used for AI-assisted setup and
// quick-launch inference.
type WorkspaceSummary struct {
	Path      string
	Branch    string
	Remote    string
	Resource  *string // canonical resource key when Git metadata was detected
	IsGit     bool
	HasReadme bool
}
