package domain

import "time"

// Artifact is a durable reference produced by work (PR URL, commit SHA,
// package version, test report, document URL, file reference, JSON result).
type Artifact struct {
	ID                    ID
	NetworkID             ID
	TaskID                *ID
	PublishedByInstanceID *ID
	Type                  ArtifactType
	URI                   string
	Label                 string
	Metadata              map[string]any
	CreatedAt             time.Time
}
