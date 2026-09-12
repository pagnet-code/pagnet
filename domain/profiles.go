package domain

import "sort"

// WorkspaceAccess describes how a profile's agents may use their workspace.
// In v1 this is enforced by the daemon/runtime configuration, not by prompts.
type WorkspaceAccess string

const (
	WorkspaceAccessReadOnly  WorkspaceAccess = "read-only"
	WorkspaceAccessReadWrite WorkspaceAccess = "read-write"
)

// Profile is a template of capabilities + access that makes common launches
// trivial. Profiles are routing/execution templates, not hard security roles.
type Profile struct {
	Name            string
	Description     string
	Capabilities    []Capability
	WorkspaceAccess WorkspaceAccess
}

var builtInProfiles = map[string]Profile{
	"advisor": {
		Name:            "advisor",
		Description:     "Answers questions and analyzes code in a read-only workspace.",
		Capabilities:    []Capability{Cap(CapAnswer), Cap(CapAnalyze)},
		WorkspaceAccess: WorkspaceAccessReadOnly,
	},
	"coder": {
		Name:            "coder",
		Description:     "Implements changes and runs tests in a read-write workspace.",
		Capabilities:    []Capability{Cap(CapImplement), Cap(CapTest)},
		WorkspaceAccess: WorkspaceAccessReadWrite,
	},
	"reviewer": {
		Name:            "reviewer",
		Description:     "Reviews code and analyzes changes in a read-only workspace.",
		Capabilities:    []Capability{Cap(CapAnalyze), Cap(CapReview)},
		WorkspaceAccess: WorkspaceAccessReadOnly,
	},
	"standards": {
		Name:            "standards",
		Description:     "Answers, analyzes, reviews and standardizes code across repositories.",
		Capabilities:    []Capability{Cap(CapAnswer), Cap(CapAnalyze), Cap(CapReview), Cap(CapStandardize)},
		WorkspaceAccess: WorkspaceAccessReadOnly,
	},
	"integration": {
		Name:            "integration",
		Description:     "Analyzes cross-repository integrations, coordinates and tests them.",
		Capabilities:    []Capability{Cap(CapAnalyze), Cap(CapCoordinate), Cap(CapTest)},
		WorkspaceAccess: WorkspaceAccessReadOnly,
	},
	"coordinator": {
		Name:            "coordinator",
		Description:     "Coordinates work across agents and delegates tasks.",
		Capabilities:    []Capability{Cap(CapCoordinate), Cap(CapDelegate)},
		WorkspaceAccess: WorkspaceAccessReadOnly,
	},
}

// BuiltInProfile returns the built-in profile with the given name.
func BuiltInProfile(name string) (Profile, bool) {
	p, ok := builtInProfiles[name]
	return p, ok
}

// AllProfiles returns all built-in profiles in stable (name-sorted) order.
func AllProfiles() []Profile {
	names := make([]string, 0, len(builtInProfiles))
	for n := range builtInProfiles {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Profile, 0, len(names))
	for _, n := range names {
		out = append(out, builtInProfiles[n])
	}
	return out
}
