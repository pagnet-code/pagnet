package fabricagent

import (
	"context"
	"sort"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/runtimeprofile"
)

// RuntimeChoice is host-local configuration. Only its name, runtime and
// availability may be published; paths, argv and environment remain private.
type RuntimeChoice struct {
	Name       string                 `json:"name"`
	Runtime    domain.RuntimeName     `json:"runtime"`
	Available  bool                   `json:"available"`
	Executable string                 `json:"-"`
	Profile    runtimeprofile.Profile `json:"-"`
}

// RuntimeInventory resolves installed executables without launching them,
// requesting models, reading shell aliases or installing a wrapper.
func RuntimeInventory(ctx context.Context, profilePath string) ([]RuntimeChoice, error) {
	if ctx == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Runtime inventory context required")
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	configured, e := runtimeprofile.Load(profilePath)
	if e != nil {
		return nil, e
	}
	type binary interface{ BinaryPath() (string, bool) }
	drivers := []struct {
		runtime domain.RuntimeName
		driver  binary
	}{
		{domain.RuntimeQwenCode, agentruntime.NewQwenPersistent("")},
		{domain.RuntimeClaudeCode, agentruntime.NewClaudePersistent("")},
		{domain.RuntimeCodex, agentruntime.NewCodexPersistent("")},
		{domain.RuntimeOpenCode, agentruntime.NewOpenCodePersistent("")},
		{domain.RuntimeGrok, agentruntime.NewGrok("")},
	}
	rows := make([]RuntimeChoice, 0, len(drivers)+len(configured.Profiles))
	for _, d := range drivers {
		path, available := d.driver.BinaryPath()
		rows = append(rows, RuntimeChoice{Runtime: d.runtime, Available: available, Executable: path})
	}
	for _, p := range configured.Profiles {
		path, available := p.ResolvedExecutable()
		rows = append(rows, RuntimeChoice{Name: p.Name, Runtime: p.Runtime, Available: available, Executable: path, Profile: p})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Runtime != rows[j].Runtime {
			return rows[i].Runtime < rows[j].Runtime
		}
		return rows[i].Name < rows[j].Name
	})
	return rows, ctx.Err()
}

// SelectRuntime never interprets a description as an executable preference.
// Ambiguous omitted selection preserves a searchable unbound identity.
func SelectRuntime(rows []RuntimeChoice, runtime domain.RuntimeName, profile string) (*RuntimeChoice, error) {
	if runtime != "" || profile != "" {
		for _, row := range rows {
			if row.Name != profile || runtime != "" && row.Runtime != runtime {
				continue
			}
			if !row.Available {
				return nil, fabric.NewError(fabric.CodeTargetUnavailable, "Selected runtime is not installed on this host")
			}
			copy := row
			return &copy, nil
		}
		return nil, fabric.NewError(fabric.CodeUnsupported, "Select an installed supported runtime or configured runtime profile")
	}
	var selected *RuntimeChoice
	for _, row := range rows {
		if !row.Available {
			continue
		}
		if selected != nil {
			return nil, nil
		}
		copy := row
		selected = &copy
	}
	return selected, nil
}
