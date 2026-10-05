package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/runtimeprofile"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

type AgentSetupResult struct {
	Ref      fabric.EndpointRef `json:"ref"`
	Revision fabric.Revision    `json:"revision"`
	Name     string             `json:"name"`
	State    string             `json:"state"`
	Runtime  domain.RuntimeName `json:"runtime,omitempty"`
}
type selectedAgentConfiguration struct {
	Input       AgentCreateInput
	Spec        *sessionworker.NativeSpec
	Environment []string
}

func (n *InstalledNode) selectedAgentRuntime(ctx context.Context, input AgentCreateInput) (*sessionworker.NativeSpec, error) {
	if len(input.Role) > 16<<10 || len(input.Model) > 256 || len(input.Workspace) > 4096 || strings.ContainsRune(input.Role, 0) || strings.ContainsRune(input.Model, 0) || strings.ContainsRune(input.Workspace, 0) {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Agent execution settings exceed bounds")
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return nil, e
	}
	rows, e := fabricagent.RuntimeInventory(ctx, filepath.Join(home, ".pagnet", runtimeprofile.Filename))
	if e != nil {
		return nil, e
	}
	selected, e := fabricagent.SelectRuntime(rows, domain.RuntimeName(input.Runtime), input.Profile)
	if e != nil {
		return nil, e
	}
	if selected == nil {
		if input.Role != "" || input.Model != "" {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Select --runtime or --profile to apply private role/model settings")
		}
		return nil, nil
	}
	if input.Workspace == "" {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Choose the agent's working folder with --workspace")
	}
	workspace, e := filepath.Abs(input.Workspace)
	if e != nil {
		return nil, e
	}
	workspace, e = filepath.EvalSymlinks(workspace)
	if e != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Agent working folder must already exist")
	}
	info, e := os.Stat(workspace)
	if e != nil || !info.IsDir() {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Agent working folder must be a directory")
	}
	paths := n.Runtime.ExecutionPaths()
	spec := sessionworker.NativeSpec{Kind: "local", Runtime: selected.Runtime, Binary: selected.Executable, PrefixArgs: append([]string(nil), selected.Profile.Args...), NativeDirs: selected.Profile.Directories(), Workspace: workspace, Model: input.Model, StandingInstructions: input.Role, MCPExecutable: paths.Binary, LocalAuthorityDirectory: paths.AuthorityDirectory, LocalFabricSocket: paths.SocketPath, Env: append([]string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}, selected.Profile.Environment()...)}
	if sessionworker.ValidateLocalRuntimeEnvironment(spec, nil) != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Selected runtime profile contains unsupported or persisted credential settings; select a private credential provider instead")
	}
	return &spec, nil
}

// ProvisionAgentRuntime installs an explicit execution profile using the actual
// retained runtime, without activating a vendor process or submitting a task.
func (n *InstalledNode) ProvisionAgentRuntime(ctx context.Context, access *fabricauth.OwnerAdministration, requestID string, input AgentCreateInput) (AgentSetupResult, error) {
	var result AgentSetupResult
	if n == nil || n.Runtime == nil || access == nil || access.VerifyCurrent(ctx) != nil {
		return result, localDenied()
	}
	owner, e := n.Installation.Operator(ctx)
	if e != nil {
		return result, e
	}
	if access.PrincipalView() != owner.PrincipalView() {
		return result, localDenied()
	}
	spec, e := n.selectedAgentRuntime(ctx, input)
	if e != nil {
		return result, e
	}
	private := selectedAgentConfiguration{Input: input, Spec: spec}
	if spec != nil {
		private.Environment = append([]string(nil), spec.Env...)
	}
	var raw []byte
	if spec == nil {
		raw, e = json.Marshal(input)
	} else {
		raw, e = json.Marshal(private)
	}
	if e != nil {
		return result, e
	}
	defer clear(raw)
	ref, e := n.ReserveSetupEndpoint(ctx, access, "agent.create", requestID, raw)
	if e != nil {
		return result, e
	}
	result = AgentSetupResult{Ref: ref, Name: input.Name, State: "unbound"}
	descriptor := fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: input.Name, Description: input.Description}
	var retained fabricagent.RetainedAgent
	if spec != nil {
		store, e := fabricagent.NewRetainedAgentStore(ctx, n.Installation.Store, owner, n.Installation.Keys)
		if e != nil {
			return result, e
		}
		retained, e = store.Reserve(ctx, ref, sha256.Sum256(raw), *spec, filepath.Join(filepath.Dir(spec.LocalFabricSocket), "workers"))
		if e != nil {
			return result, e
		}
		descriptor.Bindings = []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1", Cancellation: true}}
		result.Runtime = spec.Runtime
	}
	if e = access.VerifyCurrent(ctx); e != nil {
		return result, e
	}
	result.Revision, e = n.Installation.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: descriptor})
	if e != nil {
		return result, e
	}
	if spec != nil {
		scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: result.Revision, BindingID: "native"}
		if _, e = n.Runtime.Profiles.Put(ctx, scope, retained.Profile); e != nil {
			return result, e
		}
		if _, _, e = n.Runtime.Profiles.ProvisionInitialControl(ctx, n.Runtime.Authority, scope); e != nil {
			return result, e
		}
		result.State = "configured"
	}
	if e = access.VerifyCurrent(ctx); e != nil {
		return result, e
	}
	return result, nil
}
