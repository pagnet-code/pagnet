package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

// AgentCreateInput publishes only the chosen network-facing description.
// Runtime instructions/credentials belong to private execution profiles.
type AgentCreateInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Role        string `json:"role,omitempty"`
	Runtime     string `json:"runtime,omitempty"`
	Profile     string `json:"profile,omitempty"`
	Workspace   string `json:"workspace,omitempty"`
	Model       string `json:"model,omitempty"`
}

// AgentAdministration consumes genuine owner callbacks and the installation's
// original writer. Creating a searchable identity does not launch a turn.
func (n *InstalledNode) AgentAdministration(committed func()) map[string]fabricadmin.Handler {
	return map[string]fabricadmin.Handler{"agent.create": func(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
		if n == nil || n.Installation == nil || n.Node == nil || access == nil || request.Operation != "agent.create" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
			return nil, localDenied()
		}
		owner, err := n.Installation.Operator(ctx)
		if err != nil {
			return nil, err
		}
		if access.PrincipalView() != owner.PrincipalView() {
			return nil, localDenied()
		}
		var input AgentCreateInput
		if err = fabric.DecodeJSON(request.Input, &input); err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(request.Input))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&input); err != nil {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Agent setup contains unsupported fields")
		}
		if strings.TrimSpace(input.Name) == "" || len(input.Name) > 256 || strings.ContainsAny(input.Name, "\x00\r\n") || strings.TrimSpace(input.Description) == "" || len(input.Description) > 4096 || strings.ContainsRune(input.Description, 0) {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Agent name and network description required")
		}
		var output json.RawMessage
		err = n.Installation.WithCurrentOperator(ctx, owner, func(current context.Context) error {
			if e := access.VerifyCurrent(current); e != nil {
				return e
			}
			result, e := n.ProvisionAgentRuntime(current, access, request.ID, input)
			if e != nil {
				return e
			}
			if committed != nil {
				committed()
			}
			output, e = json.Marshal(result)
			return e
		})
		return output, err
	}}
}
