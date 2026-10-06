// The installed hosted product's private owner-administration operations. They
// merge into the node's existing admin server (the same handlers-map pattern as
// AgentAdministration / ServiceAdministration); duplicate operation names are
// startup errors, as today. Every act runs under the genuine owner session and
// references the catalog publisher and daemon through the fail-closed deferred
// holders.

package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/agentbridge"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

// HostedBindingCreateInput is the private owner input for creating a hosted
// binding. The profile is the operator-selected original-worker association
// (its Scope carries the worker's instance/generation); the descriptor is
// registered by the handler.
type HostedBindingCreateInput struct {
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Profile     fabricagent.HostedProfile `json:"profile"`
}

// HostedBindingRevokeInput is the private owner input for revoking a hosted
// binding (retiring its endpoint). NEW calls are then denied; the retained
// journal (historical reads) remains.
type HostedBindingRevokeInput struct {
	Endpoint string `json:"endpoint"`
}

// HostedSideportAssociateInput is the private owner input for the sideport
// association act (the daemon re-derives the exact profile and re-probes the
// genuine original worker).
type HostedSideportAssociateInput struct {
	InstanceID string `json:"instanceId"`
	Socket     string `json:"socket"`
	Endpoint   string `json:"endpoint"`
	Generation string `json:"generation"`
}

// Administration returns the hosted product's private owner-administration
// handlers. A nil product contributes no operations.
func (h *InstalledHosted) Administration() map[string]fabricadmin.Handler {
	if h == nil {
		return nil
	}
	return map[string]fabricadmin.Handler{
		"hosted.binding.create":       h.hostedBindingCreate,
		"hosted.binding.list":         h.hostedBindingList,
		"hosted.binding.revoke":       h.hostedBindingRevoke,
		"hosted.sideport.associate":   h.hostedSideportAssociate,
	}
}

func (h *InstalledHosted) hostedBindingCreate(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if h == nil || h.node == nil || access == nil || request.Operation != "hosted.binding.create" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input HostedBindingCreateInput
	if err := fabric.DecodeJSON(request.Input, &input); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted binding create contains unsupported fields")
	}
	if strings.TrimSpace(input.Name) == "" || len(input.Name) > 256 || strings.ContainsAny(input.Name, "\x00\r\n") ||
		strings.TrimSpace(input.Description) == "" || len(input.Description) > 4096 || strings.ContainsRune(input.Description, 0) {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted binding name and description required")
	}
	if input.Profile.Validate() != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted binding profile is invalid")
	}
	store := h.node.Installation.Store
	owner, err := h.node.Installation.Operator(ctx)
	if err != nil {
		return nil, err
	}
	if access.PrincipalView() != owner.PrincipalView() {
		return nil, localDenied()
	}
	// The catalog publisher is referenced through the fail-closed deferred
	// holder: an unwired publisher is an honest refusal, never a silent skip.
	publisher := h.deferred.publisher()
	if publisher == nil {
		return nil, hostedNotWired("catalog publisher")
	}
	var output json.RawMessage
	err = h.node.Installation.WithCurrentOperator(ctx, owner, func(current context.Context) error {
		if e := access.VerifyCurrent(current); e != nil {
			return e
		}
		root := store.AuthorityIdentity()
		ref, e := fabric.NewEndpointRef(root.PublicKey)
		if e != nil {
			return e
		}
		const bindingID = "original"
		descriptor := fabric.EndpointDescriptor{
			Ref:         ref,
			Kind:        "actor.agent",
			Name:        input.Name,
			Description: input.Description,
			Bindings:    []fabric.BindingSummary{{ID: bindingID, Protocol: HostedNativeBindingProtocol, Version: "1"}},
		}
		revision, e := store.Register(current, owner, fabric.RegistryUpdate{Descriptor: descriptor})
		if e != nil {
			return e
		}
		scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: bindingID}
		if _, e = h.Profiles.Install(current, access, scope, input.Profile); e != nil {
			return e
		}
		// A brand-new binding has no prior cloud revision (the CAS expectation
		// is empty). The publish is triggered under the same owner session.
		if e = publisher.Publish(current, access, ref, revision, bindingID, ""); e != nil {
			return e
		}
		out, e := json.Marshal(map[string]string{"endpoint": ref.String(), "revision": string(revision), "binding": bindingID})
		if e != nil {
			return e
		}
		output = out
		return nil
	})
	return output, err
}

// hostedBindingList is the truthful list of the node's hosted bindings,
// including retired state. It never fabricates a binding.
func (h *InstalledHosted) hostedBindingList(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if h == nil || h.node == nil || access == nil || request.Operation != "hosted.binding.list" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	owner, err := h.node.Installation.Operator(ctx)
	if err != nil {
		return nil, err
	}
	if access.PrincipalView() != owner.PrincipalView() {
		return nil, localDenied()
	}
	store := h.node.Installation.Store
	type hostedBindingView struct {
		Endpoint  string `json:"endpoint"`
		Revision  string `json:"revision"`
		Binding   string `json:"binding"`
		Retired   bool   `json:"retired"`
		Instance  string `json:"instance,omitempty"`
		NetworkID string `json:"networkId,omitempty"`
	}
	var out []hostedBindingView
	cursor := ""
	for {
		page, err := store.ListEndpointHeads(ctx, owner, cursor, 100)
		if err != nil {
			return nil, err
		}
		for _, head := range page.Heads {
			descriptor, err := store.GetEndpoint(ctx, head.Ref, head.Revision)
			if err != nil {
				continue
			}
			binding := ""
			for _, b := range descriptor.Bindings {
				if b.Protocol == HostedNativeBindingProtocol {
					if binding != "" {
						binding = ""
						break
					}
					binding = b.ID
				}
			}
			if binding == "" {
				continue
			}
			view := hostedBindingView{Endpoint: head.Ref.String(), Revision: string(head.Revision), Binding: binding, Retired: head.Retired}
			if !head.Retired {
				scope := registry.DescriptorBatchScope{Endpoint: head.Ref, ExpectedEndpointRevision: descriptor.Revision, BindingID: binding}
				if profile, _, err := h.Profiles.Get(ctx, scope); err == nil {
					view.Instance = profile.Scope.InstanceID
					view.NetworkID = profile.NetworkID
				}
			}
			out = append(out, view)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if out == nil {
		out = []hostedBindingView{}
	}
	return json.Marshal(out)
}

func (h *InstalledHosted) hostedBindingRevoke(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if h == nil || h.node == nil || access == nil || request.Operation != "hosted.binding.revoke" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input HostedBindingRevokeInput
	if err := fabric.DecodeJSON(request.Input, &input); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted binding revoke contains unsupported fields")
	}
	if strings.TrimSpace(input.Endpoint) == "" {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted binding revoke requires an endpoint")
	}
	ref, err := fabric.ParseEndpointRef(input.Endpoint)
	if err != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted binding revoke endpoint is invalid")
	}
	store := h.node.Installation.Store
	owner, err := h.node.Installation.Operator(ctx)
	if err != nil {
		return nil, err
	}
	if access.PrincipalView() != owner.PrincipalView() {
		return nil, localDenied()
	}
	var output json.RawMessage
	err = h.node.Installation.WithCurrentOperator(ctx, owner, func(current context.Context) error {
		if e := access.VerifyCurrent(current); e != nil {
			return e
		}
		descriptor, e := store.GetEndpoint(current, ref, "")
		if e != nil {
			return e
		}
		// Retiring the endpoint denies NEW calls (the endpoint is no longer
		// active); the retained journal (historical reads) is untouched.
		_, e = store.Retire(current, owner, ref, descriptor.Revision)
		if e != nil {
			return e
		}
		out, e := json.Marshal(map[string]string{"endpoint": ref.String(), "status": "revoked"})
		if e != nil {
			return e
		}
		output = out
		return nil
	})
	return output, err
}

func (h *InstalledHosted) hostedSideportAssociate(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if h == nil || h.node == nil || access == nil || request.Operation != "hosted.sideport.associate" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	d := h.deferred.daemon()
	if d == nil {
		return nil, hostedNotWired("daemon")
	}
	var input HostedSideportAssociateInput
	if err := fabric.DecodeJSON(request.Input, &input); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted sideport associate contains unsupported fields")
	}
	if strings.TrimSpace(input.InstanceID) == "" || strings.TrimSpace(input.Socket) == "" || strings.TrimSpace(input.Generation) == "" {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted sideport associate requires instance, socket and generation")
	}
	ref, err := fabric.ParseEndpointRef(input.Endpoint)
	if err != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted sideport associate endpoint is invalid")
	}
	owner, err := h.node.Installation.Operator(ctx)
	if err != nil {
		return nil, err
	}
	if access.PrincipalView() != owner.PrincipalView() {
		return nil, localDenied()
	}
	sp := agentbridge.HostedFabricSideport{Socket: input.Socket, Endpoint: ref, Generation: input.Generation}
	// The daemon re-derives the exact installed profile through the node's
	// selected-binding resolve port and re-probes the genuine original worker.
	if err := d.AssociateHostedFabricSideport(ctx, input.InstanceID, sp); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"instance": input.InstanceID, "status": "associated"})
}
