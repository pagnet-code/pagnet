package fabricnode

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
)

// BindingProvider resolves private CURRENT adapter configuration for one exact
// published binding. It must not search, infer authority, or select alternatives.
type BindingProvider interface {
	ResolveBinding(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, fabric.BindingSummary, *fabric.OfferDescriptor) (fabric.EndpointAdapter, [32]byte, error)
}
type BindingProtocol struct{ Protocol, Version string }
type Router struct {
	providers map[BindingProtocol]BindingProvider
}

func NewRouter(providers map[BindingProtocol]BindingProvider) (*Router, error) {
	if len(providers) == 0 || len(providers) > 128 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid adapter registration budget")
	}
	owned := make(map[BindingProtocol]BindingProvider, len(providers))
	for key, provider := range providers {
		if !fabric.ValidNamespacedName(key.Protocol) || key.Version == "" || len(key.Version) > 128 || provider == nil {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid adapter registration")
		}
		owned[key] = provider
	}
	return &Router{owned}, nil
}
func (r *Router) Select(ctx context.Context, caller fabric.ExecutionContext, endpoint fabric.EndpointDescriptor, offer *fabric.OfferDescriptor) (dispatch.Selection, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return dispatch.Selection{}, fabric.NewError(fabric.CodeCancelled, "Adapter selection ended")
	}
	if err := caller.VerifyAuthenticated(endpoint.Ref.Domain()); err != nil {
		return dispatch.Selection{}, err
	}
	var selected *fabric.BindingSummary
	if offer != nil {
		if offer.Ref.Endpoint() != endpoint.Ref || offer.BindingID == "" {
			return dispatch.Selection{}, fabric.NewError(fabric.CodeStaleReference, "Offer does not belong to selected endpoint")
		}
		for i := range endpoint.Bindings {
			if endpoint.Bindings[i].ID == offer.BindingID {
				selected = &endpoint.Bindings[i]
				break
			}
		}
	} else if len(endpoint.Bindings) == 0 {
		return dispatch.Selection{}, fabric.NewError(fabric.CodeTargetUnavailable, "Endpoint has no connected execution binding")
	} else if len(endpoint.Bindings) == 1 {
		selected = &endpoint.Bindings[0]
	} else {
		return dispatch.Selection{}, fabric.NewError(fabric.CodeInvalidInput, "Endpoint has multiple bindings; select an explicit offer")
	}
	if selected == nil {
		return dispatch.Selection{}, fabric.NewError(fabric.CodeStaleReference, "Selected binding is absent")
	}
	provider := r.providers[BindingProtocol{selected.Protocol, selected.Version}]
	if provider == nil {
		return dispatch.Selection{}, fabric.NewError(fabric.CodeUnsupported, "Selected adapter protocol is not configured")
	}
	adapter, fingerprint, err := provider.ResolveBinding(ctx, caller, endpoint, *selected, offer)
	if err != nil {
		return dispatch.Selection{}, err
	}
	if adapter == nil || fingerprint == ([32]byte{}) {
		return dispatch.Selection{}, fabric.NewError(fabric.CodeTargetUnavailable, "Selected private adapter is unavailable")
	}
	return dispatch.Selection{BindingID: selected.ID, EndpointRevision: endpoint.Revision, Fingerprint: fingerprint, Adapter: adapter}, nil
}

var _ dispatch.BindingResolver = (*Router)(nil)
