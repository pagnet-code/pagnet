package fabricnode

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

// ServiceBindingProvider exposes only explicitly connected private installations.
// Catalog synchronization is shared by all authorized node callers; discovery
// and adapter selection cannot install services or infer caller permissions.
type ServiceBindingProvider struct {
	connections *fabricservices.Connections
	a2a         *fabricservices.A2AConnections
}

func NewServiceBindingProvider(c *fabricservices.Connections) (*ServiceBindingProvider, error) {
	if c == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Service connections are required")
	}
	return &ServiceBindingProvider{connections: c}, nil
}
func (p *ServiceBindingProvider) ResolveBinding(ctx context.Context, caller fabric.ExecutionContext, endpoint fabric.EndpointDescriptor, binding fabric.BindingSummary, offer *fabric.OfferDescriptor) (fabric.EndpointAdapter, [32]byte, error) {
	if p == nil || ctx == nil || caller.VerifyAuthenticated(endpoint.Ref.Domain()) != nil {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeUnauthenticated, "Authenticated service caller required")
	}
	matched := false
	for _, b := range endpoint.Bindings {
		if b == binding {
			matched = true
		}
	}
	if !matched {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeStaleReference, "Selected service binding changed")
	}
	if binding.Protocol == "a2a.jsonrpc" && offer == nil && p.a2a != nil {
		return p.a2a.Resolve(ctx, registry.DescriptorBatchScope{Endpoint: endpoint.Ref, ExpectedEndpointRevision: endpoint.Revision, BindingID: binding.ID})
	}
	if p.connections == nil {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeUnsupported, "Selected service protocol is not installed")
	}
	if binding.Protocol != "mcp.tools" || offer == nil || offer.Ref.Endpoint() != endpoint.Ref || offer.BindingID != binding.ID {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeUnsupported, "MCP requires an exact published operation")
	}
	return p.connections.ResolveMCP(ctx, registry.DescriptorBatchScope{Endpoint: endpoint.Ref, ExpectedEndpointRevision: endpoint.Revision, BindingID: binding.ID})
}

var _ BindingProvider = (*ServiceBindingProvider)(nil)

func NewA2AServiceBindingProvider(c *fabricservices.A2AConnections) (*ServiceBindingProvider, error) {
	if c == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "A2A service connections are required")
	}
	return &ServiceBindingProvider{a2a: c}, nil
}
