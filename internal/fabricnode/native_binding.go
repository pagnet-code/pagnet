package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
)

// NativeBindingProvider resolves operator-installed execution configuration.
// Resolving a binding never launches or wakes its process; the exact native
// adapter performs lifecycle admission only after actual node dispatch.
type NativeBindingProvider struct {
	Profiles *fabricnative.ProfileStore
	Adapter  *fabricnative.Adapter
}

func (p *NativeBindingProvider) ResolveBinding(ctx context.Context, caller fabric.ExecutionContext, descriptor fabric.EndpointDescriptor, binding fabric.BindingSummary, offer *fabric.OfferDescriptor) (fabric.EndpointAdapter, [32]byte, error) {
	if p == nil || p.Profiles == nil || p.Adapter == nil || binding.Protocol != "local.native" || binding.Version != "1" {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeUnsupported, "Native binding is not configured")
	}
	if err := caller.VerifyAuthenticated(descriptor.Ref.Domain()); err != nil {
		return nil, [32]byte{}, err
	}
	if offer != nil && (offer.Ref.Endpoint() != descriptor.Ref || offer.BindingID != binding.ID) {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeStaleReference, "Native offer binding differs")
	}
	profile, generation, err := p.Profiles.Get(ctx, registry.DescriptorBatchScope{Endpoint: descriptor.Ref, ExpectedEndpointRevision: descriptor.Revision, BindingID: binding.ID})
	if err != nil {
		return nil, [32]byte{}, err
	}
	// Includes retained private generation and physical profile identity without
	// exposing paths or credentials in the network/search/telemetry model.
	raw, err := json.Marshal(struct {
		Ref         fabric.EndpointRef
		Revision    fabric.Revision
		Binding     string
		Generation  uint64
		Profile     fabricnative.Profile
		Environment []string
	}{descriptor.Ref, descriptor.Revision, binding.ID, generation, profile, profile.Native.Env})
	if err != nil {
		return nil, [32]byte{}, err
	}
	defer clear(raw)
	return p.Adapter, sha256.Sum256(raw), nil
}

var _ BindingProvider = (*NativeBindingProvider)(nil)
