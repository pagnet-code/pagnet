package fabricnode

import (
	"bytes"
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/daemon"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/localpeer"
)

// HostedNativeBindingProtocol identifies an explicit original-worker binding.
// It is separate from a local native launch/adoption profile. The canonical
// endpoint is still an ordinary actor endpoint with no required offer taxonomy.
const HostedNativeBindingProtocol = "pagnet.agent.hosted-native.v1"

// HostedRuntimeBindings composes real original daemon ownership and private
// signed node association into kernel authentication. It does not install a
// second process, adopt a SID, change a native profile, or imply INVOKE is ready.
// The installed runtime must separately compose the actual invocation adapter,
// encrypted catalog and original source reader before enabling product exposure.
type HostedRuntimeBindings struct {
	store    *registry.Store
	profiles *fabricagent.HostedProfiles
	daemon   *daemon.Daemon
	guard    *daemon.HostedOwnerGuard
	root     registry.AuthorityIdentity
}

func NewHostedRuntimeBindings(ctx context.Context, store *registry.Store, profiles *fabricagent.HostedProfiles, host *daemon.Daemon, guard *daemon.HostedOwnerGuard) (*HostedRuntimeBindings, error) {
	if ctx == nil || store == nil || profiles == nil || host == nil || guard == nil || host.HostedOwnerGuard != guard {
		return nil, localDenied()
	}
	root, err := store.CurrentAuthorityIdentity(ctx)
	if err != nil {
		return nil, err
	}
	return &HostedRuntimeBindings{store, profiles, host, guard, root}, nil
}

// Ready must succeed BEFORE any hosted-enabled listener is exposed. It is
// startup-only, independent of normal local discovery/invocation hot paths.
func (h *HostedRuntimeBindings) Ready(ctx context.Context) error {
	if h == nil {
		return localDenied()
	}
	return h.daemon.HostedOwnerGuardReady(ctx, h.guard)
}

func (h *HostedRuntimeBindings) selected(ctx context.Context, ref fabric.EndpointRef, revision fabric.Revision, binding string) (fabric.EndpointDescriptor, registry.DescriptorBatchScope, fabricagent.HostedProfile, error) {
	if h == nil || ctx == nil || ref.IsOffer() || ref.Domain() != h.root.Namespace {
		return fabric.EndpointDescriptor{}, registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, localDenied()
	}
	descriptor, err := h.store.GetEndpoint(ctx, ref, revision)
	if err != nil {
		return descriptor, registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, err
	}
	selected := ""
	for _, b := range descriptor.Bindings {
		if b.Protocol == HostedNativeBindingProtocol && (binding == "" || binding == b.ID) {
			if selected != "" {
				return descriptor, registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, localDenied()
			}
			selected = b.ID
		}
	}
	if selected == "" {
		return descriptor, registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, localDenied()
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: descriptor.Revision, BindingID: selected}
	profile, _, err := h.profiles.Get(ctx, scope)
	return descriptor, scope, profile, err
}

// ResolveHosted is suitable only for the actual private socket listener: its
// peer is kernel-captured there and its nonce is checked by original worker IPC.
func (h *HostedRuntimeBindings) ResolveHosted(ctx context.Context, selector fabrichost.HostedSelector) (fabricauth.HostedActivation, error) {
	descriptor, scope, profile, err := h.selected(ctx, selector.Endpoint, "", "")
	if err != nil || profile.Scope.InstanceID != selector.InstanceID {
		return fabricauth.HostedActivation{}, localDenied()
	}
	return h.daemon.ResolveHostedActivation(ctx, profile, descriptor.Ref, descriptor.Revision, scope.BindingID, selector.Peer, selector.Nonce, selector.Generation)
}

func (h *HostedRuntimeBindings) verified(ctx context.Context, peer fabricauth.HostedPeer) (fabric.Principal, registry.DescriptorBatchScope, error) {
	if h == nil || peer.Root.Namespace != h.root.Namespace || peer.Root.StoreID != h.root.StoreID || peer.Root.KeyRevision != h.root.KeyRevision || peer.Root.Owner != h.root.Owner || !bytes.Equal(peer.Root.PublicKey, h.root.PublicKey) {
		return fabric.Principal{}, registry.DescriptorBatchScope{}, localDenied()
	}
	a := peer.Activation
	descriptor, scope, profile, err := h.selected(ctx, a.Endpoint, a.DescriptorRevision, a.BindingID)
	if err != nil {
		return fabric.Principal{}, scope, err
	}
	if err = h.daemon.VerifyHostedActivation(ctx, profile, peer); err != nil {
		return fabric.Principal{}, scope, err
	}
	principal := fabric.Principal{Ref: descriptor.Ref.String(), Kind: descriptor.Kind, Issuer: h.root.Namespace}
	if principal == h.root.Owner || !fabric.ValidNamespacedName(principal.Kind) {
		return fabric.Principal{}, scope, localDenied()
	}
	return principal, scope, nil
}
func (h *HostedRuntimeBindings) ValidateHosted(ctx context.Context, peer fabricauth.HostedPeer) (fabric.Principal, error) {
	principal, _, err := h.verified(ctx, peer)
	return principal, err
}
func (h *HostedRuntimeBindings) HostedFacts(ctx context.Context, peer fabricauth.HostedPeer) (*fabricauth.HostedCallerAuthority, error) {
	principal, scope, err := h.verified(ctx, peer)
	if err != nil {
		return nil, err
	}
	return h.profiles.CallerAuthority(ctx, scope, principal)
}

// ValidateOwner retains the existing local-managed guard via the mandatory
// chained guard. All original workers must be registered before serving sockets.
func (h *HostedRuntimeBindings) ValidateOwner(ctx context.Context, peer localpeer.ProcessSnapshot) error {
	if h == nil {
		return localDenied()
	}
	return h.guard.Validate(ctx, peer)
}
