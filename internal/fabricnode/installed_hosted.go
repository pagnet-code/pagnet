// The installed hosted product: the fused local installation + cloud daemon
// composition. It links the actual owner guard, runtime bindings, invocation
// guard, sideports, catalog and admin over the loaded installation, and exposes
// the daemon-side components for daemon.Config. It is never enabled by the
// presence of a SID or a test fixture: a nil InstalledConfig.Hosted means the
// product is unavailable, and every deferred reference is fail-closed until the
// daemon exists and cmd/pagnet completes the wiring before the first host
// connection.

package fabricnode

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/daemon"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/localpeer"
)

// HostedNativeLaneAvailable reports whether this platform runs the daemon's
// native worker lane (the same GOOS gate as the daemon's native registry). The
// installed hosted product depends on that lane, so it is unavailable elsewhere;
// an explicit hosted request on a lane-less platform is a startup error, not a
// silent skip.
func HostedNativeLaneAvailable() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin"
}

// hostedNotWired is the honest error for a deferred hosted reference that has
// not been wired yet. It is never a silent no-op: an unwired call is a refusal.
func hostedNotWired(what string) error {
	return fabric.NewError(fabric.CodeTargetUnavailable, "Hosted product "+what+" is not wired yet")
}

// hostedDeferred holds the hosted references that cannot exist when
// OpenInstalled runs (they need the daemon, which cmd/pagnet creates later).
// Each is fail-closed until it is wired: the profile probe and owner-guard next
// are wired in OpenInstalled once the daemon/native runtime exists; the
// bindings, publisher and daemon are wired in cmd/pagnet after daemon.New and
// before the first host connection.
type hostedDeferred struct {
	mu           sync.RWMutex
	probeFn      fabricagent.OriginalHostedProbe
	nextFn       fabricauth.OwnerValidator
	bindingsRef  *HostedRuntimeBindings
	publisherRef *HostedCatalogPublisher
	daemonRef    *daemon.Daemon
}

func newHostedDeferred() *hostedDeferred { return &hostedDeferred{} }

func (h *hostedDeferred) setProbe(p fabricagent.OriginalHostedProbe) {
	if h == nil || p == nil {
		return
	}
	h.mu.Lock()
	h.probeFn = p
	h.mu.Unlock()
}
func (h *hostedDeferred) setNext(v fabricauth.OwnerValidator) {
	if h == nil || v == nil {
		return
	}
	h.mu.Lock()
	h.nextFn = v
	h.mu.Unlock()
}
func (h *hostedDeferred) setBindings(b *HostedRuntimeBindings) {
	if h == nil || b == nil {
		return
	}
	h.mu.Lock()
	h.bindingsRef = b
	h.mu.Unlock()
}
func (h *hostedDeferred) setPublisher(p *HostedCatalogPublisher) {
	if h == nil || p == nil {
		return
	}
	h.mu.Lock()
	h.publisherRef = p
	h.mu.Unlock()
}
func (h *hostedDeferred) setDaemon(d *daemon.Daemon) {
	if h == nil || d == nil {
		return
	}
	h.mu.Lock()
	h.daemonRef = d
	h.mu.Unlock()
}

// probe is the fail-closed profile probe (wired to the daemon's real
// original-worker inspection).
func (h *hostedDeferred) probe() fabricagent.OriginalHostedProbe {
	return func(ctx context.Context, p fabricagent.HostedProfile) error {
		if h == nil {
			return hostedNotWired("probe")
		}
		h.mu.RLock()
		pfn := h.probeFn
		h.mu.RUnlock()
		if pfn == nil {
			return hostedNotWired("probe")
		}
		return pfn(ctx, p)
	}
}
// ownerValidator is the fail-closed owner-guard `next` (wired to the local
// node's owner validator once the native runtime is composed).
func (h *hostedDeferred) ownerValidator() fabricauth.OwnerValidator {
	return func(ctx context.Context, peer localpeer.ProcessSnapshot) error {
		if h == nil {
			return hostedNotWired("owner validator")
		}
		h.mu.RLock()
		v := h.nextFn
		h.mu.RUnlock()
		if v == nil {
			return hostedNotWired("owner validator")
		}
		return v(ctx, peer)
	}
}
// hostedValidator is the fail-closed hosted-socket validator (wired to the
// composed runtime bindings).
func (h *hostedDeferred) hostedValidator() fabricauth.HostedValidator {
	return func(ctx context.Context, peer fabricauth.HostedPeer) (fabric.Principal, error) {
		if h == nil {
			return fabric.Principal{}, hostedNotWired("hosted validator")
		}
		h.mu.RLock()
		b := h.bindingsRef
		h.mu.RUnlock()
		if b == nil {
			return fabric.Principal{}, hostedNotWired("hosted validator")
		}
		return b.ValidateHosted(ctx, peer)
	}
}
// hostedFacts is the fail-closed hosted-socket facts provider.
func (h *hostedDeferred) hostedFacts() fabricauth.HostedFactsProvider {
	return func(ctx context.Context, peer fabricauth.HostedPeer) (*fabricauth.HostedCallerAuthority, error) {
		if h == nil {
			return nil, hostedNotWired("hosted facts")
		}
		h.mu.RLock()
		b := h.bindingsRef
		h.mu.RUnlock()
		if b == nil {
			return nil, hostedNotWired("hosted facts")
		}
		return b.HostedFacts(ctx, peer)
	}
}
// resolveHosted is the fail-closed hosted-socket resolver.
func (h *hostedDeferred) resolveHosted() fabrichost.HostedResolver {
	return func(ctx context.Context, sel fabrichost.HostedSelector) (fabricauth.HostedActivation, error) {
		if h == nil {
			return fabricauth.HostedActivation{}, hostedNotWired("hosted resolver")
		}
		h.mu.RLock()
		b := h.bindingsRef
		h.mu.RUnlock()
		if b == nil {
			return fabricauth.HostedActivation{}, hostedNotWired("hosted resolver")
		}
		return b.ResolveHosted(ctx, sel)
	}
}
// publisher is the (possibly nil) catalog publisher for admin handlers; nil is
// an honest refusal, never a silent no-op.
func (h *hostedDeferred) publisher() *HostedCatalogPublisher {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.publisherRef
}
// daemon is the (possibly nil) daemon for admin acts; nil is an honest refusal.
func (h *hostedDeferred) daemon() *daemon.Daemon {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.daemonRef
}

// InstalledHostedConfig is the explicit installed hosted product. A nil
// InstalledConfig.Hosted means the product is unavailable (explicit, never
// implicit).
type InstalledHostedConfig struct {
	// Probe is an explicit profile probe. Nil = the daemon's real
	// original-worker inspection, wired after daemon.New (fail-closed until
	// then).
	Probe fabricagent.OriginalHostedProbe
	// InvocationLimits bound the signed initial-effect journal. Zero = the
	// finite product default; explicit override; never unlimited.
	InvocationLimits fabricagent.HostedInvocationLimits
}

// DefaultHostedInvocationLimits is the finite product default for the signed
// initial-effect journal (used when InstalledHostedConfig.InvocationLimits is
// zero). It is finite on both axes; it is never unlimited.
var DefaultHostedInvocationLimits = fabricagent.HostedInvocationLimits{MaxInvocations: 4096, MaxBytes: 256 << 20}

// InstalledHosted is the composed installed hosted product. The daemon-side
// components (owner guard, invocation guard, sideports) are handed to
// daemon.Config; the runtime bindings and catalog publisher are set
// post-daemon (they need the daemon, which does not exist when OpenInstalled
// runs).
type InstalledHosted struct {
	Profiles        *fabricagent.HostedProfiles
	Invocations     *fabricagent.HostedInvocations
	OwnerGuard      *daemon.HostedOwnerGuard
	InvocationGuard *daemon.HostedInvocationGuard
	Sideports       *daemon.HostedFabricSideports
	// Resolve is the node's selected-binding wiring shared by the invocation
	// guard and the sideport association: the exact registered descriptor, its
	// hosted-native binding and the installed profile, matched by instance.
	Resolve func(context.Context, string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error)
	// SearchBackend is the node's real search backend (the step-5 import feed
	// target).
	SearchBackend *search.Backend
	node          *InstalledNode
	deferred      *hostedDeferred
}

// SetProbe wires the profile probe (post-daemon).
func (h *InstalledHosted) SetProbe(p fabricagent.OriginalHostedProbe) {
	if h != nil && h.deferred != nil {
		h.deferred.setProbe(p)
	}
}
// SetOwnerValidator wires the owner-guard next (once the native runtime is
// composed).
func (h *InstalledHosted) SetOwnerValidator(v fabricauth.OwnerValidator) {
	if h != nil && h.deferred != nil {
		h.deferred.setNext(v)
	}
}
// SetBindings wires the composed runtime bindings (post-daemon).
func (h *InstalledHosted) SetBindings(b *HostedRuntimeBindings) {
	if h != nil && h.deferred != nil {
		h.deferred.setBindings(b)
	}
}
// SetPublisher wires the catalog publisher (post-daemon).
func (h *InstalledHosted) SetPublisher(p *HostedCatalogPublisher) {
	if h != nil && h.deferred != nil {
		h.deferred.setPublisher(p)
	}
}
// SetDaemon wires the daemon reference (post-daemon).
func (h *InstalledHosted) SetDaemon(d *daemon.Daemon) {
	if h != nil && h.deferred != nil {
		h.deferred.setDaemon(d)
	}
}

// HostedValidator / HostedFacts / ResolveHosted are the fail-closed closures
// the node's authenticator and host listener use. They are non-nil at
// construction (so SupportsHosted holds at fabrichost.Start) and deny until the
// bindings are wired.
func (h *InstalledHosted) HostedValidator() fabricauth.HostedValidator {
	if h == nil || h.deferred == nil {
		return func(context.Context, fabricauth.HostedPeer) (fabric.Principal, error) {
			return fabric.Principal{}, hostedNotWired("hosted validator")
		}
	}
	return h.deferred.hostedValidator()
}
func (h *InstalledHosted) HostedFacts() fabricauth.HostedFactsProvider {
	if h == nil || h.deferred == nil {
		return func(context.Context, fabricauth.HostedPeer) (*fabricauth.HostedCallerAuthority, error) {
			return nil, hostedNotWired("hosted facts")
		}
	}
	return h.deferred.hostedFacts()
}
func (h *InstalledHosted) ResolveHosted() fabrichost.HostedResolver {
	if h == nil || h.deferred == nil {
		return func(context.Context, fabrichost.HostedSelector) (fabricauth.HostedActivation, error) {
			return fabricauth.HostedActivation{}, hostedNotWired("hosted resolver")
		}
	}
	return h.deferred.resolveHosted()
}

// Wired reports whether the product's deferred references are all wired. It is
// the advertisement gate's companion: a product that is not wired is not ready.
func (h *InstalledHosted) Wired() bool {
	if h == nil || h.deferred == nil {
		return false
	}
	h.deferred.mu.RLock()
	defer h.deferred.mu.RUnlock()
	return h.deferred.probeFn != nil && h.deferred.nextFn != nil && h.deferred.bindingsRef != nil
}

// hostedNativeBinding is one installed hosted-native association: the exact
// registered descriptor, its selected-binding scope and the installed profile.
type hostedNativeBinding struct {
	Descriptor fabric.EndpointDescriptor
	Scope      registry.DescriptorBatchScope
	Profile    fabricagent.HostedProfile
}

// hostedNativeBindings lists the installation's non-retired endpoints carrying
// the hosted-native binding, with their current descriptor, scope and installed
// profile. This is the node's selection authority — never caller-supplied
// identity. Endpoints without an installed profile are skipped (the binding
// exists but the profile is not yet installed).
func (n *InstalledNode) hostedNativeBindings(ctx context.Context, profiles *fabricagent.HostedProfiles) ([]hostedNativeBinding, error) {
	if n == nil || n.Installation == nil || profiles == nil || ctx == nil {
		return nil, localDenied()
	}
	store := n.Installation.Store
	owner, err := n.Installation.Operator(ctx)
	if err != nil {
		return nil, err
	}
	var out []hostedNativeBinding
	cursor := ""
	for {
		page, err := store.ListEndpointHeads(ctx, owner, cursor, 100)
		if err != nil {
			return nil, err
		}
		for _, head := range page.Heads {
			if head.Retired {
				continue
			}
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
			scope := registry.DescriptorBatchScope{Endpoint: head.Ref, ExpectedEndpointRevision: descriptor.Revision, BindingID: binding}
			profile, _, err := profiles.Get(ctx, scope)
			if err != nil {
				continue
			}
			out = append(out, hostedNativeBinding{Descriptor: descriptor, Scope: scope, Profile: profile})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, nil
}

// hostedNativeResolvePort is the node's selected-binding wiring: the exact
// registered descriptor, its hosted-native binding and the installed profile,
// matched by instance. Never a value taken from a delivery payload.
func (n *InstalledNode) hostedNativeResolvePort(profiles *fabricagent.HostedProfiles) func(context.Context, string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error) {
	return func(ctx context.Context, instanceID string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error) {
		bindings, err := n.hostedNativeBindings(ctx, profiles)
		if err != nil {
			return registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, err
		}
		for _, b := range bindings {
			if b.Profile.Scope.InstanceID == instanceID {
				return b.Scope, b.Profile, nil
			}
		}
		return registry.DescriptorBatchScope{}, fabricagent.HostedProfile{},
			fabric.NewError(fabric.CodeNotFound, "Hosted native instance is not bound to a selected binding")
	}
}

// hostedNativeCaller is the node-composed authenticated context of the local
// hosted actor: the principal bound to the (single) installed hosted-native
// endpoint, composed from its signed registered descriptor — never delivery
// data. The HostedOwner port is endpoint-agnostic, so the product composes one
// hosted actor: exactly one installed hosted binding is required (the
// single-hosted-actor model); zero or more is an honest refusal.
func (n *InstalledNode) hostedNativeCaller(profiles *fabricagent.HostedProfiles) fabricagent.HostedOwner {
	store := n.Installation.Store
	return func(ctx context.Context) (fabric.ExecutionContext, error) {
		bindings, err := n.hostedNativeBindings(ctx, profiles)
		if err != nil {
			return fabric.ExecutionContext{}, err
		}
		if len(bindings) != 1 {
			return fabric.ExecutionContext{},
				fabric.NewError(fabric.CodeTargetUnavailable, "Hosted native caller requires exactly one installed hosted binding")
		}
		b := bindings[0]
		descriptorBytes, err := json.Marshal(b.Descriptor)
		if err != nil {
			return fabric.ExecutionContext{}, err
		}
		principal := fabric.Principal{Ref: b.Descriptor.Ref.String(), Kind: b.Descriptor.Kind, Issuer: store.Namespace()}
		return fabric.NewAuthenticatedContext(principal, store.Namespace(), descriptorBytes)
	}
}

// newInstalledHosted composes the installed hosted product over the loaded
// installation and the composed native runtime. The daemon-side components are
// created here (they need the installation, not the daemon); the runtime
// bindings and catalog publisher are set post-daemon.
func newInstalledHosted(ctx context.Context, n *InstalledNode, cfg InstalledHostedConfig, deferred *hostedDeferred, ownerGuard *daemon.HostedOwnerGuard, searchBackend *search.Backend) (*InstalledHosted, error) {
	if ctx == nil || n == nil || n.Installation == nil || n.Runtime == nil || deferred == nil || ownerGuard == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Missing installed hosted composition resources")
	}
	store := n.Installation.Store
	owner := func(ctx context.Context) (fabric.ExecutionContext, error) { return n.Installation.Operator(ctx) }
	probe := cfg.Probe
	if probe == nil {
		probe = deferred.probe()
	}
	limits := cfg.InvocationLimits
	if limits == (fabricagent.HostedInvocationLimits{}) {
		limits = DefaultHostedInvocationLimits
	}
	profiles, err := fabricagent.NewHostedProfiles(ctx, store, owner, n.Installation.Keys, probe)
	if err != nil {
		return nil, err
	}
	resolve := n.hostedNativeResolvePort(profiles)
	caller := n.hostedNativeCaller(profiles)
	journal, err := fabricagent.NewHostedInvocations(ctx, store, profiles, n.Installation.Keys, limits)
	if err != nil {
		return nil, err
	}
	invocationGuard := daemon.NewHostedInvocationGuard(journal, caller, resolve)
	sideports := daemon.NewHostedFabricSideports(resolve)
	return &InstalledHosted{
		Profiles:        profiles,
		Invocations:     journal,
		OwnerGuard:      ownerGuard,
		InvocationGuard: invocationGuard,
		Sideports:       sideports,
		Resolve:         resolve,
		SearchBackend:   searchBackend,
		node:            n,
		deferred:        deferred,
	}, nil
}

// Networks returns the networks of the node's installed hosted bindings (the
// networks whose hosted catalog the daemon imports). Empty = the daemon imports
// nothing (a nil importer). The daemon reads it once at composition, so the
// importer's network set is fixed at serve startup: a binding created after
// startup is imported from the next serve restart.
func (h *InstalledHosted) Networks() []string {
	if h == nil || h.node == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bindings, err := h.node.hostedNativeBindings(ctx, h.Profiles)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(bindings))
	for _, b := range bindings {
		if b.Profile.NetworkID != "" && !seen[b.Profile.NetworkID] {
			seen[b.Profile.NetworkID] = true
			out = append(out, b.Profile.NetworkID)
		}
	}
	return out
}
