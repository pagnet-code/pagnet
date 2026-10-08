package fabricnode

// Per-link destination serving runtime (E1 slice-2b).
//
// Each destination link is a REAL composed node execution stack over the
// installed store: a per-link RemoteBoundary (live trust + exposure checks),
// a per-link retained invocation ledger (policy = that boundary), per-link
// service connections + router, retained final outputs and the federation
// admission ledger. A link's runtime is cached per channel ID and recomposed
// only when the peer identity revision or the link record revision changes.
// All singletons (admission ledger, final output, invocation ledger
// configuration) use the installed product's D5 fixed limits so every link's
// composition observes the same persisted configuration.

import (
	"context"
	"errors"
	"time"

	sdka2a "github.com/a2aproject/a2a-go/v2/a2a"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricfederation"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

// D5 product constants (fixed values, all links identical):
//
//	verify limits    — MaxLifetime 5 minutes, MaxClockSkew 0 (synchronized clocks;
//	                   30-second bundle lifetimes leave headroom)
//	admission limits — 100_000 invocations / 1 GiB (admission quota, not bytes)
//	max records      — 4096 (ConnStream)
//	max bytes        — 128 MiB (duplex)
//	conn lifetime    — 5 minutes
//	max active       — 8 (per-link concurrent execution pipelines)
//	final outputs    — the existing DefaultFinalOutputLimits (64, 64 MiB, 4096)
const (
	federationServingConnLifetime = 5 * time.Minute
	federationServingMaxActive    = 8
	federationServingMaxBytes     = uint64(128 << 20)
	federationServingMaxRecords   = uint64(4096)
)

var (
	federationServingVerifyLimits = federation.VerifyLimits{
		MaxLifetime:  5 * time.Minute,
		MaxClockSkew: 0,
	}
	federationServingAdmissionLimits = federation.AdmissionLimits{
		MaxInvocations: 100000,
		MaxBytes:       1 << 30,
	}
)

// linkServing is one composed per-link serving stack. It is immutable while
// serving; recomposition replaces the cache entry, never mutates it.
type linkServing struct {
	channel        [32]byte
	configuration  federation.Config
	linkRevision   uint64
	localRevision  uint64
	remoteRevision uint64

	boundary    *RemoteBoundary
	node        *Node
	connections *fabricservices.Connections
	a2a         *fabricservices.A2AConnections
	runtime     *FederationRuntime
}

// current reports whether this composition still matches the link and both
// peer identity revisions.
func (s *linkServing) current(linkRevision, localRevision, remoteRevision uint64) bool {
	return s != nil && s.linkRevision == linkRevision && s.localRevision == localRevision && s.remoteRevision == remoteRevision
}

// Close retires the link stack in dependency order: execution first, then the
// composed node, then the service connections. A bounded join timeout never
// turns an incomplete join into a successful close.
func (s *linkServing) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var e error
	if s.runtime != nil {
		e = errors.Join(e, s.runtime.Close(ctx))
	}
	if s.node != nil {
		e = errors.Join(e, s.node.CloseContext(ctx))
	}
	if s.connections != nil {
		e = errors.Join(e, s.connections.Close())
	}
	if s.a2a != nil {
		e = errors.Join(e, s.a2a.Close())
	}
	return e
}

// composeFederationLink builds the complete per-link destination serving
// stack for one destination link. Every check is live: peer identity,
// exposure record, service catalog and singleton ledgers are read from the
// installed store at composition time. A missing exposure record fails
// composition (fail-closed: the relay closes the connection and the bundle
// never executes). The profiles store is supplied by the relay (shared by
// every link) so this function never takes the relay lock.
func (n *InstalledNode) composeFederationLink(ctx context.Context, relay *federationRelay, channel [32]byte, link FederationLink, linkRevision uint64, localCertified, remoteCertified registry.CertifiedPeer, profiles *fabricservices.ProfileStore) (*linkServing, error) {
	installation := n.Installation
	store := installation.Store
	keys := installation.Keys
	owner := func(ctx context.Context) (fabric.ExecutionContext, error) { return installation.Operator(ctx) }

	// 1. Per-link trust gate + boundary.
	localBinding, e := fabricfederation.Binding(localCertified)
	if e != nil {
		return nil, e
	}
	remoteBinding, e := fabricfederation.Binding(remoteCertified)
	if e != nil {
		return nil, e
	}
	gate, e := fabricfederation.New(ctx, fabricfederation.Config{
		Peers:  n.Federation.Peers,
		Owner:  owner,
		Local:  localCertified,
		Remote: remoteCertified,
	})
	if e != nil {
		return nil, e
	}
	configuration := federation.Config{
		Local:      localBinding,
		Remote:     remoteBinding,
		Keys:       n.Federation.ExchangeKeys,
		Trust:      gate,
		Channel:    link.Channel,
		SourceRole: false,
		MaxRecords: federationServingMaxRecords,
	}
	boundary, e := NewRemoteBoundary(ctx, n.Runtime.Boundary, gate, n.Federation.Exposures, configuration, federationServingVerifyLimits)
	if e != nil {
		return nil, e
	}

	if profiles == nil {
		return nil, localDenied()
	}

	// 3. Per-link retained invocation ledger (policy = per-link boundary).
	var ledger *fabricservices.Invocations
	if n.Services != nil {
		ledger, e = fabricservices.OpenInvocations(ctx, profiles, n.Services.config.InvocationConfig, boundary)
	} else {
		ledger, e = fabricservices.BootstrapInvocations(ctx, profiles, fabricservices.DefaultInvocationConfig(), boundary)
	}
	if e != nil {
		return nil, e
	}

	// 4. Per-link service connections + router. The installed ServiceRuntime's
	// connections are bound to the local boundary's ledger and cannot serve
	// remote callers (ledger identity + remote dispatch stamp), so every link
	// composes its own connections and router over the same installed
	// profiles, credentials and descriptors.
	var (
		connections *fabricservices.Connections
		a2a         *fabricservices.A2AConnections
		providers   = map[BindingProtocol]BindingProvider{
			{Protocol: "local.native", Version: "1"}: n.Runtime.BindingProvider,
		}
	)
	if n.Services != nil {
		credentials := n.Services.config.Credentials
		connections, e = fabricservices.NewConnections(profiles, credentials, ledger, n.Services.config.MaxConnections)
		if e != nil {
			return nil, e
		}
		a2a, e = fabricservices.NewA2AConnections(profiles, ledger, credentials, func(ctx context.Context, caller fabric.ExecutionContext, d fabric.EndpointDescriptor, _ fabric.InvokeRequest) error {
			return boundary.WithCurrent(ctx, caller, d, func(context.Context) error { return nil })
		}, n.Services.config.MaxConnections)
		if e != nil {
			return nil, e
		}
		if e = relay.connectExposedServices(ctx, n, connections, a2a, link); e != nil {
			return nil, e
		}
		mcpProvider, e := NewServiceBindingProvider(connections)
		if e != nil {
			return nil, e
		}
		for _, version := range sdkmcp.SupportedProtocolVersions() {
			providers[BindingProtocol{Protocol: "mcp.tools", Version: version}] = mcpProvider
		}
		a2aProvider, e := NewA2AServiceBindingProvider(a2a)
		if e != nil {
			return nil, e
		}
		providers[BindingProtocol{Protocol: "a2a.jsonrpc", Version: string(sdka2a.Version)}] = a2aProvider
	}
	router, e := NewRouter(providers)
	if e != nil {
		return nil, e
	}

	// 5. Composed node execution stack over the retained store. The boundary
	// is both the authenticator and the admission policy; there is no extra
	// close resource to own.
	node, e := ComposeRetained(ctx, store, func(context.Context, *registry.Store, *search.Backend) (Ports, error) {
		ports := Ports{
			Authenticator:       boundary,
			Bindings:            router,
			Admission:           boundary,
			InvocationPlacement: extension.PlacementDestination,
		}
		if n.Extensions != nil {
			ports.Interceptors = n.Extensions
		}
		return ports, nil
	})
	if e != nil {
		return nil, errors.Join(e, (&linkServing{connections: connections, a2a: a2a}).Close(ctx))
	}

	// 6. Retained final outputs: per-store singleton, opened when the
	// installed setup path already bootstrapped it, bootstrapped with the
	// D5 defaults otherwise.
	final, e := OpenFinalOutputs(ctx, boundary, ledger, keys)
	if e != nil {
		var missing *fabric.Error
		if !errors.As(e, &missing) || missing.Code != fabric.CodeNotFound {
			return nil, errors.Join(e, node.CloseContext(ctx), (&linkServing{connections: connections, a2a: a2a}).Close(ctx))
		}
		final, e = BootstrapFinalOutputs(ctx, boundary, ledger, keys, DefaultFinalOutputLimits)
		if e != nil {
			return nil, errors.Join(e, node.CloseContext(ctx), (&linkServing{connections: connections, a2a: a2a}).Close(ctx))
		}
	}

	// 7. Federation admission ledger: per-store singleton, same pattern.
	admissions, e := federation.OpenAdmissionLedger(ctx, federation.AdmissionConfig{
		Store:        store,
		Owner:        owner,
		Protector:    keys,
		Peers:        boundary.peers,
		Policy:       boundary.FederationAdmissionPolicy(),
		Limits:       federationServingAdmissionLimits,
		Verification: federationServingVerifyLimits,
	})
	if e != nil {
		var missing *fabric.Error
		if !errors.As(e, &missing) || missing.Code != fabric.CodeNotFound {
			return nil, errors.Join(e, node.CloseContext(ctx), (&linkServing{connections: connections, a2a: a2a}).Close(ctx))
		}
		admissions, e = federation.BootstrapAdmissionLedger(ctx, federation.AdmissionConfig{
			Store:        store,
			Owner:        owner,
			Protector:    keys,
			Peers:        boundary.peers,
			Policy:       boundary.FederationAdmissionPolicy(),
			Limits:       federationServingAdmissionLimits,
			Verification: federationServingVerifyLimits,
		})
		if e != nil {
			return nil, errors.Join(e, node.CloseContext(ctx), (&linkServing{connections: connections, a2a: a2a}).Close(ctx))
		}
	}

	runtime, e := NewFederationRuntime(FederationRuntimeConfig{
		Boundary:   boundary,
		Node:       node,
		Admissions: admissions,
		Outputs:    final,
		Lifetime:   relay.lifetime,
		MaxActive:  federationServingMaxActive,
	})
	if e != nil {
		return nil, errors.Join(e, node.CloseContext(ctx), (&linkServing{connections: connections, a2a: a2a}).Close(ctx))
	}

	return &linkServing{
		channel:        channel,
		configuration:  configuration,
		linkRevision:   linkRevision,
		localRevision:  localCertified.Revision,
		remoteRevision: remoteCertified.Revision,
		boundary:       boundary,
		node:           node,
		connections:    connections,
		a2a:            a2a,
		runtime:        runtime,
	}, nil
}

// connectExposedServices connects the per-link service stack to every
// exposure whose remote domain is this link's remote namespace. An exposure
// pins either an exact published offer (MCP/A2A) or an endpoint: the pinned
// record is re-verified at composition time and the connection scope is the
// live endpoint with the exposed binding (the same scope the dispatch path
// resolves). Any missing or stale record fails composition (fail-closed: the
// relay closes the connection and the bundle never executes).
func (r *federationRelay) connectExposedServices(ctx context.Context, n *InstalledNode, connections *fabricservices.Connections, a2a *fabricservices.A2AConnections, link FederationLink) error {
	configuration, _, e := n.Federation.Exposures.Current(ctx)
	if e != nil {
		return e
	}
	store := n.Installation.Store
	for _, exposure := range configuration.Exposures {
		if exposure.RemoteDomain != link.RemoteNamespace {
			continue
		}
		endpointRef := exposure.Target
		if exposure.Target.IsOffer() {
			offer, e := store.GetOffer(ctx, exposure.Target, exposure.Revision)
			if e != nil {
				return e
			}
			if offer.BindingID != exposure.BindingID {
				return fabric.NewError(fabric.CodeInvalidInput, "exposure binding does not match the pinned offer")
			}
			endpointRef = exposure.Target.Endpoint()
		}
		descriptor, e := store.GetEndpoint(ctx, endpointRef, "")
		if e != nil {
			return e
		}
		var binding *fabric.BindingSummary
		for i := range descriptor.Bindings {
			if descriptor.Bindings[i].ID == exposure.BindingID {
				binding = &descriptor.Bindings[i]
				break
			}
		}
		if binding == nil {
			return fabric.NewError(fabric.CodeInvalidInput, "exposure binding is not published on the endpoint")
		}
		scope := registry.DescriptorBatchScope{
			Endpoint:               endpointRef,
			ExpectedEndpointRevision: descriptor.Revision,
			BindingID:              exposure.BindingID,
		}
		switch binding.Protocol {
		case "mcp.tools":
			if e = connections.ConnectMCP(ctx, scope, false); e != nil {
				return e
			}
		case "a2a.jsonrpc":
			if e = a2a.Connect(ctx, scope); e != nil {
				return e
			}
		}
	}
	return nil
}
