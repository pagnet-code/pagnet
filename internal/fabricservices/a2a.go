package fabricservices

import (
	"context"
	"net/http"
	"sync"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/a2a"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// A2AConnections owns explicit selected SDK adapters, sharing the SAME private
// profile and root replay/association ledger. DisclosureGate is mandatory
// actual external-provider policy; installation/URL alone grants no permission.
type A2AConnections struct {
	profiles    *ProfileStore
	ledger      *Invocations
	credentials CredentialProvider
	disclosure  a2a.DisclosureGate
	max         int
	mu          sync.Mutex
	entries     map[string]*connectedA2A
	closed      bool
	sources     int
	closeDone   chan struct{}
	closeErr    error
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}
type connectedA2A struct {
	adapter     *a2a.Adapter
	scope       registry.DescriptorBatchScope
	profile     Profile
	generation  uint64
	fingerprint [32]byte
}

func NewA2AConnections(p *ProfileStore, i *Invocations, credentials CredentialProvider, disclosure a2a.DisclosureGate, max int) (*A2AConnections, error) {
	if p == nil || i == nil || i.profiles != p || credentials == nil || disclosure == nil || max < 1 || max > 256 {
		return nil, denied()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &A2AConnections{profiles: p, ledger: i, credentials: credentials, disclosure: disclosure, max: max, entries: map[string]*connectedA2A{}, ctx: ctx, cancel: cancel, closeDone: make(chan struct{})}, nil
}

// Connect is explicit setup from an operator-selected exact retained AgentCard
// and interface. It never fetches/discovers a card or starts a model/server.
func (c *A2AConnections) Connect(ctx context.Context, scope registry.DescriptorBatchScope) error {
	if c == nil || ctx == nil {
		return denied()
	}
	p, gen, e := c.profiles.Get(ctx, scope)
	if e != nil {
		return e
	}
	if p.Protocol != "a2a.jsonrpc" || p.A2A == nil {
		return denied()
	}
	fp := Fingerprint(scope, p, gen)
	store, e := NewA2AAssociations(c.ledger, scope, fp)
	if e != nil {
		return e
	}
	creds := func(ctx context.Context, _ fabric.ExecutionContext, selected sdk.AgentInterface) (http.Header, error) {
		if selected != p.A2A.Interface {
			return nil, denied()
		}
		v, e := c.credentials.Resolve(ctx, p.CredentialSelector)
		if e != nil || v.BindingDigest != p.BindingDigest || len(v.MCP.Environment) != 0 || len(v.MCP.Headers) > 64 {
			return nil, denied()
		}
		h := http.Header{}
		n := 0
		for k, v := range v.MCP.Headers {
			n += len(k) + len(v)
			if n > 64<<10 {
				return nil, denied()
			}
			h.Set(k, v)
		}
		return h, nil
	}
	descriptor, e := c.profiles.store.GetEndpoint(ctx, scope.Endpoint, scope.ExpectedEndpointRevision)
	if e != nil {
		return e
	}
	rootIdempotency := false
	for _, binding := range descriptor.Bindings {
		if binding.ID == scope.BindingID {
			rootIdempotency = binding.Idempotency
		}
	}
	if rootIdempotency && !store.SupportsRootIdempotency() {
		return fabric.NewError(fabric.CodeUnsupported, "Service replay policy is not configured")
	}
	adapter, e := a2a.New(a2a.Config{RootIdempotency: rootIdempotency, Ref: scope.Endpoint, Revision: scope.ExpectedEndpointRevision, BindingID: scope.BindingID, Audience: c.profiles.root.Namespace, BindingDigest: p.BindingDigest, Card: p.A2A.Card, Interface: p.A2A.Interface, Credentials: creds, DisclosureGate: c.disclosure, Associations: store, AllowHTTP: p.A2A.AllowHTTP, Cancellation: p.A2A.Cancellation, Limits: p.A2A.Limits})
	if e != nil {
		return e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := connectionKey(scope)
	if c.closed || c.entries[key] != nil || len(c.entries) >= c.max {
		adapter.Close()
		return denied()
	}
	c.entries[key] = &connectedA2A{adapter, scope, p, gen, fp}
	return nil
}
func (c *A2AConnections) Resolve(ctx context.Context, scope registry.DescriptorBatchScope) (fabric.EndpointAdapter, [32]byte, error) {
	if c == nil {
		return nil, [32]byte{}, denied()
	}
	c.mu.Lock()
	entry := c.entries[connectionKey(scope)]
	closed := c.closed
	c.mu.Unlock()
	if closed || entry == nil {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeTargetUnavailable, "Selected A2A service is not connected")
	}
	p, gen, e := c.profiles.Get(ctx, scope)
	if e != nil || gen != entry.generation || scope != entry.scope || !sameProfile(p, entry.profile) {
		return nil, [32]byte{}, denied()
	}
	return &guardedA2A{c, entry}, entry.fingerprint, nil
}

type guardedA2A struct {
	connections *A2AConnections
	entry       *connectedA2A
}

func (a *guardedA2A) Invoke(ctx context.Context, caller fabric.ExecutionContext, d fabric.EndpointDescriptor, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	if d.Ref != a.entry.scope.Endpoint || d.Revision != a.entry.scope.ExpectedEndpointRevision || caller.VerifyAuthenticated(a.connections.profiles.root.Namespace) != nil {
		return nil, denied()
	}
	if _, _, e := a.connections.Resolve(ctx, a.entry.scope); e != nil {
		return nil, e
	}
	// Pin the currently selected credential account outside SQL even for a
	// retained alias; changed provider-account resolution cannot expose old data.
	credential, e := a.connections.credentials.Resolve(ctx, a.entry.profile.CredentialSelector)
	if e != nil || credential.BindingDigest != a.entry.profile.BindingDigest {
		return nil, denied()
	}
	// Lookups do not authorize a fresh send. The SDK AssociationStore performs
	// the actual first FULL Reserve before the original call on absent receipts.
	receipt, e := a.connections.ledger.FindExact(ctx, caller, a.entry.scope, a.entry.fingerprint, r)
	if e == nil {
		if !receipt.Terminal {
			return nil, &fabric.Error{Code: "service.REPLAY_UNKNOWN", Message: "Original A2A invocation was attempted; its outcome is not known", Effect: fabric.EffectUnknown}
		}
		return newReplayStream(ctx, a.connections.ledger, caller, receipt), nil
	}
	if !missing(e) {
		return nil, e
	}
	releaseSource, finishCall, e := a.connections.reserveSourceSlot()
	if e != nil {
		return nil, e
	}
	defer finishCall()
	transferred := false
	defer func() {
		if !transferred {
			releaseSource()
		}
	}()
	slot := &sourceCaptureSlot{ledger: a.connections.ledger, parent: a.connections.ctx, provider: a.entry, beginDrain: a.connections.beginSourceDrain, releaseSource: releaseSource}
	owned, cancel := context.WithCancel(context.WithoutCancel(ctx))
	if r.Deadline != nil {
		var stop context.CancelFunc
		owned, stop = context.WithDeadline(owned, *r.Deadline)
		previous := cancel
		cancel = func() { stop(); previous() }
	}
	parentStop := context.AfterFunc(a.connections.ctx, cancel)
	owned = context.WithValue(owned, sourceCaptureSlotKey{}, slot)
	stream, e := a.entry.adapter.Invoke(owned, caller, d, r)
	if e != nil {
		parentStop()
		cancel()
		if slot.capture.Load() != nil {
			slot.capture.Load().close()
		}
		return nil, e
	}
	if slot.capture.Load() == nil {
		stream.Close()
		parentStop()
		cancel()
		return nil, denied()
	}
	// The source capability was minted inside the genuine SDK's first FULL Admit,
	// before its original send. Reading after the send never reauthenticates a
	// dropped caller or substitutes another source.
	capture := slot.capture.Load()
	transferred = true
	originalCancel := capture.cancel
	originalStop := capture.stopParent
	capture.cancel = func() { cancel(); originalCancel() }
	capture.stopParent = func() bool { parentStop(); return originalStop() }
	return &retainedStream{InvocationStream: stream, ledger: a.connections.ledger, caller: caller, receipt: capture.receipt, ctx: ctx, capture: capture}, nil

}
func (c *A2AConnections) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		done := c.closeDone
		c.mu.Unlock()
		<-done
		c.mu.Lock()
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	c.closed = true
	c.cancel()
	entries := c.entries
	c.entries = map[string]*connectedA2A{}
	c.mu.Unlock()
	c.wg.Wait()
	var first error
	for _, entry := range entries {
		if e := entry.adapter.Close(); e != nil && first == nil {
			first = e
		}
	}
	c.mu.Lock()
	c.closeErr = first
	close(c.closeDone)
	c.mu.Unlock()
	return first
}

func (c *A2AConnections) beginSourceDrain() (func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, denied()
	}
	c.wg.Add(1)
	return c.wg.Done, nil
}

// reserveSourceSlot bounds independent original source lifetimes, including
// SDK calls and detached drains, by the explicit connection capacity. It runs
// before a FULL paid reservation; a later detach cannot exhaust new capacity.
func (c *A2AConnections) reserveSourceSlot() (func(), func(), error) {
	c.mu.Lock()
	if c.closed || c.sources >= c.max {
		c.mu.Unlock()
		return nil, nil, fabric.NewError(fabric.CodeTargetUnavailable, "Original service source capacity exhausted")
	}
	c.sources++
	c.wg.Add(1)
	c.mu.Unlock()
	var once sync.Once
	release := func() { once.Do(func() { c.mu.Lock(); c.sources--; c.mu.Unlock() }) }
	return release, c.wg.Done, nil
}
