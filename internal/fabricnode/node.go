// Package fabricnode composes the trusted local Fabric node with its genuine
// registry and replayable compact index. It never bootstraps missing identity.
package fabricnode

import (
	"context"
	"errors"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/fabric/telemetry"
)

type Config struct {
	Directory       string
	RegistryOptions registry.Options
	// Authentication and admission come from actual private peer/identity and
	// adapter composition, never from caller assertions or descriptor prose.
	Authenticator      fabric.Authenticator
	Bindings           dispatch.BindingResolver
	Admission          dispatch.Admission
	Interceptors       node.OperationInterceptors
	ValidateReadResult node.ReadResultValidator
	Events             events.EventBus
	Tracing            telemetry.Provider
}
type Node struct {
	Store      *registry.Store
	Service    *node.Service
	index      *search.Backend
	mu         sync.Mutex
	quarantine error
	closed     bool
}

// Open restores the retained registry and index history. Registration commands
// explicitly call registry.Bootstrap first; a missing/corrupt root is an error.
// It does not install providers, pull models, contact the cloud or run endpoints.
func Open(ctx context.Context, c Config) (*Node, error) {
	if ctx == nil || c.Directory == "" || c.Authenticator == nil || c.Bindings == nil || c.Admission == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Missing trusted local node composition")
	}
	options := c.RegistryOptions
	if options == (registry.Options{}) {
		options = registry.DefaultOptions()
	}
	store, err := registry.OpenWithOptions(ctx, c.Directory, options)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			store.Close()
		}
	}()
	index, err := store.LoadIndex(ctx, store.IndexConfig())
	if err != nil {
		return nil, err
	}
	d, err := dispatch.New(dispatch.Config{Audience: store.AuthorityIdentity().Namespace, Descriptors: store, Bindings: c.Bindings, Admission: c.Admission})
	if err != nil {
		return nil, err
	}
	n := &Node{Store: store, index: index}
	cfg := node.Config{Audience: store.AuthorityIdentity().Namespace, Authenticator: c.Authenticator, Search: n, Descriptors: store, Dispatcher: d, Interceptors: c.Interceptors, ValidateReadResult: c.ValidateReadResult, Events: c.Events, Tracing: c.Tracing}
	if c.Events != nil {
		cfg.EventSource = "pagnet://" + store.AuthorityIdentity().Namespace + "/node/local"
	}
	n.Service, err = node.New(cfg)
	if err != nil {
		return nil, err
	}
	keep = true
	return n, nil
}

// Synchronize publishes only bounded outbox pages. The caller schedules this
// after registration/synchronization; searches never scan or drain the registry.
// More means another explicit bounded pass is needed. An uncertain publication
// quarantines search until an explicit node reopen verifies durable history.
func (n *Node) Synchronize(ctx context.Context, maxPages int) (more bool, err error) {
	if ctx == nil || maxPages < 1 || maxPages > 4096 {
		return false, fabric.NewError(fabric.CodeInvalidInput, "Invalid index synchronization budget")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err = n.available(); err != nil {
		return false, err
	}
	for page := 0; page < maxPages; page++ {
		batch, e := n.Store.PendingIndex(ctx, 32)
		if e != nil {
			var structured *fabric.Error
			if errors.As(e, &structured) && structured.Code == fabric.CodeNotFound {
				return false, nil
			}
			return false, e
		}
		prepared, e := n.index.Prepare(ctx, batch)
		if e != nil {
			return false, e
		}
		if e = n.index.Publish(ctx, prepared, n.Store.CommitIndex); e != nil {
			n.quarantine = fabric.NewError(fabric.CodeTargetUnavailable, "Local index publication requires retained-history recovery")
			return false, n.quarantine
		}
	}
	_, e := n.Store.PendingIndex(ctx, 1)
	var structured *fabric.Error
	if errors.As(e, &structured) && structured.Code == fabric.CodeNotFound {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	return true, nil
}
func (n *Node) available() error {
	if n.closed {
		return fabric.NewError(fabric.CodeTargetUnavailable, "Local node closed")
	}
	return n.quarantine
}
func (n *Node) Search(ctx context.Context, r fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	if ctx == nil {
		return fabric.DiscoverResult{}, fabric.NewError(fabric.CodeInvalidInput, "Missing discovery context")
	}
	n.mu.Lock()
	err := n.available()
	index := n.index
	n.mu.Unlock()
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err := r.Validate(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	domain := n.Store.AuthorityIdentity().Namespace
	if len(r.Scope.Domains) == 0 {
		r.Scope.Domains = []string{domain}
	}
	for _, requested := range r.Scope.Domains {
		if requested != domain {
			return fabric.DiscoverResult{}, fabric.NewError(fabric.CodeUnsupported, "Remote discovery requires an explicitly configured federation binding")
		}
	}
	return index.Search(ctx, r)
}

// Close releases the registry's sole-writer lock. Transport owners must close
// their sessions/streams before closing the composed node.
func (n *Node) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	return n.Store.Close()
}

var _ node.SearchReader = (*Node)(nil)
