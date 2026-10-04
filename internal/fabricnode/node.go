// Package fabricnode composes the trusted local Fabric node with its genuine
// registry and replayable compact index. It never bootstraps missing identity.
package fabricnode

import (
	"context"
	"errors"
	"io"
	"path/filepath"
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
	// Compose receives the one actual retained store and restored compact index.
	// It must not reopen the registry or manufacture a replacement root.
	Compose func(context.Context, *registry.Store, *search.Backend) (Ports, error)
}

type Ports struct {
	// Authentication and admission come from actual private peer/identity and
	// adapter composition, never from caller assertions or descriptor prose.
	Authenticator      fabric.Authenticator
	Bindings           dispatch.BindingResolver
	Admission          dispatch.Admission
	Interceptors       node.OperationInterceptors
	ValidateReadResult node.ReadResultValidator
	Events             events.EventBus
	Tracing            telemetry.Provider
	// Search is optional explicit hybrid backend composition; nil uses
	// the embedded lexical backend. Close owns any provider/session resources.
	Search node.SearchReader
	Close  io.Closer
}
type Node struct {
	Store      *registry.Store
	Service    *node.Service
	index      *search.Backend
	reader     node.SearchReader
	resources  io.Closer
	directory  string
	mu         sync.Mutex
	quarantine error
	closed     bool
}

// Open restores the retained registry and index history. Registration commands
// explicitly call registry.Bootstrap first; a missing/corrupt root is an error.
// It does not install providers, pull models, contact the cloud or run endpoints.
func Open(ctx context.Context, c Config) (*Node, error) {
	if ctx == nil || c.Directory == "" || c.Compose == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Missing trusted local node composition")
	}
	options := c.RegistryOptions
	if options == (registry.Options{}) {
		options = registry.DefaultOptions()
	}
	directory, err := filepath.Abs(c.Directory)
	if err != nil {
		return nil, err
	}
	store, err := registry.OpenWithOptions(ctx, directory, options)
	if err != nil {
		return nil, err
	}
	keep := false
	var resources io.Closer
	defer func() {
		if !keep {
			if resources != nil {
				resources.Close()
			}
			store.Close()
		}
	}()
	index, err := store.LoadIndex(ctx, store.IndexConfig())
	if err != nil {
		return nil, err
	}
	ports, err := c.Compose(ctx, store, index)
	resources = ports.Close
	if err != nil {
		return nil, err
	}
	if ports.Authenticator == nil {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Missing actual node authenticator")
	}
	d, err := dispatch.New(dispatch.Config{Audience: store.AuthorityIdentity().Namespace, Descriptors: store, Bindings: ports.Bindings, Admission: ports.Admission})
	if err != nil {
		return nil, err
	}
	n := &Node{Store: store, index: index, reader: ports.Search, resources: resources, directory: directory}
	if n.reader == nil {
		n.reader = index
	}
	cfg := node.Config{Audience: store.AuthorityIdentity().Namespace, Authenticator: ports.Authenticator, Search: n, Descriptors: store, Dispatcher: d, Interceptors: ports.Interceptors, ValidateReadResult: ports.ValidateReadResult, Events: ports.Events, Tracing: ports.Tracing}
	if ports.Events != nil {
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
	reader := n.reader
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
	return reader.Search(ctx, r)
}

// Close releases the registry's sole-writer lock. Transport owners must close
// their sessions/streams before closing the composed node.
func (n *Node) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	n.mu.Unlock()
	var err error
	if n.resources != nil {
		err = n.resources.Close()
	}
	return errors.Join(err, n.Store.Close())
}

var _ node.SearchReader = (*Node)(nil)

// Directory is private trusted host configuration for native sandbox denial.
// It must never be published in network descriptors, prompts or envelopes.
func (n *Node) Directory() string { return n.directory }
