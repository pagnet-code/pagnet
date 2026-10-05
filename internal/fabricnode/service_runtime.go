package fabricnode

import (
	"context"
	"errors"
	sdka2a "github.com/a2aproject/a2a-go/v2/a2a"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"sort"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

type ServiceRuntimeConfig struct {
	Credentials      fabricservices.CredentialProvider
	InvocationConfig fabricservices.InvocationConfig
	MaxConnections   int
	SetupTimeout     time.Duration
	SetupConcurrency int
}
type ServiceConnectionStatus struct {
	Selection             fabricservices.StartupSelection
	Connecting, Connected bool
	ErrorCode             string
}

// ServiceRuntime owns explicitly selected SDK connections in the SAME retained
// installation. Startup cannot initialize state or invoke tools. The actual
// local caller Boundary governs each invocation, not operator setup authority.
type ServiceRuntime struct {
	installation *localinstallation.Installation
	boundary     *LocalBoundary
	Profiles     *fabricservices.ProfileStore
	Invocations  *fabricservices.Invocations
	Startup      *fabricservices.Startup
	MCP          *fabricservices.Connections
	A2A          *fabricservices.A2AConnections
	providers    map[BindingProtocol]BindingProvider
	config       ServiceRuntimeConfig
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	statuses     map[string]ServiceConnectionStatus
	closed       bool
	wg           sync.WaitGroup
	closeOnce    sync.Once
	closeDone    chan struct{}
	closeErr     error
}

func validServiceRuntimeConfig(c ServiceRuntimeConfig) bool {
	return c.Credentials != nil && c.MaxConnections >= 1 && c.MaxConnections <= 256 && c.SetupTimeout >= time.Millisecond && c.SetupTimeout <= time.Minute && c.SetupConcurrency >= 1 && c.SetupConcurrency <= 8
}
func serviceRuntimeKey(scope registry.DescriptorBatchScope) string {
	return scope.Endpoint.String() + "/" + scope.BindingID
}

// InitializeServiceState is EXPLICIT operator setup, never called by Open or
// discovery. It fails on existing/missing-inconsistent replay state rather than
// resetting it. Both records are retained in the installation's only Store.
func InitializeServiceState(ctx context.Context, i *localinstallation.Installation, b *LocalBoundary, c ServiceRuntimeConfig) error {
	if i == nil || b == nil || b.store != i.Store || !validServiceRuntimeConfig(c) {
		return localDenied()
	}
	owner, e := i.Operator(ctx)
	if e != nil {
		return e
	}
	return i.WithCurrentOperator(ctx, owner, func(current context.Context) error {
		p, e := fabricservices.NewProfileStore(current, i.Store, i.Operator, i.Keys)
		if e != nil {
			return e
		}
		_, _, e = fabricservices.BootstrapServiceState(current, p, c.InvocationConfig, b, c.MaxConnections)
		return e
	})
}

// NewServiceRuntime verifies the entire bounded startup manifest and every
// private profile before asynchronous connection work. A remote outage leaves
// that selection unavailable; it cannot disable local discovery/native work.
func NewServiceRuntime(ctx context.Context, i *localinstallation.Installation, b *LocalBoundary, c ServiceRuntimeConfig) (*ServiceRuntime, error) {
	if ctx == nil || i == nil || b == nil || b.store != i.Store || !validServiceRuntimeConfig(c) {
		return nil, localDenied()
	}
	p, e := fabricservices.NewProfileStore(ctx, i.Store, i.Operator, i.Keys)
	if e != nil {
		return nil, e
	}
	ledger, e := fabricservices.OpenInvocations(ctx, p, c.InvocationConfig, b)
	if e != nil {
		return nil, e
	}
	startup, e := fabricservices.OpenStartup(ctx, ledger, c.MaxConnections)
	if e != nil {
		return nil, e
	}
	choices, e := startup.Selections(ctx)
	if e != nil {
		return nil, e
	}
	for _, choice := range choices {
		profile, generation, e := p.Get(ctx, choice.Scope)
		if e != nil || profile.BindingDigest != choice.Account || profile.Protocol != choice.Protocol || profile.Version != choice.Version || fabricservices.Fingerprint(choice.Scope, profile, generation) != choice.Fingerprint {
			return nil, localDenied()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	r := &ServiceRuntime{installation: i, boundary: b, Profiles: p, Invocations: ledger, Startup: startup, config: c, ctx: life, cancel: cancel, statuses: map[string]ServiceConnectionStatus{}, closeDone: make(chan struct{})}
	r.MCP, e = fabricservices.NewConnections(p, c.Credentials, ledger, c.MaxConnections)
	if e != nil {
		cancel()
		return nil, e
	}
	disclosure := func(current context.Context, caller fabric.ExecutionContext, d fabric.EndpointDescriptor, _ fabric.InvokeRequest) error {
		return b.WithCurrent(current, caller, d, func(context.Context) error { return nil })
	}
	r.A2A, e = fabricservices.NewA2AConnections(p, ledger, c.Credentials, disclosure, c.MaxConnections)
	if e != nil {
		cancel()
		r.MCP.Close()
		return nil, e
	}
	mcpProvider, e := NewServiceBindingProvider(r.MCP)
	if e != nil {
		r.Close()
		return nil, e
	}
	a2aProvider, e := NewA2AServiceBindingProvider(r.A2A)
	if e != nil {
		r.Close()
		return nil, e
	}
	r.providers = map[BindingProtocol]BindingProvider{{Protocol: "a2a.jsonrpc", Version: string(sdka2a.Version)}: a2aProvider}
	for _, version := range sdkmcp.SupportedProtocolVersions() {
		r.providers[BindingProtocol{Protocol: "mcp.tools", Version: version}] = mcpProvider
	}
	for _, choice := range choices {
		if _, ok := r.providers[BindingProtocol{Protocol: choice.Protocol, Version: choice.Version}]; !ok {
			r.Close()
			return nil, fabric.NewError(fabric.CodeUnsupported, "Selected service SDK protocol is unsupported")
		}
		r.statuses[serviceRuntimeKey(choice.Scope)] = ServiceConnectionStatus{Selection: choice, Connecting: true}
	}
	// Workers consume only this bounded operator manifest, not descriptors/catalog.
	jobs := make(chan fabricservices.StartupSelection, len(choices))
	for _, choice := range choices {
		jobs <- choice
	}
	close(jobs)
	for n := 0; n < c.SetupConcurrency; n++ {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for choice := range jobs {
				if life.Err() != nil {
					return
				}
				r.connect(life, choice, false)
			}
		}()
	}
	return r, nil
}
func (r *ServiceRuntime) connect(ctx context.Context, choice fabricservices.StartupSelection, bootstrap bool) error {
	bounded, cancel := context.WithTimeout(ctx, r.config.SetupTimeout)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	var e error
	switch choice.Protocol {
	case "mcp.tools":
		e = r.MCP.ConnectMCP(bounded, choice.Scope, bootstrap)
	case "a2a.jsonrpc":
		e = r.A2A.Connect(bounded, choice.Scope)
	default:
		e = fabric.NewError(fabric.CodeUnsupported, "Selected service protocol is not installed")
	}
	code := ""
	if e != nil {
		code = "unavailable"
		var f *fabric.Error
		if errors.As(e, &f) {
			code = string(f.Code)
		}
	}
	r.mu.Lock()
	if !r.closed {
		r.statuses[serviceRuntimeKey(choice.Scope)] = ServiceConnectionStatus{Selection: choice, Connected: e == nil, ErrorCode: code}
	}
	r.mu.Unlock()
	return e
}

// Connect is an explicit operator action. Its durable startup choice commits
// before external setup; failed setup remains selected/offline, never reroutes.
func (r *ServiceRuntime) Connect(ctx context.Context, scope registry.DescriptorBatchScope, bootstrapCatalog bool) error {
	if r == nil || ctx == nil {
		return localDenied()
	}
	owner, e := r.installation.Operator(ctx)
	if e != nil {
		return e
	}
	return r.installation.WithCurrentOperator(ctx, owner, func(current context.Context) error {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return localDenied()
		}
		r.wg.Add(1)
		r.mu.Unlock()
		defer r.wg.Done()
		profile, _, e := r.Profiles.Get(current, scope)
		if e != nil {
			return e
		}
		r.mu.Lock()
		_, supported := r.providers[BindingProtocol{Protocol: profile.Protocol, Version: profile.Version}]
		r.mu.Unlock()
		if !supported {
			return fabric.NewError(fabric.CodeUnsupported, "Selected service SDK protocol is unsupported")
		}
		selection, e := r.Startup.Select(current, scope)
		if e != nil {
			return e
		}
		key := serviceRuntimeKey(scope)
		r.mu.Lock()
		old, exists := r.statuses[key]
		if exists && old.Selection == selection && (old.Connected || old.Connecting) {
			r.mu.Unlock()
			if old.Connecting {
				return fabric.NewError(fabric.CodeTargetUnavailable, "Selected service is connecting")
			}
			return nil
		}
		r.statuses[key] = ServiceConnectionStatus{Selection: selection, Connecting: true}

		r.mu.Unlock()
		return r.connect(current, selection, bootstrapCatalog)
	})
}

// Bindings returns a copied protocol map; selection never opens a connection.
// The maintained SDK's exact supported protocol versions are registered once;
// an unconnected selection stays unavailable, never triggers lazy setup.
func (r *ServiceRuntime) Bindings() map[BindingProtocol]BindingProvider {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := make(map[BindingProtocol]BindingProvider, len(r.providers))
	for k, p := range r.providers {
		v[k] = p
	}
	return v
}
func (r *ServiceRuntime) Status() []ServiceConnectionStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := make([]ServiceConnectionStatus, 0, len(r.statuses))
	for _, s := range r.statuses {
		v = append(v, s)
	}
	sort.Slice(v, func(a, b int) bool {
		return serviceRuntimeKey(v[a].Selection.Scope) < serviceRuntimeKey(v[b].Selection.Scope)
	})
	return v
}
func (r *ServiceRuntime) CloseContext(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return localDenied()
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.cancel()
		r.mu.Unlock()
		go func() {
			e1 := r.MCP.Close()
			e2 := r.A2A.Close()
			r.wg.Wait()
			r.closeErr = errors.Join(e1, e2)
			close(r.closeDone)
		}()
	})
	select {
	case <-r.closeDone:
		return r.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *ServiceRuntime) Close() error { return r.CloseContext(context.Background()) }
