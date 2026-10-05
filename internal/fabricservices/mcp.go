package fabricservices

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp/catalog"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// Credentials resolves only explicitly selected operator-private material.
// Digest must identify the configured provider ACCOUNT/profile, not its token.
// Token rotation is allowed only inside that same pinned identity.
type Credentials struct {
	BindingDigest [32]byte
	MCP           mcp.Credentials
}
type CredentialProvider interface {
	Resolve(context.Context, string) (Credentials, error)
}
type credentialBinding struct {
	profile  Profile
	provider CredentialProvider
	binding  string
}

func (c credentialBinding) Credentials(ctx context.Context, binding string) (mcp.Credentials, error) {
	if binding != c.binding {
		return mcp.Credentials{}, denied()
	}
	resolved, e := c.provider.Resolve(ctx, c.profile.CredentialSelector)
	if e != nil || resolved.BindingDigest != c.profile.BindingDigest {
		return mcp.Credentials{}, denied()
	}
	// Bound credential material before SDK/HTTP allocation, and never store it.
	if len(resolved.MCP.Headers) > 64 || len(resolved.MCP.Environment) > 256 {
		return mcp.Credentials{}, denied()
	}
	n := 0
	for k, v := range resolved.MCP.Headers {
		n += len(k) + len(v)
	}
	for _, v := range resolved.MCP.Environment {
		n += len(v)
		if strings.ContainsRune(v, 0) {
			return mcp.Credentials{}, denied()
		}
	}
	if n > 64<<10 {
		return mcp.Credentials{}, denied()
	}
	return resolved.MCP, nil
}

// Stdio uses exactly the installed binary/arguments, not shell expansion or an
// inherited shell account. The official SDK owns child teardown. Setup request
// cancellation cannot accidentally kill an otherwise connected SDK session.
type stdioFactory struct{ profile MCPProfile }

func (f stdioFactory) Transport(_ context.Context, c mcp.Credentials, tap *mcp.ResultTap) (sdk.Transport, error) {
	if len(c.Headers) != 0 {
		return nil, denied()
	}
	cmd := exec.Command(f.profile.Binary, f.profile.Args...)
	cmd.Env = append([]string{}, c.Environment...)
	return tap.WrapLocal(&sdk.CommandTransport{Command: cmd})
}

type connectedMCP struct {
	adapter     *mcp.Adapter
	scope       registry.DescriptorBatchScope
	profile     Profile
	generation  uint64
	fingerprint [32]byte
	credentials credentialBinding
	transport   *http.Transport
}

// Connections are bounded node-owned installations shared by callers. Resolve
// performs no discovery, handshake, spawn or fallback. Close joins SDK sessions.
type Connections struct {
	profiles               *ProfileStore
	credentials            CredentialProvider
	max                    int
	invocations            *Invocations
	mu                     sync.Mutex
	entries                map[string]*connectedMCP
	pending                map[string]bool
	closed                 bool
	ctx                    context.Context
	cancel                 context.CancelFunc
	wg                     sync.WaitGroup
	onDescriptorsCommitted func()
}

func NewConnections(profiles *ProfileStore, credentials CredentialProvider, invocations *Invocations, max int) (*Connections, error) {
	if profiles == nil || credentials == nil || invocations == nil || invocations.profiles != profiles || max < 1 || max > 256 {
		return nil, denied()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Connections{profiles: profiles, credentials: credentials, invocations: invocations, max: max, entries: map[string]*connectedMCP{}, pending: map[string]bool{}, ctx: ctx, cancel: cancel}, nil
}
func connectionKey(scope registry.DescriptorBatchScope) string {
	return scope.Endpoint.String() + "\x00" + scope.BindingID
}

// ConnectMCP is explicit operator setup. BootstrapCatalog is accepted only for
// explicit FIRST installation; Open never initializes missing retained state.
// The published registry catalog is shared; agents need no per-agent attach.
func (c *Connections) ConnectMCP(ctx context.Context, scope registry.DescriptorBatchScope, bootstrapCatalog bool) error {
	if c == nil || ctx == nil {
		return denied()
	}
	key := connectionKey(scope)
	c.mu.Lock()
	if c.closed || c.entries[key] != nil || c.pending[key] || len(c.entries)+len(c.pending) >= c.max {
		c.mu.Unlock()
		return fabric.NewError(fabric.CodeStaleReference, "Service connection already active or capacity exhausted")
	}
	c.pending[key] = true
	c.wg.Add(1)
	c.mu.Unlock()
	defer c.wg.Done()
	defer func() { c.mu.Lock(); delete(c.pending, key); c.mu.Unlock() }()
	p, gen, e := c.profiles.Get(ctx, scope)
	if e != nil {
		return e
	}
	if p.Protocol != "mcp.tools" || p.MCP == nil {
		return denied()
	}
	owner, e := c.profiles.owner(ctx)
	if e != nil {
		return e
	}
	ref := c.profiles.protector.Reference()
	limits := registry.DefaultDescriptorBatchLimits()
	if limits.MaxRows < p.MCP.Limits.MaxTools {
		return denied()
	}
	cc := catalog.Config{BindingDigest: p.BindingDigest, Store: c.profiles.store, Owner: owner, Scope: scope, Limits: limits, MaxTools: p.MCP.Limits.MaxTools, Protector: c.profiles.protector, KeyID: ref.ID, KeyVersion: ref.Version}
	var cat *catalog.Catalog
	if bootstrapCatalog {
		cat, e = catalog.Bootstrap(ctx, cc)
	} else {
		cat, e = catalog.Open(ctx, cc)
	}
	if e != nil {
		return e
	}
	cb := credentialBinding{p, c.credentials, scope.BindingID}
	var transport mcp.TransportFactory
	var ownedHTTP *http.Transport
	if p.MCP.URL != "" {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return denied()
		}
		owned := base.Clone()
		ownedHTTP = owned
		owned.Proxy = nil
		owned.MaxConnsPerHost = p.MCP.Limits.MaxPending
		owned.MaxIdleConns = p.MCP.Limits.MaxPending
		owned.MaxIdleConnsPerHost = p.MCP.Limits.MaxPending
		owned.MaxResponseHeaderBytes = 64 << 10
		owned.ResponseHeaderTimeout = 15 * time.Second
		owned.IdleConnTimeout = 30 * time.Second
		transport = mcp.RemoteFactory{Endpoint: p.MCP.URL, AllowHTTP: p.MCP.AllowHTTP, Reconnects: 0, Client: &http.Client{Transport: &lifetimeTransport{ctx: c.ctx, base: owned, endpoint: p.MCP.URL}}}
	} else {
		transport = stdioFactory{*p.MCP}
	}
	// Adapter lifetime is owned by Connections, never a transient setup context.
	adapter, e := mcp.New(c.ctx, mcp.Config{BindingID: scope.BindingID, Audience: c.profiles.root.Namespace, Endpoint: scope.Endpoint, Credentials: cb, Transport: transport, Catalog: committedCatalog{Catalog: cat, hook: c.onDescriptorsCommitted}, Limits: p.MCP.Limits, ProtocolVersion: p.Version})
	if e != nil {
		return e
	}
	keep := false
	defer func() {
		if !keep {
			adapter.Close()
			if ownedHTTP != nil {
				ownedHTTP.CloseIdleConnections()
			}
		}
	}()
	setup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	if e = adapter.Connect(setup); e != nil {
		return e
	}
	if adapter.ProtocolVersion() != p.Version {
		return fabric.NewError(fabric.CodeUnsupported, "Installed MCP binding version differs from negotiated SDK version")
	}
	if e = adapter.Sync(setup); e != nil {
		return e
	}
	// A concurrent descriptor/profile change must not publish a stale connection.
	latest, latestGen, e := c.profiles.Get(ctx, scope)
	if e != nil || latestGen != gen || !sameProfile(latest, p) {
		return denied()
	}
	entry := &connectedMCP{adapter, scope, p, gen, Fingerprint(scope, p, gen), cb, ownedHTTP}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return denied()
	}
	c.entries[key] = entry
	keep = true
	return nil
}
func sameProfile(a, b Profile) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	defer clear(x)
	defer clear(y)
	return bytes.Equal(x, y)
}

// ResolveMCP checks CURRENT retained descriptor/profile before exposing the
// existing adapter. Account identity is verified separately outside root SQL.
func (c *Connections) ResolveMCP(ctx context.Context, scope registry.DescriptorBatchScope) (fabric.EndpointAdapter, [32]byte, error) {
	if c == nil {
		return nil, [32]byte{}, denied()
	}
	c.mu.Lock()
	entry := c.entries[connectionKey(scope)]
	closed := c.closed
	c.mu.Unlock()
	if closed || entry == nil {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeTargetUnavailable, "Service is not connected; connect it explicitly")
	}
	p, gen, e := c.profiles.Get(ctx, scope)
	if e != nil {
		return nil, [32]byte{}, e
	}
	if gen != entry.generation || !sameProfile(p, entry.profile) || scope.ExpectedEndpointRevision != entry.scope.ExpectedEndpointRevision {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeStaleReference, "Service descriptor or installed profile changed")
	}
	return &guardedMCP{c, entry}, entry.fingerprint, nil
}

type guardedMCP struct {
	connections *Connections
	entry       *connectedMCP
}

func (a *guardedMCP) Invoke(ctx context.Context, caller fabric.ExecutionContext, d fabric.EndpointDescriptor, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	if caller.VerifyAuthenticated(a.connections.profiles.root.Namespace) != nil || d.Ref != a.entry.scope.Endpoint || d.Revision != a.entry.scope.ExpectedEndpointRevision {
		return nil, denied()
	}
	if _, _, e := a.connections.ResolveMCP(ctx, a.entry.scope); e != nil {
		return nil, e
	}
	// A changed private credential account can NEVER reuse the earlier session.
	if _, e := a.entry.credentials.Credentials(ctx, a.entry.scope.BindingID); e != nil {
		return nil, e
	}
	receipt, fresh, e := a.connections.invocations.Reserve(ctx, caller, a.entry.scope, a.entry.fingerprint, r)
	if e != nil {
		return nil, e
	}
	if !fresh {
		if !receipt.Terminal {
			return nil, &fabric.Error{Code: "service.REPLAY_UNKNOWN", Message: "Original service invocation was attempted; its outcome is not known", Effect: fabric.EffectUnknown}
		}
		return newReplayStream(ctx, a.connections.invocations, caller, receipt), nil
	}
	stream, e := a.entry.adapter.Invoke(ctx, caller, d, r)
	if e != nil {
		return nil, e
	}
	return &retainedStream{InvocationStream: stream, ledger: a.connections.invocations, caller: caller, receipt: receipt, ctx: ctx}, nil
}
func (c *Connections) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	entries := c.entries
	c.entries = map[string]*connectedMCP{}
	c.mu.Unlock()
	c.wg.Wait()
	var first error
	for _, e := range entries {
		if err := e.adapter.Close(); err != nil && first == nil {
			first = err
		}
		if e.transport != nil {
			e.transport.CloseIdleConnections()
		}
	}
	return first
}

// SDK Streamable transports deliberately detach their session context from
// setup. Bind every actual HTTP request to node ownership as well, retaining
// the request deadline and raw SDK response stream until Body.Close.
type lifetimeTransport struct {
	ctx      context.Context
	base     *http.Transport
	endpoint string
}

func (t *lifetimeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// The maintained SDK issues its exact session DELETE during Close AFTER
	// local operation cancellation. This cleanup has its own finite lifetime;
	// no POST/GET/tool request can escape the owned operation cancellation.
	if r.Method == http.MethodDelete && r.URL.String() == t.endpoint && r.Header.Get("Mcp-Session-Id") != "" && r.Body == nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		resp, err := t.base.RoundTrip(r.Clone(ctx))
		if err != nil {
			cancel()
			return nil, err
		}
		resp.Body = &lifetimeBody{ReadCloser: resp.Body, cleanup: cancel}
		return resp, nil
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(t.ctx, cancel)
	cleanup := func() { stop(); cancel() }
	if t.ctx.Err() != nil {
		cleanup()
		return nil, t.ctx.Err()
	}
	resp, e := t.base.RoundTrip(r.Clone(ctx))
	if e != nil {
		cleanup()
		return nil, e
	}
	resp.Body = &lifetimeBody{ReadCloser: resp.Body, cleanup: cleanup}
	return resp, nil
}

type lifetimeBody struct {
	io.ReadCloser
	once    sync.Once
	cleanup func()
}

func (b *lifetimeBody) Close() error { e := b.ReadCloser.Close(); b.once.Do(b.cleanup); return e }
