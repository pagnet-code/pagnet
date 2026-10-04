package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
)

type fixtureCredentials struct{ calls atomic.Int32 }

func (p *fixtureCredentials) Credentials(context.Context, string) (Credentials, error) {
	p.calls.Add(1)
	return Credentials{}, nil
}

type memoryFactory struct {
	server        *sdk.Server
	serverSession *sdk.ServerSession
}

func (f *memoryFactory) Transport(ctx context.Context, _ Credentials, tap *ResultTap) (sdk.Transport, error) {
	client, server := sdk.NewInMemoryTransports()
	var err error
	f.serverSession, err = f.server.Connect(ctx, server, nil)
	if err != nil {
		return nil, err
	}
	return tap.WrapLocal(client)
}

type fixtureCatalog struct {
	mu       sync.Mutex
	records  map[string]ToolBinding
	pubs     int
	next     uint64
	endpoint fabric.EndpointRef
}

func (c *fixtureCatalog) Current(context.Context, string) ([]ToolIdentity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []ToolIdentity
	for _, b := range c.records {
		out = append(out, ToolIdentity{ToolName: b.ToolName, Fingerprint: b.Fingerprint})
	}
	return out, nil
}
func (c *fixtureCatalog) Apply(_ context.Context, binding string, endpoint fabric.EndpointRef, d CatalogDelta) ([]ToolBinding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, name := range d.Remove {
		delete(c.records, name)
	}
	for _, tool := range d.Upsert {
		old := c.records[tool.Name]
		ref := old.Offer.Ref
		if ref.String() == "" {
			var id [32]byte
			_, _ = rand.Read(id[:])
			ref, _ = endpoint.WithOfferID(id[:])
		}
		c.next++
		b := ToolBinding{ToolName: tool.Name, Fingerprint: tool.Fingerprint, Offer: fabric.OfferDescriptor{Ref: ref, Revision: fabric.Revision(tool.Fingerprint), Name: tool.Name, Description: tool.Description, BindingID: binding, InputSchema: bytes.Clone(tool.InputSchema), OutputSchema: bytes.Clone(tool.OutputSchema)}}
		c.records[tool.Name] = b
		c.pubs++
	}
	return nil, nil
}
func (c *fixtureCatalog) Resolve(_ context.Context, _ string, ref fabric.EndpointRef, revision fabric.Revision) (ToolBinding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range c.records {
		if b.Offer.Ref == ref {
			if revision != "" && revision != b.Offer.Revision {
				return ToolBinding{}, fabric.NewError(fabric.CodeStaleReference, "fixture revision stale")
			}
			return b, nil
		}
	}
	return ToolBinding{}, fabric.NewError(fabric.CodeStaleReference, "fixture tombstone")
}
func newAdapterFixture(t *testing.T, version string, handler sdk.ToolHandler) (*Adapter, *fixtureCatalog, *memoryFactory, *fixtureCredentials) {
	t.Helper()
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	endpoint, _ := fabric.NewEndpointRef(key)
	server := sdk.NewServer(&sdk.Implementation{Name: "real-sdk-fixture", Version: "1"}, &sdk.ServerOptions{SupportedProtocolVersions: []string{version}})
	server.AddTool(&sdk.Tool{Name: "compute", Description: "Exact arbitrary numeric judgment", InputSchema: json.RawMessage(`{"type":"object","properties":{"n":{"const":9007199254740993123456789}}}`)}, handler)
	catalog := &fixtureCatalog{records: map[string]ToolBinding{}, endpoint: endpoint}
	factory := &memoryFactory{server: server}
	credentials := &fixtureCredentials{}
	a, err := New(t.Context(), Config{Audience: "fixture-node", BindingID: "registered-fixture", Endpoint: endpoint, Credentials: credentials, Transport: factory, Catalog: catalog})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = factory.serverSession.Close() })
	if err = a.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	return a, catalog, factory, credentials
}
func fixtureCaller(t *testing.T) fabric.ExecutionContext {
	t.Helper()
	caller, err := fabric.NewAuthenticatedContext(fabric.Principal{Ref: "fixture-human", Issuer: "fixture-authority", Kind: "pagnet.human"}, "fixture-node", []byte("isolated verified fixture assertion"))
	if err != nil {
		t.Fatal(err)
	}
	return caller
}
func invokeFixture(t *testing.T, a *Adapter, c *fixtureCatalog) fabric.InvocationStream {
	t.Helper()
	c.mu.Lock()
	binding := c.records["compute"]
	c.mu.Unlock()
	stream, err := a.Invoke(t.Context(), fixtureCaller(t), fabric.EndpointDescriptor{Ref: a.config.Endpoint}, fabric.InvokeRequest{InvocationID: "engine-owned-fixture-invocation", Target: binding.Offer.Ref, ExpectedRevision: binding.Offer.Revision, Input: json.RawMessage(`{"n":9007199254740993123456789}`)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	return stream
}
func drainFixture(t *testing.T, stream fabric.InvocationStream) ([]byte, fabric.InvocationFrame) {
	t.Helper()
	var raw bytes.Buffer
	for {
		f, err := stream.Next(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(f.Data) > fabric.MaxFrameBytes {
			t.Fatal("frame bound")
		}
		raw.Write(f.Data)
		if f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError {
			return raw.Bytes(), f
		}
	}
}
func TestOfficialSDKNegotiationExactNumbersAndNoDiscoveryEffect(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			var calls atomic.Int32
			a, c, _, credentials := newAdapterFixture(t, version, func(_ context.Context, r *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				calls.Add(1)
				if !bytes.Equal(r.Params.Arguments, json.RawMessage(`{"n":9007199254740993123456789}`)) {
					t.Errorf("application input changed: %s", r.Params.Arguments)
				}
				return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "original provider text"}}, StructuredContent: json.RawMessage(`{"n":9007199254740993123456789}`)}, nil
			})
			if a.ProtocolVersion() != version || calls.Load() != 0 {
				t.Fatal("negotiation or discovery launched tool")
			}
			c.mu.Lock()
			b := c.records["compute"]
			c.mu.Unlock()
			d, err := a.Describe(t.Context(), b.Offer.Ref, b.Offer.Revision)
			if err != nil || !bytes.Contains(d.InputSchema, []byte("9007199254740993123456789")) {
				t.Fatal("schema precision changed", err)
			}
			raw, terminal := drainFixture(t, invokeFixture(t, a, c))
			if terminal.Kind != fabric.FrameComplete || !bytes.Contains(raw, []byte("9007199254740993123456789")) || calls.Load() != 1 || credentials.calls.Load() != 1 {
				t.Fatal("original result lost or automatic replay/credential hotpath")
			}
			if err = a.Sync(t.Context()); err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			pubs := c.pubs
			c.mu.Unlock()
			if pubs != 1 {
				t.Fatal("unchanged schema reindexed")
			}
		})
	}
}
func TestOfficialSDKInputRequiredDoesNotReplay(t *testing.T) {
	var calls atomic.Int32
	a, c, _, _ := newAdapterFixture(t, "2026-07-28", func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		calls.Add(1)
		var result sdk.CallToolResult
		_ = json.Unmarshal([]byte(`{"resultType":"input_required","inputRequests":{}}`), &result)
		return &result, nil
	})
	_, terminal := drainFixture(t, invokeFixture(t, a, c))
	if terminal.Kind != fabric.FrameError || terminal.Error.Code != fabric.CodeUnsupported || terminal.Error.Effect != fabric.EffectUnknown || calls.Load() != 1 {
		t.Fatal("load shedding repeated destructive call", calls.Load(), terminal)
	}
}
func TestOfficialSDKCancellationCloseUnblocksAndDoesNotReplay(t *testing.T) {
	entered := make(chan struct{})
	ended := make(chan struct{})
	var calls atomic.Int32
	a, c, _, _ := newAdapterFixture(t, "2025-11-25", func(ctx context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		close(ended)
		return nil, ctx.Err()
	})
	stream := invokeFixture(t, a, c)
	_, _ = stream.Next(t.Context())
	<-entered
	waiting := make(chan error, 1)
	go func() { _, err := stream.Next(context.Background()); waiting <- err }()
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("close did not unblock stream")
	}
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("SDK cancellation did not reach original handler")
	}
	if calls.Load() != 1 {
		t.Fatal("cancel replayed tool")
	}
}
func TestOfficialSDKToolErrorDistinctAndTombstoneDoesNotRedirect(t *testing.T) {
	var calls atomic.Int32
	a, c, f, _ := newAdapterFixture(t, "2025-11-25", func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		calls.Add(1)
		return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "authorized tool error details"}}}, nil
	})
	_, terminal := drainFixture(t, invokeFixture(t, a, c))
	if terminal.Kind != fabric.FrameError || terminal.Error.Code != "mcp.tool_error" {
		t.Fatal("tool error became transport failure")
	}
	c.mu.Lock()
	old := c.records["compute"]
	c.mu.Unlock()
	f.server.RemoveTools("compute")
	if err := a.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, err := a.Describe(t.Context(), old.Offer.Ref, old.Offer.Revision)
	var typed *fabric.Error
	if !errors.As(err, &typed) || typed.Code != fabric.CodeStaleReference {
		t.Fatal("removed tool ref reused", err)
	}
	if calls.Load() != 1 {
		t.Fatal("descriptor removal invoked target")
	}
	if _, err = (&toolStream{terminal: true}).Next(t.Context()); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

// The credential provider is setup-only; a stalled provider must not make
// Close wait indefinitely for the connection mutex.
type blockedCredentials struct{ entered chan struct{} }

func (p blockedCredentials) Credentials(ctx context.Context, _ string) (Credentials, error) {
	close(p.entered)
	<-ctx.Done()
	return Credentials{}, ctx.Err()
}
func TestCloseCancelsBlockedConnectionSetup(t *testing.T) {
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	endpoint, _ := fabric.NewEndpointRef(key)
	credentials := blockedCredentials{entered: make(chan struct{})}
	a, err := New(t.Context(), Config{Audience: "fixture-node", BindingID: "blocked-setup", Endpoint: endpoint, Credentials: credentials, Transport: &memoryFactory{}, Catalog: &fixtureCatalog{}})
	if err != nil {
		t.Fatal(err)
	}
	connected := make(chan error, 1)
	go func() { connected <- a.Connect(context.Background()) }()
	<-credentials.entered
	closed := make(chan error, 1)
	go func() { closed <- a.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close stranded in connection setup")
	}
	select {
	case err := <-connected:
		if err == nil {
			t.Fatal("canceled setup accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("setup did not observe lifetime cancellation")
	}
	if err := a.Connect(t.Context()); err == nil {
		t.Fatal("closed binding reconnected")
	}
}

func TestVerifiedForeignAudienceCannotDispatch(t *testing.T) {
	var effects atomic.Int32
	a, catalog, _, _ := newAdapterFixture(t, "2026-07-28", func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{}}, nil
	})
	catalog.mu.Lock()
	binding := catalog.records["compute"]
	catalog.mu.Unlock()
	caller, err := fabric.NewAuthenticatedContext(fabric.Principal{Ref: "genuine-foreign", Issuer: "fixture-authority", Kind: "pagnet.human"}, "another-node", []byte("genuine verified foreign assertion"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Invoke(t.Context(), caller, fabric.EndpointDescriptor{Ref: a.config.Endpoint}, fabric.InvokeRequest{InvocationID: "engine-assigned", Target: binding.Offer.Ref, ExpectedRevision: binding.Offer.Revision, Input: json.RawMessage(`{}`)})
	if err == nil || effects.Load() != 0 {
		t.Fatal("foreign node assertion reached provider")
	}
}
