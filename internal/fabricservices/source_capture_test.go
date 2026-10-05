package fabricservices

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp/catalog"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type capturePolicyFixture struct{ *retainedPolicyFixture }

func (p *capturePolicyFixture) AuthorizeTx(ctx context.Context, tx *registry.AuthorityTx, c fabric.ExecutionContext, f InvocationFacts, action string) error {
	if p.denied.Load() {
		return denied()
	}
	return p.servicePolicyFixture.AuthorizeTx(ctx, tx, c, f, action)
}
func TestActualSDKSourceCaptureDroppedCallerDetachOriginalOnceAndRestart(t *testing.T) {
	p, scope, caller, dir := serviceFixture(t)
	base := &aliasPolicyFixture{servicePolicyFixture: servicePolicyFixture{p.root.Owner}}
	policy := &capturePolicyFixture{&retainedPolicyFixture{base}}
	ledger, e := BootstrapInvocations(t.Context(), p, DefaultInvocationConfig(), policy)
	if e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var effects atomic.Int32
	provider := sdk.NewServer(&sdk.Implementation{Name: "original-source", Version: "1"}, &sdk.ServerOptions{SupportedProtocolVersions: []string{"2026-07-28"}})
	provider.AddTool(&sdk.Tool{Name: "compute", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		close(entered)
		<-release
		return &sdk.CallToolResult{StructuredContent: json.RawMessage(`{"n":9007199254740993123456789}`), Content: []sdk.Content{}}, nil
	})
	server := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return provider }, &sdk.StreamableHTTPOptions{Stateless: true}))
	defer server.Close()
	profile := serviceProfile()
	profile.MCP.URL = server.URL
	profile.MCP.AllowHTTP = true
	if _, e = p.Install(t.Context(), scope, profile); e != nil {
		t.Fatal(e)
	}
	connections, e := NewConnections(p, &credentialsFixture{digest: profile.BindingDigest}, ledger, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer connections.Close()
	if e = connections.ConnectMCP(t.Context(), scope, true); e != nil {
		t.Fatal(e)
	}
	key := p.protector.Reference()
	cat, e := catalog.Open(t.Context(), catalog.Config{BindingDigest: profile.BindingDigest, Store: p.store, Owner: caller, Scope: scope, MaxTools: profile.MCP.Limits.MaxTools, Protector: p.protector, KeyID: key.ID, KeyVersion: key.Version})
	if e != nil {
		t.Fatal(e)
	}
	rows, e := p.store.ReadBindingProjection(t.Context(), caller, scope, "", 2)
	if e != nil || len(rows.Rows) != 1 {
		t.Fatal(e)
	}
	offer, e := cat.Resolve(t.Context(), scope.BindingID, rows.Rows[0].Ref, "")
	if e != nil {
		t.Fatal(e)
	}
	adapter, _, e := connections.ResolveMCP(t.Context(), scope)
	if e != nil {
		t.Fatal(e)
	}
	descriptor, e := p.store.GetEndpoint(t.Context(), scope.Endpoint, scope.ExpectedEndpointRevision)
	if e != nil {
		t.Fatal(e)
	}
	request := fabric.InvokeRequest{InvocationID: "original-after-delivery-loss", Target: offer.Offer.Ref, ExpectedRevision: offer.Offer.Revision, Input: json.RawMessage(`{"n":9007199254740993123456789}`)}
	originalCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	streamReady := make(chan fabric.InvocationStream, 1)
	finished := make(chan error, 1)
	go func() {
		_, err := executeServiceFixture(originalCtx, p, request, func(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
			s, err := adapter.Invoke(ctx, c, descriptor, r)
			if s != nil {
				streamReady <- s
			}
			return s, err
		})
		finished <- err
	}()
	<-entered
	// A second original source must be rejected BEFORE paid reservation/send,
	// even though it uses the same connected provider and a distinct request ID.
	second := request
	second.InvocationID = "capacity-rejected-original"
	_, overflow := executeServiceFixture(t.Context(), p, second, func(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
		return adapter.Invoke(ctx, c, descriptor, r)
	})
	if overflow == nil || effects.Load() != 1 {
		t.Fatal("source capacity failed before effect", overflow, effects.Load())
	}
	connections.mu.Lock()
	active := connections.sources
	connections.mu.Unlock()
	if active != 1 {
		t.Fatal("original source lost its reserved capacity", active)
	}
	cancel()
	close(release)
	// The accepted original SDK call completes despite caller delivery loss. No
	// current permission is taken from its stored receipt to disclose output.
	var stream fabric.InvocationStream
	select {
	case stream = <-streamReady:
	case err := <-finished:
		if err != nil {
			t.Fatal("original source lost", err)
		}
		select {
		case stream = <-streamReady:
		default:
			t.Fatal("original source lost without original stream")
		}
	}
	retainer, ok := stream.(interface {
		DetachOriginalDelivery() (SourceReference, error)
	})
	if !ok {
		t.Fatal("source-owned retention unavailable")
	}
	policy.denied.Store(true)
	ref, e := retainer.DetachOriginalDelivery()
	if e != nil {
		t.Fatal(e)
	}
	if e = stream.Close(); e != nil {
		t.Fatal(e)
	} // delivery detach, not original cancel
	owned := stream.(*retainedStream)
	<-owned.drainDone
	if effects.Load() != 1 {
		t.Fatal("original SDK resent")
	}
	if _, e = ledger.OpenRetainedSource(t.Context(), caller, ref); e == nil {
		t.Fatal("dropped caller disclosed source")
	}
	policy.denied.Store(false)
	// Close joins genuine source resources BEFORE the retained root is closed.
	connections.Close()
	if e = p.store.Close(); e != nil {
		t.Fatal(e)
	}
	root, e := registry.Open(t.Context(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	profiles, e := NewProfileStore(t.Context(), root, p.owner, p.protector)
	if e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenInvocations(t.Context(), profiles, DefaultInvocationConfig(), policy)
	if e != nil {
		t.Fatal(e)
	}
	source, e := reopened.OpenRetainedSource(t.Context(), caller, ref)
	if e != nil {
		t.Fatal(e)
	}
	var output bytes.Buffer
	var terminal bool
	for n := uint64(0); n < 16; n++ {
		f, e := source.Frame(t.Context(), caller, n)
		if e != nil {
			t.Fatal(e)
		}
		output.Write(f.Data)
		if f.Kind == fabric.FrameComplete {
			terminal = true
			break
		}
	}
	if !terminal || !bytes.Contains(output.Bytes(), []byte("9007199254740993123456789")) || effects.Load() != 1 {
		t.Fatal("original output not retained exactly")
	}
	select {
	case err := <-finished:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	default:
	}
}

func TestSourceCapacityAndConcurrentCloseJoin(t *testing.T) {
	for _, protocol := range []string{"mcp", "a2a"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			var reserve func() (func(), func(), error)
			var closeResource func() error
			var started func() bool
			if protocol == "mcp" {
				c := &Connections{max: 1, ctx: ctx, cancel: cancel, closeDone: make(chan struct{}), entries: map[string]*connectedMCP{}}
				reserve = c.reserveSourceSlot
				closeResource = c.Close
				started = func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }
			} else {
				c := &A2AConnections{max: 1, ctx: ctx, cancel: cancel, closeDone: make(chan struct{}), entries: map[string]*connectedA2A{}}
				reserve = c.reserveSourceSlot
				closeResource = c.Close
				started = func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }
			}
			release, finish, err := reserve()
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = reserve(); err == nil {
				t.Fatal("unbounded same-connection source admission")
			}
			first := make(chan error, 1)
			go func() { first <- closeResource() }()
			<-ctx.Done()
			if !started() {
				t.Fatal("close did not fence admission")
			}
			second := make(chan error, 1)
			go func() { second <- closeResource() }()
			select {
			case <-first:
				t.Fatal("close returned with accepted callback active")
			default:
			}
			select {
			case <-second:
				t.Fatal("concurrent close skipped callback join")
			default:
			}
			release()
			finish()
			if err = <-first; err != nil {
				t.Fatal(err)
			}
			if err = <-second; err != nil {
				t.Fatal(err)
			}
			if _, _, err = reserve(); err == nil {
				t.Fatal("closed resource accepted source")
			}
		})
	}
}
