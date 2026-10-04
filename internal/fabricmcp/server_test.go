package fabricmcp

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/node"
)

// These are real signature checks and a real node + official SDK connection.
// Test peer admission is explicit; production kernel/root composition is not
// claimed by this fixture.
type signedFactory struct {
	private   ed25519.PrivateKey
	principal fabric.Principal
	calls     atomic.Int32
	closed    atomic.Int32
}

func (f *signedFactory) Build(_ context.Context, call mcpbridge.Call) ([]byte, any, error) {
	f.calls.Add(1)
	if call.Operation != fabric.OperationDiscover {
		return nil, nil, errors.New("fixture only discovers")
	}
	payload, _ := json.Marshal(call.Discover)
	raw, err := json.Marshal(fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "owned-original", Operation: call.Operation, Principal: f.principal, Source: f.principal.Ref, CreatedAt: time.Now().UTC(), Payload: payload, Context: fabric.EnvelopeContext{Origin: f.principal.Ref}})
	return raw, ed25519.Sign(f.private, raw), err
}

type signedAuth struct {
	public    ed25519.PublicKey
	principal fabric.Principal
}

func (a signedAuth) Authenticate(_ context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	sig, ok := r.PeerEvidence.([]byte)
	if !ok || r.Audience != "owned-node" || !ed25519.Verify(a.public, r.ExactEnvelope, sig) {
		return fabric.ExecutionContext{}, errors.New("unauthentic original envelope")
	}
	return fabric.NewAuthenticatedContext(a.principal, r.Audience, r.ExactEnvelope)
}

type indexedReader struct {
	calls    atomic.Int32
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
}

func (r *indexedReader) Search(ctx context.Context, _ fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	r.calls.Add(1)
	if r.entered != nil {
		close(r.entered)
		if r.release != nil {
			<-r.release
		} else {
			<-ctx.Done()
		}
		close(r.canceled)
		return fabric.DiscoverResult{}, ctx.Err()
	}
	return fabric.DiscoverResult{Candidates: []fabric.Candidate{}, IndexRevision: "original-index"}, nil
}
func composition(t *testing.T, search *indexedReader) (*Server, *signedFactory) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	principal := fabric.Principal{Ref: "retained-local-owner", Issuer: "fixture-root", Kind: "actor.human"}
	service, err := node.New(node.Config{Audience: "owned-node", Authenticator: signedAuth{public, principal}, Search: search})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Executor: service, MaxConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server, &signedFactory{private: private, principal: principal}
}
func TestOfficialSDKConnectionOwnsExactlyThreeToolsAndOriginalAuthentication(t *testing.T) {
	search := &indexedReader{}
	server, factory := composition(t, search)
	clientConn, serverConn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.ServeVerified(t.Context(), serverConn, bufio.NewReader(serverConn), factory) }()
	client := sdk.NewClient(&sdk.Implementation{Name: "actual-local-client", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &sdk.IOTransport{Reader: clientConn, Writer: clientConn, MaxLineLength: 1 << 20}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := session.ListTools(t.Context(), nil)
	if err != nil || len(tools.Tools) != 3 {
		t.Fatal("official session did not expose exactly three tools", err)
	}
	result, err := session.CallTool(t.Context(), &sdk.CallToolParams{Name: "discover", Arguments: map[string]any{"query": "local work", "limit": 1}})
	if err != nil || result.IsError || factory.calls.Load() != 1 || search.calls.Load() != 1 {
		t.Fatal("real authenticated node not reached", err, result)
	}
	result, err = session.CallTool(t.Context(), &sdk.CallToolParams{Name: "discover", Arguments: map[string]any{"query": "local work", "limit": 1, "principal": "forged"}})
	if err != nil || !result.IsError || factory.calls.Load() != 1 {
		t.Fatal("caller identity field reached trusted signer", err)
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("SDK session disconnect did not join")
	}
}
func TestDisconnectCancelsActualNodeReadBeforeSessionWait(t *testing.T) {
	search := &indexedReader{entered: make(chan struct{}), canceled: make(chan struct{})}
	server, factory := composition(t, search)
	clientConn, serverConn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.ServeVerified(t.Context(), serverConn, serverConn, factory) }()
	client := sdk.NewClient(&sdk.Implementation{Name: "actual-local-client", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &sdk.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
	if err != nil {
		t.Fatal(err)
	}
	callDone := make(chan struct{})
	go func() {
		defer close(callDone)
		_, _ = session.CallTool(t.Context(), &sdk.CallToolParams{Name: "discover", Arguments: map[string]any{"query": "work", "limit": 1}})
	}()
	select {
	case <-search.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("real read never entered")
	}
	clientConn.Close()
	select {
	case <-search.canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("disconnect left actual handler live")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("disconnect did not settle SDK connection")
	}
	<-callDone
}
func TestStrictTransportRejectsDuplicateTrailingAndOversizedFrames(t *testing.T) {
	for _, raw := range []string{"{\"jsonrpc\":\"2.0\",\"jsonrpc\":\"2.0\"}\n", "{} {}\n", string(make([]byte, 2049)) + "\n"} {
		t.Run("malformed", func(t *testing.T) {
			search := &indexedReader{}
			server, factory := composition(t, search)
			server.config.MaxLineBytes = 1024
			client, peer := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- server.ServeVerified(t.Context(), peer, peer, factory) }()
			_, _ = client.Write([]byte(raw))
			client.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("invalid frame retained connection")
			}
			if factory.calls.Load() != 0 || search.calls.Load() != 0 {
				t.Fatal("malformed transport reached signer/effect")
			}
		})
	}
}
func TestVerifiedTransportFailsClosedWithoutFactoryAndAfterShutdown(t *testing.T) {
	server, factory := composition(t, &indexedReader{})
	client, peer := net.Pipe()
	defer client.Close()
	if err := server.ServeVerified(t.Context(), peer, peer, nil); err == nil {
		t.Fatal("nil peer authority accepted")
	}
	server.Close()
	client2, peer2 := net.Pipe()
	defer client2.Close()
	if err := server.ServeVerified(t.Context(), peer2, peer2, factory); err == nil {
		t.Fatal("closed server accepted session")
	}
}

func (f *signedFactory) Close() error { f.closed.Add(1); return nil }

func TestCloseContextDeadlineDoesNotClaimIgnoringExecutorJoined(t *testing.T) {
	search := &indexedReader{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	server, factory := composition(t, search)
	clientConn, serverConn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.ServeVerified(t.Context(), serverConn, serverConn, factory) }()
	client := sdk.NewClient(&sdk.Implementation{Name: "actual-local-client", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &sdk.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	callDone := make(chan struct{})
	go func() {
		defer close(callDone)
		_, _ = session.CallTool(t.Context(), &sdk.CallToolParams{Name: "discover", Arguments: map[string]any{"query": "work", "limit": 1}})
	}()
	select {
	case <-search.entered:
	case <-time.After(time.Second):
		t.Fatal("executor did not enter")
	}
	bounded, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	err = server.CloseContext(bounded)
	if !errors.Is(err, context.DeadlineExceeded) {
		close(search.release)
		t.Fatal("shutdown claimed cancellation-ignoring executor joined", err)
	}
	if factory.closed.Load() != 0 {
		close(search.release)
		t.Fatal("identity closed before original callback joined")
	}
	close(search.release)
	joined, cancelJoin := context.WithTimeout(t.Context(), time.Second)
	defer cancelJoin()
	if err = server.CloseContext(joined); err != nil {
		t.Fatal("shutdown failed to join after real callback exit", err)
	}
	if factory.closed.Load() != 1 {
		t.Fatal("identity session not closed exactly once")
	}
	<-done
	<-callDone
}
func TestInvalidServeOwnsFactoryClosure(t *testing.T) {
	server, factory := composition(t, &indexedReader{})
	if err := server.ServeVerified(nil, nil, nil, factory); err == nil || factory.closed.Load() != 1 {
		t.Fatal("invalid owned factory leaked", err)
	}
}
