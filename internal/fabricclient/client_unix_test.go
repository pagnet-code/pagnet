//go:build linux || darwin

package fabricclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
)

type exactExecutor struct {
	auth         *fabricauth.Authority
	authAudience string
	received     chan json.RawMessage
}

func (e *exactExecutor) Execute(ctx context.Context, raw []byte, evidence any) (node.Result, error) {
	caller, err := e.auth.Authenticate(ctx, fabric.AuthenticationRequest{ExactEnvelope: raw, PeerEvidence: evidence, Audience: e.authAudience})
	if err != nil {
		return node.Result{}, err
	}
	envelope, err := caller.DecodeVerifiedEnvelope(raw, e.authAudience)
	if err != nil {
		return node.Result{}, err
	}
	e.received <- bytes.Clone(envelope.Payload)
	return node.Result{Stream: &emptyStream{id: envelope.ID}}, nil
}

type emptyStream struct {
	id  string
	seq uint64
}

func (s *emptyStream) Next(context.Context) (fabric.InvocationFrame, error) {
	if s.seq > 1 {
		return fabric.InvocationFrame{}, io.EOF
	}
	kind := fabric.FrameStart
	if s.seq == 1 {
		kind = fabric.FrameComplete
	}
	f := fabric.InvocationFrame{InvocationID: s.id, Sequence: s.seq, Kind: kind}
	s.seq++
	return f, nil
}
func (*emptyStream) Close() error { return nil }

func TestActualAuthenticatedSocketPreservesExactInputAndNeverRetries(t *testing.T) {
	ctx := t.Context()
	private, err := os.MkdirTemp("", "pgn-client-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(private)
	owner := fabric.Principal{Ref: "local:client-owner", Kind: "local.owner", Issuer: "operator.setup"}
	store, err := registry.Bootstrap(ctx, filepath.Join(private, "root"), owner)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root := store.AuthorityIdentity()
	socket := filepath.Join(private, "fabric.sock")
	auth, err := fabricauth.New(fabricauth.Config{Root: root, RootOwner: owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: store.CurrentAuthorityIdentity})
	if err != nil {
		t.Fatal(err)
	}
	executor := &exactExecutor{auth: auth, authAudience: root.Namespace, received: make(chan json.RawMessage, 2)}
	server, err := fabricmcp.New(fabricmcp.Config{Executor: executor})
	if err != nil {
		t.Fatal(err)
	}
	host, err := fabrichost.Start(ctx, fabrichost.Config{SocketPath: socket, Authority: auth, Server: server})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	client, err := Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ref, _ := fabric.NewEndpointRef(root.PublicKey)
	input := json.RawMessage(`{"account":9007199254740993,"nested":{"number":123456789012345678901234567890}}`)
	arguments, _ := json.Marshal(map[string]any{"target": ref.String(), "input": input})
	result, err := client.Call(ctx, fabric.OperationInvoke, arguments)
	if err != nil || result.IsError {
		t.Fatal("actual call", err, result)
	}
	if got := <-executor.received; !bytes.Equal(got, input) {
		t.Fatalf("exact numeric input changed: %s", got)
	}
	if _, err = client.Call(ctx, fabric.Operation("smart.invoke"), arguments); err == nil {
		t.Fatal("unsupported operation sent")
	}
	if _, err = client.Call(ctx, fabric.OperationInvoke, json.RawMessage(`{"target":"x","target":"y"}`)); err == nil {
		t.Fatal("duplicate arguments accepted")
	}
	select {
	case <-executor.received:
		t.Fatal("invalid request or automatic replay executed")
	default:
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Call(ctx, fabric.OperationInvoke, arguments); err == nil {
		t.Fatal("closed connection reused")
	}
}
