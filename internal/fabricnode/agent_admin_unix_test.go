//go:build linux || darwin

package fabricnode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

func TestInstalledAgentCreateActualOwnerSocketAndRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	private, err := os.MkdirTemp("", "pgn-create-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(private)
	directory, socket := filepath.Join(private, "domain"), filepath.Join(private, "node.sock")
	installation, err := localinstallation.Bootstrap(ctx, directory, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	identity := installation.Store.AuthorityIdentity()
	if err = installation.Close(); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	published := make(chan error, 32)
	open := func() *InstalledNode {
		n, e := OpenInstalled(ctx, InstalledConfig{Directory: directory, Binary: binary, ObserveIndexPublication: func(more bool, e error) {
			if !more || e != nil {
				select {
				case published <- e:
				default:
				}
			}
		}})
		if e != nil {
			t.Fatal(e)
		}
		return n
	}
	n := open()
	defer func() {
		if n != nil {
			if e := n.CloseContext(ctx); e != nil {
				t.Error(e)
			}
		}
	}()
	for {
		select {
		case e := <-published:
			if e != nil {
				t.Fatal(e)
			}
			goto ready
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
ready:
	admin, e := fabricadmin.Dial(ctx, socket)
	if e != nil {
		t.Fatal(e)
	}
	request := fabricadmin.Request{Version: 1, ID: "create-maria-one", Operation: "agent.create", Input: json.RawMessage(`{"name":"Maria","description":"salesfixturemarker supports customers"}`)}
	first, e := admin.Call(ctx, request)
	if e != nil || first.Error != nil {
		t.Fatal(e, first.Error)
	}
	var created struct {
		Ref      fabric.EndpointRef `json:"ref"`
		Revision fabric.Revision    `json:"revision"`
		Name     string             `json:"name"`
	}
	if e = fabric.DecodeJSON(first.Result, &created); e != nil || created.Ref.Domain() != identity.Namespace || created.Name != "Maria" {
		t.Fatal(e, string(first.Result))
	}
	select {
	case e := <-published:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	client, e := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(fabric.DiscoverRequest{Query: "salesfixturemarker", Limit: 10})
	result, e := client.Call(ctx, fabric.OperationDiscover, raw)
	if e != nil || result.IsError {
		t.Fatal(e, result)
	}
	if len(result.Content) != 1 {
		t.Fatal("missing search result")
	}
	text, ok := result.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatal("nontext search result")
	}
	var found fabric.DiscoverResult
	if e = fabric.DecodeJSON([]byte(text.Text), &found); e != nil || len(found.Candidates) != 1 || found.Candidates[0].Document.Ref != created.Ref {
		t.Fatal("committed agent not discoverable", e, text.Text)
	}
	changed := request
	changed.Input = json.RawMessage(`{"name":"Someone else","description":"different"}`)
	conflict, e := admin.Call(ctx, changed)
	if e != nil || conflict.Error == nil || conflict.Error.Code != fabric.CodeInvalidMutation {
		t.Fatal("identity request conflict accepted", e, conflict)
	}
	unknown := request
	unknown.ID = "unknown-operation"
	unknown.Operation = "agent.unknown"
	rejected, e := admin.Call(ctx, unknown)
	if e != nil || rejected.Error == nil || rejected.Error.Code != fabric.CodeUnsupported {
		t.Fatal("unknown operation not structured", e, rejected)
	}
	extra := request
	extra.ID = "extra-field"
	extra.Input = json.RawMessage(`{"name":"Leak","description":"shown","instructions":"private"}`)
	rejected, e = admin.Call(ctx, extra)
	if e != nil || rejected.Error == nil || rejected.Error.Code != fabric.CodeInvalidInput {
		t.Fatal("unsupported private input accepted", e, rejected)
	}
	client.Close()
	admin.Close()
	if e = n.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	n = nil
	n = open()
	admin, e = fabricadmin.Dial(ctx, socket)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	repeated, e := admin.Call(ctx, request)
	if e != nil || repeated.Error != nil || string(repeated.Result) != string(first.Result) {
		t.Fatal("retry after restart changed identity", e, repeated)
	}
	if n.Installation.Store.AuthorityIdentity().StoreID != identity.StoreID {
		t.Fatal("writer identity replaced")
	}
}
