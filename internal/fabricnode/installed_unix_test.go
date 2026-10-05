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
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

func TestActualInstalledNodeAuthenticatedDiscoverySameRootRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	parent := t.TempDir()
	socketDir := filepath.Join(parent, "run")
	if err := os.Mkdir(socketDir, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "authority")
	socket := filepath.Join(socketDir, "node.sock")
	installed, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	root := installed.Store.AuthorityIdentity()
	owner, err := installed.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := fabric.NewEndpointRef(root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// A description-only agent is searchable. There is no runtime binding,
	// schema, provider credential, paid process or remote control plane.
	_, err = installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: "Maria", Description: "Sales and customer enquiries"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = installed.Close(); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var prior []byte
	for turn := 0; turn < 2; turn++ {
		n, err := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
		if err != nil {
			t.Fatal(err)
		}
		if n.Node.Store != n.Installation.Store || n.Node.Store.AuthorityIdentity().StoreID != root.StoreID {
			t.Fatal("substituted installed root")
		}
		if _, err = n.Node.Synchronize(ctx, 2); err != nil {
			t.Fatal(err)
		}
		client, err := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
		if err != nil {
			t.Fatal(err)
		}
		result, err := client.Call(ctx, fabric.OperationDiscover, json.RawMessage(`{"query":"sales","limit":1}`))
		if err != nil || result.IsError || len(result.Content) != 1 {
			t.Fatal("genuine product discovery failed", err, result)
		}
		raw := []byte(result.Content[0].(*sdk.TextContent).Text)
		var discovered fabric.DiscoverResult
		if err = json.Unmarshal(raw, &discovered); err != nil || len(discovered.Candidates) != 1 || discovered.Candidates[0].Document.Ref != ref {
			t.Fatal("lost description-only discovery", err, string(raw))
		}
		if turn > 0 && string(raw) != string(prior) {
			t.Fatal("restart changed index results")
		}
		prior = raw
		if err = client.Close(); err != nil {
			t.Fatal(err)
		}
		if err = n.CloseContext(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err = os.Lstat(socket); !os.IsNotExist(err) {
			t.Fatal("listener did not join/remove actual socket", err)
		}
	}
	retained, err := registry.Open(ctx, dir)
	if err != nil {
		t.Fatal("product shutdown did not release installation writer", err)
	}
	defer retained.Close()
	if retained.AuthorityIdentity().StoreID != root.StoreID {
		t.Fatal("root changed")
	}
}
func TestInstalledNodeMissingStateNeverBootstraps(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := OpenInstalled(context.Background(), InstalledConfig{Directory: dir, Binary: binary}); err == nil {
		n.Close()
		t.Fatal("product silently bootstrapped")
	}
	if _, err = os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("missing installation generated state", err)
	}
}
