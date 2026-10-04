package catalog

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"path/filepath"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func catalogFixture(t *testing.T) (Config, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "registry")
	owner := fabric.Principal{Ref: "fixture.operator", Kind: "local.owner", Issuer: "fixture.authority"}
	store, err := registry.Bootstrap(t.Context(), dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	identity := store.AuthorityIdentity()
	caller, err := fabric.NewAuthenticatedContext(owner, store.Namespace(), []byte("genuine pinned local fixture assertion"))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := fabric.NewEndpointRef(identity.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fabric.EndpointDescriptor{Ref: ref, Kind: "tool.mcp", Name: "Explicit provider", Description: "Private registered provider", Bindings: []fabric.BindingSummary{{ID: "provider", Protocol: "mcp.tools", Version: "2026-07-28", Cancellation: true}}}
	rev, err := store.Register(t.Context(), caller, fabric.RegistryUpdate{Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	protector, err := durable.NewAESGCM(durable.KeyReference{ID: "operator-secret", Version: "1"}, key[:])
	if err != nil {
		t.Fatal(err)
	}
	return Config{BindingDigest: sha256.Sum256([]byte("configured-provider-profile-and-principal")), Store: store, Owner: caller, Scope: registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: rev, BindingID: "provider"}, MaxTools: 4096, Protector: protector, KeyID: "operator-secret", KeyVersion: "1"}, dir
}
func tool(name, description string) mcp.ToolDescriptor {
	d := mcp.ToolDescriptor{Name: name, Description: description, InputSchema: json.RawMessage(`{"type":"object","properties":{"n":{"const":9007199254740993123456789}}}`)}
	d.Fingerprint = toolFingerprint(d)
	return d
}
func TestRealCatalogRestartExactSchemasRemovalNewIdentityAndMissingState(t *testing.T) {
	config, dir := catalogFixture(t)
	if _, err := Open(t.Context(), config); err == nil {
		t.Fatal("Open implicitly bootstrapped missing projection")
	}
	c, err := Bootstrap(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Bootstrap(t.Context(), config); err == nil {
		t.Fatal("Bootstrap replaced existing binding")
	}
	d := tool("compute", "Version one")
	result, err := c.Apply(t.Context(), "provider", config.Scope.Endpoint, mcp.CatalogDelta{Upsert: []mcp.ToolDescriptor{d}})
	if err != nil {
		t.Fatal(err)
	}
	old := result[0]
	if !bytes.Contains(old.Offer.InputSchema, []byte("9007199254740993123456789")) {
		t.Fatal("schema precision changed")
	}
	summary, err := c.Current(t.Context(), "provider")
	if err != nil || len(summary) != 1 || summary[0].Fingerprint != d.Fingerprint {
		t.Fatal("schema-free current summary unavailable", err)
	}
	if err = config.Store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := registry.Open(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	config.Store = reopened
	c, err = Open(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := c.Resolve(t.Context(), "provider", old.Offer.Ref, old.Offer.Revision)
	if err != nil || exact.Offer.Ref != old.Offer.Ref || exact.Offer.Revision != old.Offer.Revision {
		t.Fatal("restart replaced stable offer", err)
	}
	d = tool("compute", "Version two")
	updated, err := c.Apply(t.Context(), "provider", config.Scope.Endpoint, mcp.CatalogDelta{Upsert: []mcp.ToolDescriptor{d}})
	if err != nil {
		t.Fatal(err)
	}
	if updated[0].Offer.Ref != old.Offer.Ref || updated[0].Offer.Revision == old.Offer.Revision {
		t.Fatal("changed tool identity/revision incorrect")
	}
	if _, err = c.Resolve(t.Context(), "provider", old.Offer.Ref, old.Offer.Revision); err == nil {
		t.Fatal("stale remembered revision invoked")
	}
	if _, err = c.Apply(t.Context(), "provider", config.Scope.Endpoint, mcp.CatalogDelta{Remove: []string{"compute"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Resolve(t.Context(), "provider", old.Offer.Ref, ""); err == nil {
		t.Fatal("removed ref resolves")
	}
	reappeared, err := c.Apply(t.Context(), "provider", config.Scope.Endpoint, mcp.CatalogDelta{Upsert: []mcp.ToolDescriptor{d}})
	if err != nil {
		t.Fatal(err)
	}
	if reappeared[0].Offer.Ref == old.Offer.Ref {
		t.Fatal("name-only reappearance resurrected original identity")
	}
	_ = reopened.Close()
	final, err := registry.Open(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()
	config.Store = final
	if _, err = Open(t.Context(), config); err != nil {
		t.Fatal(err)
	}
}
func TestCatalogWrongProtectorEvenEmptyAndGenuineConcurrentCAS(t *testing.T) {
	config, _ := catalogFixture(t)
	c, err := Bootstrap(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	var wrongKey [32]byte
	wrong, err := durable.NewAESGCM(durable.KeyReference{ID: "operator-secret", Version: "1"}, wrongKey[:])
	if err != nil {
		t.Fatal(err)
	}
	bad := config
	bad.Protector = wrong
	if _, err = Open(t.Context(), bad); err == nil {
		t.Fatal("empty catalog accepted wrong same-reference key")
	}
	if _, err = c.Apply(t.Context(), "provider", config.Scope.Endpoint, mcp.CatalogDelta{Upsert: []mcp.ToolDescriptor{tool("a", "first")}}); err != nil {
		t.Fatal(err)
	}
	if _, err = other.Apply(t.Context(), "provider", config.Scope.Endpoint, mcp.CatalogDelta{Upsert: []mcp.ToolDescriptor{tool("b", "stale second writer")}}); err == nil {
		t.Fatal("stale catalog generation admitted")
	}
	current, err := other.Current(t.Context(), "provider")
	if err != nil || len(current) != 1 || current[0].ToolName != "a" {
		t.Fatal("partial stale delta committed", err)
	}
	bad = config
	bad.BindingDigest = sha256.Sum256([]byte("different-provider-or-principal"))
	if _, err = Open(t.Context(), bad); err == nil {
		t.Fatal("same public binding silently substituted provider/principal")
	}
	bad = config
	bad.KeyVersion = "2"
	if _, err = Open(t.Context(), bad); err == nil {
		t.Fatal("key configuration silently replaced")
	}
}

type credentials struct{}

func (credentials) Credentials(context.Context, string) (mcp.Credentials, error) {
	return mcp.Credentials{}, nil
}

type factory struct {
	server  *sdk.Server
	session *sdk.ServerSession
}

func (f *factory) Transport(ctx context.Context, _ mcp.Credentials, tap *mcp.ResultTap) (sdk.Transport, error) {
	client, server := sdk.NewInMemoryTransports()
	var err error
	f.session, err = f.server.Connect(ctx, server, nil)
	if err != nil {
		return nil, err
	}
	return tap.WrapLocal(client)
}
func TestOfficialProviderSyncUsesActualSignedRegistryAndExactInvoke(t *testing.T) {
	config, dir := catalogFixture(t)
	c, err := Bootstrap(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	var effects atomic.Int32
	server := sdk.NewServer(&sdk.Implementation{Name: "genuine-provider", Version: "1"}, nil)
	server.AddTool(&sdk.Tool{Name: "compute", Description: "Typed original result", InputSchema: json.RawMessage(`{"type":"object","properties":{"n":{"const":9007199254740993123456789}}}`)}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{StructuredContent: json.RawMessage(`{"n":9007199254740993123456789}`), Content: []sdk.Content{}}, nil
	})
	transport := &factory{server: server}
	adapter, err := mcp.New(t.Context(), mcp.Config{BindingID: "provider", Audience: config.Store.Namespace(), Endpoint: config.Scope.Endpoint, Credentials: credentials{}, Transport: transport, Catalog: c})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if err = adapter.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer transport.session.Close()
	if err = adapter.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	public, next, err := config.Store.ListOffers(t.Context(), config.Scope.Endpoint, config.Scope.ExpectedEndpointRevision, "", 100)
	if err != nil || next != "" || len(public) != 1 {
		t.Fatal("provider descriptors not genuine registry publication", err)
	}
	exact, err := adapter.Describe(t.Context(), public[0].Ref, public[0].Revision)
	if err != nil || effects.Load() != 0 {
		t.Fatal("discovery caused target effect", err)
	}
	stream, err := adapter.Invoke(t.Context(), config.Owner, fabric.EndpointDescriptor{Ref: config.Scope.Endpoint}, fabric.InvokeRequest{InvocationID: "engine-assigned-original", Target: exact.Ref, ExpectedRevision: exact.Revision, Input: json.RawMessage(`{"n":9007199254740993123456789}`)})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	var raw bytes.Buffer
	for {
		frame, err := stream.Next(t.Context())
		if err != nil {
			if err == io.EOF {
				t.Fatal("no genuine terminal")
			}
			t.Fatal(err)
		}
		raw.Write(frame.Data)
		if frame.Kind == fabric.FrameError {
			t.Fatal("provider execution failed")
		}
		if frame.Kind == fabric.FrameComplete {
			break
		}
	}
	if effects.Load() != 1 || !bytes.Contains(raw.Bytes(), []byte("9007199254740993123456789")) {
		t.Fatal("effect replay or numeric rounding")
	}
	if err = adapter.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	stable, _, err := config.Store.ListOffers(t.Context(), config.Scope.Endpoint, config.Scope.ExpectedEndpointRevision, "", 100)
	if err != nil || stable[0].Ref != exact.Ref || stable[0].Revision != exact.Revision {
		t.Fatal("unchanged sync replaced offer identity")
	}
	_ = adapter.Close()
	_ = transport.session.Close()
	_ = config.Store.Close()
	reopened, err := registry.Open(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	config.Store = reopened
	if _, err = Open(t.Context(), config); err != nil {
		t.Fatal("actual composed catalog restart failed", err)
	}
}
