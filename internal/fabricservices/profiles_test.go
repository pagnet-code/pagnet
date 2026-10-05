package fabricservices

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func serviceFixture(t *testing.T) (*ProfileStore, registry.DescriptorBatchScope, fabric.ExecutionContext, string) {
	t.Helper()
	owner := fabric.Principal{Ref: "fixture.operator", Kind: "local.owner", Issuer: "fixture.retained.root"}
	dir := filepath.Join(t.TempDir(), "registry")
	s, e := registry.Bootstrap(t.Context(), dir, owner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	caller, e := fabric.NewAuthenticatedContext(owner, s.Namespace(), []byte("explicit owned fixture assertion"))
	if e != nil {
		t.Fatal(e)
	}
	ref, _ := fabric.NewEndpointRef(s.AuthorityIdentity().PublicKey)
	rev, e := s.Register(t.Context(), caller, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Name: "Installed service", Kind: "tool.mcp", Description: "Private provider", Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "2026-07-28", Cancellation: true}}}})
	if e != nil {
		t.Fatal(e)
	}
	key, e := durable.NewAESGCM(durable.KeyReference{ID: "explicit-service-key", Version: "1"}, bytes.Repeat([]byte{27}, 32))
	if e != nil {
		t.Fatal(e)
	}
	p, e := NewProfileStore(t.Context(), s, func(context.Context) (fabric.ExecutionContext, error) { return caller, nil }, key)
	if e != nil {
		t.Fatal(e)
	}
	return p, registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: rev, BindingID: "mcp"}, caller, dir
}
func serviceProfile() Profile {
	return Profile{Protocol: "mcp.tools", Version: "2026-07-28", CredentialSelector: "private-provider-selector", BindingDigest: sha256.Sum256([]byte("actual-selected-account")), MCP: &MCPProfile{URL: "https://private-service.example/mcp", Limits: mcp.DefaultLimits}}
}
func TestActualProfileRetainedImmutableEncryptedAndRevisionFenced(t *testing.T) {
	p, scope, caller, dir := serviceFixture(t)
	v := serviceProfile()
	if _, _, e := p.Get(t.Context(), scope); !missing(e) {
		t.Fatal("Get fabricated missing installation", e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gen, e := p.Install(t.Context(), scope, v)
			if e == nil && gen != 1 {
				e = denied()
			}
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	changed := v
	changed.BindingDigest = sha256.Sum256([]byte("different account"))
	if _, e := p.Install(t.Context(), scope, changed); e == nil {
		t.Fatal("account changed under same binding")
	}
	d, e := p.store.GetEndpoint(t.Context(), scope.Endpoint, scope.ExpectedEndpointRevision)
	if e != nil {
		t.Fatal(e)
	}
	old := d.Revision
	d.Revision = ""
	d.Name = "Renamed service"
	rev, e := p.store.Update(t.Context(), caller, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: old})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = p.Get(t.Context(), scope); e == nil {
		t.Fatal("stale revision accepted")
	}
	scope.ExpectedEndpointRevision = rev
	if e = p.store.Close(); e != nil {
		t.Fatal(e)
	}
	s, e := registry.Open(t.Context(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	reopened, e := NewProfileStore(t.Context(), s, p.owner, p.protector)
	if e != nil {
		t.Fatal(e)
	}
	got, gen, e := reopened.Get(t.Context(), scope)
	if e != nil || gen != 1 || !sameProfile(got, v) {
		t.Fatal("restart changed retained profile", gen, e)
	}
	wrong, _ := durable.NewAESGCM(p.protector.Reference(), bytes.Repeat([]byte{28}, 32))
	bad, _ := NewProfileStore(t.Context(), s, p.owner, wrong)
	if _, _, e = bad.Get(t.Context(), scope); e == nil {
		t.Fatal("wrong retained key accepted")
	}
	for _, name := range []string{"registry.sqlite", "registry.sqlite-journal"} {
		raw, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil && os.IsNotExist(e) {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		for _, secret := range []string{v.CredentialSelector, v.MCP.URL, "different account"} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatal("private service profile leaked to root file")
			}
		}
	}
	exact, _ := json.Marshal(v)
	if len(exact) == 0 {
		t.Fatal("fixture")
	}
}
func TestPrivateServiceProfilesRejectUnsafeAddressesAndUnboundedInputs(t *testing.T) {
	p, scope, _, _ := serviceFixture(t)
	for _, url := range []string{"https://u:secret@private/mcp", "https://private/mcp?token=secret", "https://private/mcp#secret", "http://private/mcp"} {
		v := serviceProfile()
		v.MCP.URL = url
		if _, e := p.Install(t.Context(), scope, v); e == nil {
			t.Fatal("unsafe profile accepted", url)
		}
	}
	v := serviceProfile()
	v.MCP.URL = ""
	v.MCP.Binary = "relative-binary"
	if _, e := p.Install(t.Context(), scope, v); e == nil {
		t.Fatal("PATH executable resolution accepted")
	}
	if _, _, e := p.Get(t.Context(), scope); !missing(e) {
		t.Fatal("failed installation wrote state", e)
	}
}
