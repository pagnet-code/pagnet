//go:build linux || darwin

package fabricnode

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func TestActualFederationExposurePrivateInstallationRestartCurrentCAS(t *testing.T) {
	ctx := t.Context()
	private, e := os.MkdirTemp("", "pagnet-exposure-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	dir := filepath.Join(private, "domain")
	socket := filepath.Join(private, "fabric.sock")
	installed, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	defer installed.Close()
	owner, e := installed.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewFederationExposures(ctx, installed.Store, installed.Operator, installed, installed.Keys)
	if e != nil {
		t.Fatal(e)
	}
	if s.Reload(ctx) == nil {
		t.Fatal("missing exposure auto initialized")
	}
	ref, _ := fabric.NewEndpointRef(installed.Store.AuthorityIdentity().PublicKey)
	rev, e := installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Name: "published", Kind: "tool.local", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	remoteRef, _ := fabric.NewEndpointRef(make([]byte, 32))
	remote := remoteRef.Domain()
	c := FederationExposureConfiguration{Exposures: []FederationExposure{{remote, ref, rev, "native"}}}
	generation, e := s.Put(ctx, 0, c)
	if e != nil {
		t.Fatal(e)
	}
	if again, e := s.Put(ctx, 0, c); e != nil || again != generation {
		t.Fatal("exact install retry changed original", again, e)
	}
	check := func(store *registry.Store, owner fabric.ExecutionContext, s *FederationExposures, target fabric.EndpointRef, rev fabric.Revision, binding string) error {
		return store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error { return s.CheckTx(tx, remote, target, rev, binding) })
	}
	if e = check(installed.Store, owner, s, ref, rev, "native"); e != nil {
		t.Fatal(e)
	}
	if check(installed.Store, owner, s, ref, rev, "wrong") == nil || check(installed.Store, owner, s, ref, "stale", "native") == nil {
		t.Fatal("inferred exposure")
	}
	stale, e := NewFederationExposures(ctx, installed.Store, installed.Operator, installed, installed.Keys)
	if e != nil {
		t.Fatal(e)
	}
	if e = stale.Reload(ctx); e != nil {
		t.Fatal(e)
	}
	generation, e = s.Put(ctx, generation, FederationExposureConfiguration{})
	if e != nil {
		t.Fatal(e)
	}
	if check(installed.Store, owner, stale, ref, rev, "native") == nil {
		t.Fatal("stale compiled exposure survived retirement")
	}
	if e = installed.Close(); e != nil {
		t.Fatal(e)
	}
	installed, e = localinstallation.Load(ctx, dir, registry.DefaultOptions())
	if e != nil {
		t.Fatal(e)
	}
	defer installed.Close()
	s, e = NewFederationExposures(ctx, installed.Store, installed.Operator, installed, installed.Keys)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Reload(ctx); e != nil {
		t.Fatal(e)
	}
	owner, e = installed.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if check(installed.Store, owner, s, ref, rev, "native") == nil {
		t.Fatal("restart resurrected removed exposure")
	}
	static, _ := fabric.NewAuthenticatedContext(owner.PrincipalView(), installed.Store.Namespace(), []byte("static owner name"))
	if _, e = NewFederationExposures(ctx, installed.Store, func(context.Context) (fabric.ExecutionContext, error) { return static, nil }, installed, installed.Keys); e == nil {
		t.Fatal("static setup proof accepted")
	}
}
