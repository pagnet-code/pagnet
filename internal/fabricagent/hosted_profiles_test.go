//go:build linux || darwin

package fabricagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func TestHostedProfileRequiresRealKernelAdministrationAndKeepsOriginalPrivateCloudIdentity(t *testing.T) {
	ctx := t.Context()
	parent, e := os.MkdirTemp("", "pgn-hosted-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(parent)
	socket := filepath.Join(parent, "peer.sock")
	installation, e := localinstallation.Bootstrap(ctx, filepath.Join(parent, "authority"), localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	defer installation.Close()
	owner, e := installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	root := installation.Store.AuthorityIdentity()
	ref, _ := fabric.NewEndpointRef(root.PublicKey)
	descriptor := fabric.EndpointDescriptor{Ref: ref, Name: "Original Maria", Kind: "actor.agent", Description: "Sales and customers", Bindings: []fabric.BindingSummary{{ID: "original", Protocol: "pagnet.native-agent", Version: "1", Streaming: true}}}
	revision, e := installation.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: descriptor})
	if e != nil {
		t.Fatal(e)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "original"}
	profile := HostedProfile{DefinitionID: domain.NewID().String(), PrincipalID: domain.NewID().String(), NetworkID: domain.NewID().String(), OwnershipID: domain.NewID().String(), NativeProfile: sha256.Sum256([]byte("actual-original-private-profile")), WorkerDirectory: filepath.Join(parent, "original-cloud-worker"), Scope: sessionworker.Scope{ServerURL: "https://app.pagnet.dev", TenantID: domain.NewID().String(), AccountID: domain.NewID().String(), HostID: domain.NewID().String(), InstanceID: domain.NewID().String(), Generation: "genuine-original-generation"}}
	// Store conformance fixture supplies inspection, not native-effect authority.
	probes := 0
	profiles, e := NewHostedProfiles(ctx, installation.Store, func(context.Context) (fabric.ExecutionContext, error) { return owner, nil }, installation.Keys, func(_ context.Context, p HostedProfile) error {
		probes++
		if p != profile {
			return hostedProfileError()
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = profiles.Install(ctx, nil, scope, profile); e == nil || probes != 0 {
		t.Fatal("missing kernel capability reached original probe", e)
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	listener.SetUnlinkOnClose(false)
	if e = os.Chmod(socket, 0600); e != nil {
		t.Fatal(e)
	}
	peer, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	conn, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	auth, e := fabricauth.New(fabricauth.Config{Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: installation.Store.CurrentAuthorityIdentity})
	if e != nil {
		t.Fatal(e)
	}
	session, e := auth.BindOwner(ctx, conn)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	var escaped *fabricauth.OwnerAdministration
	e = session.WithOwnerAdministration(ctx, []byte(`{"operation":"agent.hosted.register"}`), func(ctx context.Context, access *fabricauth.OwnerAdministration) error {
		escaped = access
		generation, e := profiles.Install(ctx, access, scope, profile)
		if e != nil {
			return e
		}
		if generation != 1 {
			t.Fatal("initial original profile changed generation", generation)
		}
		retry, e := profiles.Install(ctx, access, scope, profile)
		if e != nil || retry != generation {
			t.Fatal("exact retry replaced original binding", retry, e)
		}
		changed := profile
		changed.Scope.Generation = "replacement"
		if _, e = profiles.Install(ctx, access, scope, changed); e == nil {
			t.Fatal("physical original generation replaced")
		}
		return nil
	})
	if e != nil {
		t.Fatal("real owner callback deadlocked or failed", e)
	}
	if _, e = profiles.Install(ctx, escaped, scope, profile); e == nil {
		t.Fatal("escaped capability gained persisted install authority")
	}
	got, fingerprint, e := profiles.Get(ctx, scope)
	if e != nil || !reflect.DeepEqual(got, profile) || fingerprint == ([32]byte{}) {
		t.Fatal("original private profile changed", got, e)
	}
	principal := fabric.Principal{Ref: scope.Endpoint.String(), Kind: "actor.agent", Issuer: root.Namespace}
	witness, e := profiles.CallerAuthority(ctx, scope, principal)
	if e != nil || witness.PrincipalView() != principal || witness.Digest() == ([32]byte{}) {
		t.Fatal("original cloud actor association witness", e)
	}
	verifyCurrent := func() error {
		return installation.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{}, witness.VerifyTx)
	}
	if e = verifyCurrent(); e != nil {
		t.Fatal("genuine current signed profile transaction", e)
	}
	if _, e = profiles.CallerAuthority(ctx, scope, root.Owner); e == nil {
		t.Fatal("original cloud actor association impersonated operator")
	}
	var stored []byte
	e = installation.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
		row, e := tx.Get(hostedProfileKey(scope))
		stored = row.Value
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(stored, []byte(profile.Scope.InstanceID)) || bytes.Contains(stored, []byte(profile.WorkerDirectory)) || bytes.Contains(stored, []byte("https://app.pagnet.dev")) {
		t.Fatal("private original identity/path persisted in plaintext")
	}
	descriptor.Revision = revision
	descriptor.Name = "Public name changed"
	descriptor.Revision = ""
	next, e := installation.Store.Update(ctx, owner, fabric.RegistryUpdate{Descriptor: descriptor, ExpectedRevision: revision})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = profiles.Get(ctx, scope); e == nil {
		t.Fatal("stale descriptor revision retained paid binding")
	}
	if e = verifyCurrent(); e == nil {
		t.Fatal("stale signed actor witness survived descriptor change")
	}
	scope.ExpectedEndpointRevision = next
	if _, _, e = profiles.Get(ctx, scope); e == nil {
		t.Fatal("new revision silently regenerated original profile")
	}
}
