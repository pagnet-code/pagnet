//go:build linux || darwin

package fabricagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestHostedPublicationExactEncryptedRetryKernelOwnerAndRestart(t *testing.T) {
	ctx := t.Context()
	parent, err := os.MkdirTemp("", "pgn-pub-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	socket := filepath.Join(parent, "peer.sock")
	dir := filepath.Join(parent, "root")
	i, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { i.Close() }()
	owner, _ := i.Operator(ctx)
	root := i.Store.AuthorityIdentity()
	ref, _ := fabric.NewEndpointRef(root.PublicKey)
	d := fabric.EndpointDescriptor{Ref: ref, Name: "Maria", Kind: "actor.agent", Description: "Sales", Bindings: []fabric.BindingSummary{{ID: "original", Protocol: "pagnet.agent.hosted-native.v1", Version: "1"}}}
	revision, err := i.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: d})
	if err != nil {
		t.Fatal(err)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "original"}
	profile := HostedProfile{DefinitionID: domain.NewID().String(), PrincipalID: domain.NewID().String(), NetworkID: domain.NewID().String(), OwnershipID: domain.NewID().String(), NativeProfile: sha256.Sum256([]byte("original")), WorkerDirectory: filepath.Join(parent, "worker"), Scope: sessionworker.Scope{ServerURL: "https://app.pagnet.dev", TenantID: domain.NewID().String(), AccountID: domain.NewID().String(), HostID: domain.NewID().String(), InstanceID: domain.NewID().String(), Generation: "original-generation"}}
	newProfiles := func() *HostedProfiles {
		p, err := NewHostedProfiles(ctx, i.Store, func(context.Context) (fabric.ExecutionContext, error) { return owner, nil }, i.Keys, func(_ context.Context, p HostedProfile) error {
			if p != profile {
				return hostedProfileError()
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	profiles := newProfiles()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	bind := func() *fabricauth.Session {
		a, err := fabricauth.New(fabricauth.Config{Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: i.Store.CurrentAuthorityIdentity})
		if err != nil {
			t.Fatal(err)
		}
		s, err := a.BindOwner(ctx, conn)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	session := bind()
	defer func() { session.Close() }()
	prepared := 0
	prepare := func(_ context.Context, p HostedProfile) (transport.FabricHostedPublication, error) {
		prepared++
		aad := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: p.Scope.TenantID, NetworkID: p.NetworkID, ObjectType: transport.ObjectTypeFabricDescriptor, ObjectID: ref.String(), Sender: p.Scope.InstanceID, Recipient: ref.String(), CreatedAt: "2026-10-05T00:00:00Z", KeyEpochID: domain.NewID().String()}
		// A large ciphertext exercises atomic chunks above the 64 KiB root-value
		// limit. This is a journal storage fixture, not a runtime ownership mock.
		env, err := e2ee.Encrypt(bytes.Repeat([]byte("private original descriptor "), 6000), [32]byte{1}, aad)
		return transport.FabricHostedPublication{RequestID: domain.NewID().String(), Ref: ref, Revision: revision, DomainPublicKey: root.PublicKey, NetworkID: p.NetworkID, InstanceID: p.Scope.InstanceID, OwnershipID: p.OwnershipID, OwnershipGeneration: p.Scope.Generation, Envelope: env, AAD: aad}, err
	}
	var original []byte
	var escaped *fabricauth.OwnerAdministration
	run := func(initial bool) error {
		return session.WithOwnerAdministration(ctx, []byte(`{"operation":"hosted.publish"}`), func(ctx context.Context, a *fabricauth.OwnerAdministration) error {
			escaped = a
			if initial {
				if _, err := profiles.Install(ctx, a, scope, profile); err != nil {
					return err
				}
			}
			p, err := profiles.PreparePublication(ctx, a, scope, "", prepare)
			if err != nil {
				return err
			}
			raw, _ := json.Marshal(p)
			if original == nil {
				original = raw
			} else if !bytes.Equal(original, raw) {
				t.Fatal("retry changed ciphertext, epoch or request identity")
			}
			if _, err = profiles.PreparePublication(ctx, a, scope, "wrong-CAS-revision", prepare); err == nil {
				t.Fatal("changed expected relay revision accepted")
			}
			return nil
		})
	}
	if err = run(true); err != nil {
		t.Fatal(err)
	}
	if err = run(false); err != nil {
		t.Fatal(err)
	}
	if _, err = profiles.PreparePublication(ctx, escaped, scope, "", prepare); err == nil {
		t.Fatal("escaped kernel owner capability")
	}
	if prepared != 1 {
		t.Fatal("retry re-encrypted descriptor", prepared)
	}
	session.Close()
	if err = i.Close(); err != nil {
		t.Fatal(err)
	}
	i, err = localinstallation.Load(ctx, dir, registry.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	owner, err = i.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	profiles = newProfiles()
	session = bind()
	if err = run(false); err != nil {
		t.Fatal("restart replaced encrypted publication", err)
	}
	if prepared != 1 {
		t.Fatal("restart regenerated ciphertext", prepared)
	}
}
