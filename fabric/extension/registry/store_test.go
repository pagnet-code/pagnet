//go:build linux || darwin

package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	domain "github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

type kernelFixture struct {
	config  Config
	owner   fabric.ExecutionContext
	root    *domain.Store
	session *fabricauth.Session
	path    string
	auth    *fabricauth.Authority
}

func fixture(t *testing.T) kernelFixture {
	t.Helper()
	directory, err := os.MkdirTemp("", "pgn-extension-owner-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	path := filepath.Join(directory, "domain")
	owner := fabric.Principal{Ref: "local:actual-owner", Issuer: "registered-owner", Kind: "local.owner"}
	root, err := domain.Bootstrap(t.Context(), path, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	caller, gate, session, auth := kernelOwner(t, root)
	p, err := durable.NewAESGCM(durable.KeyReference{ID: "extension-private-key", Version: "1"}, bytes.Repeat([]byte{37}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return kernelFixture{DefaultConfig(root, p, gate), caller, root, session, path, auth}
}
func kernelOwner(t *testing.T, root *domain.Store) (fabric.ExecutionContext, OwnerValidator, *fabricauth.Session, *fabricauth.Authority) {
	t.Helper()
	directory, err := os.MkdirTemp("", "pgn-extension-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socket := filepath.Join(directory, "owner.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	if err = os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	peer, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	identity := root.AuthorityIdentity()
	auth, err := fabricauth.New(fabricauth.Config{Root: identity, RootOwner: identity.Owner, Audience: identity.Namespace, SocketPath: socket, CurrentRoot: root.CurrentAuthorityIdentity})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.BindOwner(t.Context(), peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	current := func(ctx context.Context) (fabric.ExecutionContext, error) {
		raw, proof, e := session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationDiscover, Discover: &fabric.DiscoverRequest{Query: "management", Limit: 1}})
		if e != nil {
			return fabric.ExecutionContext{}, e
		}
		return auth.Authenticate(ctx, fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: identity.Namespace, PeerEvidence: proof})
	}
	caller, err := current(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	gate := func(ctx context.Context, asserted fabric.ExecutionContext, r domain.AuthorityIdentity) error {
		fresh, e := current(ctx)
		if e != nil || fresh.PrincipalView() != asserted.PrincipalView() || r.Namespace != identity.Namespace {
			return errors.New("live kernel owner unavailable")
		}
		return nil
	}
	return caller, gate, session, auth
}
func installed(id string) Installation {
	manifest := extension.ExtensionManifest{ManifestVersion: "1.0", ID: id, Version: "1", MinProtocol: "1.0", MaxProtocol: "1.0", Interceptors: []extension.Registration{{ID: id + ".interceptor", Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Placement: extension.PlacementSource, NeedsPlaintext: true, Phases: []extension.Phase{extension.PhaseRequest, extension.PhaseResponse}, TimeoutMillis: 100, FailureMode: extension.FailClosed, Binding: "private.binding"}}}
	return Installation{manifest, []Binding{{ID: "private.binding", Protocol: "provider.http", Selector: "operator-selected-private-profile", ProfileDigest: hash([]byte("profile-a")), CredentialPrincipalRef: "credential-principal-ref"}}}
}
func TestActualKernelOwnerAtomicConfigRestartCASAndPrivateBindingCommitment(t *testing.T) {
	f := fixture(t)
	s, e := Bootstrap(t.Context(), f.owner, f.config)
	if e != nil {
		t.Fatal(e)
	}
	first, e := s.Install(t.Context(), f.owner, 1, installed("acme.extension"))
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := s.Snapshot()
	if e != nil || snapshot.Generation != 2 {
		t.Fatal(e)
	}
	same := installed("acme.extension")
	same.Bindings[0].ProfileDigest = hash([]byte("profile-b"))
	second, e := s.Update(t.Context(), f.owner, 2, first.Revision, same)
	if e != nil {
		t.Fatal(e)
	}
	newer, _ := s.Snapshot()
	if newer.Plan.Revision() == snapshot.Plan.Revision() {
		t.Fatal("private provider change reused continuation identity")
	}
	if _, e = s.Update(t.Context(), f.owner, 2, first.Revision, same); e == nil {
		t.Fatal("stale generation CAS accepted")
	}
	_, inspection, e := s.Inspect(t.Context(), f.owner, "acme.extension")
	if e != nil {
		t.Fatal(e)
	}
	inspection.Bindings[0].Selector = "mutated by caller"
	_, unchanged, e := s.Inspect(t.Context(), f.owner, "acme.extension")
	if e != nil || unchanged.Bindings[0].Selector == inspection.Bindings[0].Selector {
		t.Fatal("inspection shares owned config")
	}
	s.Close()
	originalIdentity := f.root.AuthorityIdentity()
	if e = f.root.Close(); e != nil {
		t.Fatal(e)
	}
	retained, e := domain.Open(t.Context(), f.path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { retained.Close() })
	if !reflect.DeepEqual(retained.AuthorityIdentity(), originalIdentity) {
		t.Fatal("retained root identity changed")
	}
	f.root = retained
	f.owner, f.config.OwnerValidator, f.session, f.auth = kernelOwner(t, retained)
	f.config.Root = retained
	s, e = Open(t.Context(), f.owner, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	resumed, _ := s.Snapshot()
	if resumed.Generation != newer.Generation || resumed.Plan.Revision() != newer.Plan.Revision() {
		t.Fatal("restart changed retained configuration identity")
	}
	if e = s.Remove(t.Context(), f.owner, 3, second.Revision, "acme.extension"); e != nil {
		t.Fatal(e)
	}
	third, e := s.Install(t.Context(), f.owner, 4, installed("acme.extension"))
	if e != nil {
		t.Fatal(e)
	}
	if third.PhysicalID == first.PhysicalID {
		t.Fatal("removed physical configuration resurrected")
	}
	raw, e := os.ReadFile(filepath.Join(f.path, "registry.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("operator-selected-private-profile")) || bytes.Contains(raw, []byte("credential-principal-ref")) {
		t.Fatal("binding config persisted in plaintext")
	}
}
func TestKnownCommittedReplyLostQuarantinesUntilSignedReload(t *testing.T) {
	f := fixture(t)
	s, e := Bootstrap(t.Context(), f.owner, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	real := s.transaction
	s.transaction = func(ctx context.Context, c fabric.ExecutionContext, scope domain.AuthorityScope, callback func(*domain.AuthorityTx) error) error {
		if e := real(ctx, c, scope, callback); e != nil {
			return e
		}
		return errors.New("committed response lost")
	}
	if _, e = s.Install(t.Context(), f.owner, 1, installed("acme.extension")); e == nil {
		t.Fatal("lost commit reply hidden")
	}
	if _, e = s.Snapshot(); e == nil {
		t.Fatal("uncertain publication exposed engine")
	}
	s.transaction = real
	if e = s.Reload(t.Context(), f.owner); e != nil {
		t.Fatal(e)
	}
	snapshot, e := s.Snapshot()
	if e != nil || snapshot.Generation != 2 {
		t.Fatal("genuine committed config not recovered", e)
	}
	reference, _, e := s.Inspect(t.Context(), f.owner, "acme.extension")
	if e != nil || reference.Revision != 1 {
		t.Fatal(e)
	}
}
func TestMissingWrongKeyForeignAndExpiredOwnerNeverReinitialize(t *testing.T) {
	f := fixture(t)
	if _, e := Open(t.Context(), f.owner, f.config); e == nil {
		t.Fatal("missing config silently bootstrapped")
	}
	s, e := Bootstrap(t.Context(), f.owner, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	wrong := f.config
	wrong.Protector, _ = durable.NewAESGCM(f.config.Protector.Reference(), bytes.Repeat([]byte{38}, 32))
	if _, e = Open(t.Context(), f.owner, wrong); e == nil {
		t.Fatal("wrong key accepted")
	}
	if _, e = s.Install(t.Context(), fabric.ExecutionContext{}, 1, installed("acme.extension")); e == nil {
		t.Fatal("unverified owner accepted")
	}
	f.session.Close()
	if _, e = s.Install(t.Context(), f.owner, 1, installed("acme.extension")); e == nil {
		t.Fatal("closed actual owner session accepted")
	}
	snapshot, e := s.Snapshot()
	if e != nil || snapshot.Generation != 1 {
		t.Fatal("denied management changed snapshot")
	}
}
func TestDAGPlacementBindingAndCapacityFailureDoesNotPublishPartialPlan(t *testing.T) {
	f := fixture(t)
	f.config.MaxExtensions = 1
	s, e := Bootstrap(t.Context(), f.owner, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	invalid := installed("acme.extension")
	invalid.Manifest.Interceptors[0].Before = []string{invalid.Manifest.Interceptors[0].ID}
	if _, e = s.Install(t.Context(), f.owner, 1, invalid); e == nil {
		t.Fatal("cycle accepted")
	}
	invalid = installed("acme.extension")
	invalid.Manifest.Interceptors[0].Placement = extension.PlacementRelay
	if _, e = s.Install(t.Context(), f.owner, 1, invalid); e == nil {
		t.Fatal("plaintext relay placement accepted")
	}
	invalid = installed("acme.extension")
	invalid.Bindings = nil
	if _, e = s.Install(t.Context(), f.owner, 1, invalid); e == nil {
		t.Fatal("unbound registration accepted")
	}
	valid, e := s.Install(t.Context(), f.owner, 1, installed("acme.extension"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Install(t.Context(), f.owner, 2, installed("other.extension")); e == nil {
		t.Fatal("extension count limit ignored")
	}
	snapshot, _ := s.Snapshot()
	if snapshot.Generation != 2 || valid.Revision != 1 {
		t.Fatal("failure published partial config")
	}
}
func TestPaginationGenerationPinsAndExternalSignedMutationInvalidatesFacade(t *testing.T) {
	f := fixture(t)
	s, e := Bootstrap(t.Context(), f.owner, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for i, id := range []string{"acme.a", "acme.b", "acme.c"} {
		if _, e = s.Install(t.Context(), f.owner, uint64(i+1), installed(id)); e != nil {
			t.Fatal(e)
		}
	}
	page, e := s.List(t.Context(), f.owner, "", 1)
	if e != nil || len(page.Entries) != 1 || page.NextCursor == "" {
		t.Fatal(e)
	}
	next, e := s.List(t.Context(), f.owner, page.NextCursor, 1)
	if e != nil || next.Entries[0].ID <= page.Entries[0].ID {
		t.Fatal("indexed page order failed", e)
	}
	other, e := Open(t.Context(), f.owner, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = other.Install(t.Context(), f.owner, 4, installed("acme.d")); e != nil {
		t.Fatal(e)
	}
	if _, e = s.List(t.Context(), f.owner, page.NextCursor, 1); e == nil {
		t.Fatal("external signed config generation hidden")
	}
	if _, e = s.Snapshot(); e == nil {
		t.Fatal("stale configuration not quarantined")
	}
	if e = s.Reload(t.Context(), f.owner); e != nil {
		t.Fatal(e)
	}
	if _, e = s.List(t.Context(), f.owner, page.NextCursor, 1); e == nil {
		t.Fatal("stale pagination cursor accepted")
	}
}
func TestReferencedEntryCipherSubstitutionFailsReload(t *testing.T) {
	f := fixture(t)
	s, e := Bootstrap(t.Context(), f.owner, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ref, e := s.Install(t.Context(), f.owner, 1, installed("acme.extension"))
	if e != nil {
		t.Fatal(e)
	}
	e = f.root.WithNativeAuthority(t.Context(), f.owner, scope(f.config), func(tx *domain.AuthorityTx) error {
		record, e := tx.Get(key(ref.PhysicalID))
		if e != nil {
			return e
		}
		var value sealed
		if e = json.Unmarshal(record.Value, &value); e != nil {
			return e
		}
		value.Cipher[0] ^= 1
		raw, _ := json.Marshal(value)
		_, e = tx.CAS(key(ref.PhysicalID), record.Revision, raw, false)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Reload(t.Context(), f.owner); e == nil {
		t.Fatal("signed out-of-band entry substitution accepted")
	}
	if _, e = s.Snapshot(); e == nil {
		t.Fatal("corrupt config published")
	}
}
func TestEntryByteBudgetAndConfigurationSelectorAreBounded(t *testing.T) {
	f := fixture(t)
	s, e := Bootstrap(t.Context(), f.owner, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	input := installed("acme.extension")
	input.Bindings[0].Selector = strings.Repeat("a", 4097)
	if _, e = s.Install(t.Context(), f.owner, 1, input); e == nil {
		t.Fatal("selector bound ignored")
	}
	snapshot, _ := s.Snapshot()
	if snapshot.Generation != 1 {
		t.Fatal("invalid config altered generation")
	}
}

func TestRuntimeSnapshotDoesNotWaitForManagementAuthentication(t *testing.T) {
	f := fixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	originalGate := f.config.OwnerValidator
	blocked := false
	f.config.OwnerValidator = func(ctx context.Context, c fabric.ExecutionContext, r domain.AuthorityIdentity) error {
		if blocked {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return originalGate(ctx, c, r)
	}
	s, err := Bootstrap(t.Context(), f.owner, f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	blocked = true
	done := make(chan error, 1)
	go func() { _, err := s.List(t.Context(), f.owner, "", 1); done <- err }()
	<-entered
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	// List owns the management mutex inside a live authentication callback.
	// Runtime access must still read its accepted immutable snapshot directly.
	snapshotDone := make(chan error, 1)
	go func() {
		snapshot, err := s.Snapshot()
		if err == nil && snapshot.Generation != 1 {
			err = errors.New("partial snapshot")
		}
		snapshotDone <- err
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	select {
	case err = <-snapshotDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("runtime snapshot blocked behind management")
	}
	close(release)
	released = true
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPrivateBindingOrderIsCanonicalAndCallerOwned(t *testing.T) {
	f := fixture(t)
	s, err := Bootstrap(t.Context(), f.owner, f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	input := installed("acme.extension")
	second := input.Bindings[0]
	second.ID = "aaa.extra"
	input.Bindings = append(input.Bindings, second)
	if _, err = s.Install(t.Context(), f.owner, 1, input); err != nil {
		t.Fatal(err)
	}
	_, retained, err := s.Inspect(t.Context(), f.owner, "acme.extension")
	if err != nil {
		t.Fatal(err)
	}
	if input.Bindings[0].ID != "private.binding" || retained.Bindings[0].ID != "aaa.extra" || retained.Bindings[1].ID != "private.binding" {
		t.Fatal("binding normalization mutated caller or failed canonical order")
	}
}
