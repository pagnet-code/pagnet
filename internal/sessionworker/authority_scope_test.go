//go:build linux || darwin

package sessionworker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

type localOwnerFence struct{}

func (localOwnerFence) WithAdmission(_ context.Context, f fabricidentity.AdmissionFacts, commit func(fabricidentity.Witness) error) error {
	return commit(fabricidentity.Witness{Version: "local.owner.v1", FinalizedDigest: f.FinalizedDigest, Value: json.RawMessage(`{}`)})
}

func (localOwnerFence) WithNativeControl(_ context.Context, f fabricidentity.NativeControlFacts, commit func() error) error {
	if f.Owner.Ref != "spiffe://local/owner" || f.Owner.Issuer != "pinned.local" {
		return fabric.NewError(fabric.CodeUnauthenticated, "fixture control denied")
	}
	return commit()
}

func (localOwnerFence) WithNativeCancellation(_ context.Context, f fabricidentity.NativeCancellationFacts, commit func() error) error {
	if f.Owner.Ref != "spiffe://local/owner" || f.Caller != f.Owner {
		return fabric.NewError(fabric.CodeUnauthenticated, "fixture cancellation denied")
	}
	return commit()
}

type localAuthorityFixture struct {
	scope      AuthorityScope
	authority  *fabricidentity.Authority
	owner      fabric.ExecutionContext
	controller fabricidentity.Controller
	binding    fabricidentity.Binding
	directory  string
	store      *registry.Store
}

func localJournalScope(t *testing.T) AuthorityScope { return newLocalAuthorityFixture(t).scope }
func newLocalAuthorityFixture(t *testing.T) localAuthorityFixture {
	t.Helper()
	principal := fabric.Principal{Ref: "spiffe://local/owner", Kind: "local.owner", Issuer: "pinned.local"}
	directory := filepath.Join(t.TempDir(), "domain")
	store, e := registry.Bootstrap(context.Background(), directory, principal)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	owner, e := fabric.NewAuthenticatedContext(principal, store.Namespace(), []byte("authenticated owner setup"))
	if e != nil {
		t.Fatal(e)
	}
	ref, e := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	revision, e := store.Register(context.Background(), owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Offline", Description: "Local native", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	authority, e := fabricidentity.New(store, localOwnerFence{})
	if e != nil {
		t.Fatal(e)
	}
	controller, e := authority.AcquireController(context.Background(), owner, fabricidentity.Scope{Endpoint: ref, DescriptorRevision: revision, BindingID: "native"}, 0, "controller-request", "actual-controller")
	if e != nil {
		t.Fatal(e)
	}
	binding, e := authority.BindWorker(context.Background(), owner, controller, 0, fabricidentity.WorkerBinding{WorkerID: "real-local-worker", StateDirectoryID: "random-state-dir-identity", OwnershipGeneration: "ownership-generation", ActualRuntime: "fake-persistent", ProfileDigest: sha256.Sum256([]byte("actual profile"))})
	if e != nil {
		t.Fatal(e)
	}
	scope, e := nativeauthority.NewLocalScope(authority.Identity(), binding)
	if e != nil {
		t.Fatal(e)
	}
	return localAuthorityFixture{scope, authority, owner, controller, binding, directory, store}
}
func TestLocalJournalIndependentImmutableStorageNoCloudAdmission(t *testing.T) {
	scope := localJournalScope(t)
	dir := filepath.Join(t.TempDir(), "worker")
	journal, e := OpenAuthorityJournal(dir, scope)
	if e != nil {
		t.Fatal(e)
	}
	var protocol, raw string
	if e = journal.db.QueryRow("SELECT protocol,scope FROM worker_meta").Scan(&protocol, &raw); e != nil {
		t.Fatal(e)
	}
	if protocol != LocalProtocol || journal.scope != (Scope{}) || journal.authorityScope() != scope || journal.instanceID() != scope.WorkerID() {
		t.Fatal("local ownership mapped to cloud scope")
	}
	for _, field := range []string{"serverUrl", "accountId", "tenantId", "hostId", "runnerId", "nativeAdmissionId"} {
		if strings.Contains(raw, `"`+field+`"`) {
			t.Fatal("fake cloud field in local metadata", field)
		}
	}
	current := lease(t, journal)
	if _, execute, e := journal.Admit(context.Background(), current, 1, "unauthorized-command", "prompt", json.RawMessage(`{"input":"cannot execute"}`)); e == nil || execute {
		t.Fatal("local mode accepted unauthenticated cloud/generic admission", e)
	}
	journal.Close()
	if cloud, e := OpenJournal(dir, testScope()); e == nil {
		cloud.Close()
		t.Fatal("local storage relabeled as cloud")
	}
	reopened, e := OpenAuthorityJournal(dir, scope)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if reopened.authorityScope() != scope {
		t.Fatal("restart rewrote original ownership")
	}
}
func TestCloudAuthorityJournalPreservesOriginalMetaBytes(t *testing.T) {
	scope := testScope()
	journal, _ := testJournal(t)
	var protocol, stored string
	if e := journal.db.QueryRow("SELECT protocol,scope FROM worker_meta").Scan(&protocol, &stored); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(scope)
	if e != nil {
		t.Fatal(e)
	}
	if protocol != Protocol || stored != string(raw) {
		t.Fatal("current cloud journal/source bytes changed")
	}
	if cloud, ok := journal.authorityScope().Cloud(); !ok || cloud != scope {
		t.Fatal("cloud ownership metadata not retained")
	}
}
