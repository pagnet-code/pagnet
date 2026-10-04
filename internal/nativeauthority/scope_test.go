package nativeauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type ownerFence struct{}

func (ownerFence) WithAdmission(_ context.Context, f fabricidentity.AdmissionFacts, commit func(fabricidentity.Witness) error) error {
	return commit(fabricidentity.Witness{Version: "local.owner.v1", FinalizedDigest: f.FinalizedDigest, Value: json.RawMessage(`{}`)})
}
func bindingFixture(t *testing.T) (registry.AuthorityIdentity, fabricidentity.Binding) {
	t.Helper()
	p := fabric.Principal{Ref: "spiffe://local/owner", Kind: "local.owner", Issuer: "pinned.local"}
	s, e := registry.Bootstrap(context.Background(), filepath.Join(t.TempDir(), "domain"), p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	c, e := fabric.NewAuthenticatedContext(p, s.Namespace(), []byte("verified setup"))
	if e != nil {
		t.Fatal(e)
	}
	ref, e := fabric.NewEndpointRef(s.AuthorityIdentity().PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	rev, e := s.Register(context.Background(), c, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Offline", Description: "Local", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	a, e := fabricidentity.New(s, ownerFence{})
	if e != nil {
		t.Fatal(e)
	}
	controller, e := a.AcquireController(context.Background(), c, fabricidentity.Scope{Endpoint: ref, DescriptorRevision: rev, BindingID: "native"}, 0, "request", "controller")
	if e != nil {
		t.Fatal(e)
	}
	b, e := a.BindWorker(context.Background(), c, controller, 0, fabricidentity.WorkerBinding{WorkerID: "actual-local-worker", StateDirectoryID: "random-state-dir", OwnershipGeneration: "ownership-generation", ActualRuntime: "fake-persistent", ProfileDigest: sha256.Sum256([]byte("profile"))})
	if e != nil {
		t.Fatal(e)
	}
	return a.Identity(), b
}
func TestCloudScopeOriginalBytesAndClosedAuthorityRoundTrip(t *testing.T) {
	cloud := CloudScope{ServerURL: "https://configured.example", TenantID: "actual-tenant", AccountID: "actual-account", HostID: "actual-host", InstanceID: "actual-instance", Generation: "actual-ownership-generation"}
	raw, e := json.Marshal(cloud)
	if e != nil {
		t.Fatal(e)
	}
	if string(raw) != `{"serverUrl":"https://configured.example","tenantId":"actual-tenant","accountId":"actual-account","hostId":"actual-host","instanceId":"actual-instance","generation":"actual-ownership-generation"}` {
		t.Fatal("cloud source/capture bytes changed")
	}
	scoped, e := NewCloudScope(cloud)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := json.Marshal(scoped)
	if e != nil {
		t.Fatal(e)
	}
	var roundtrip Scope
	if e = json.Unmarshal(wire, &roundtrip); e != nil || roundtrip != scoped {
		t.Fatal("comparable cloud scope roundtrip", e)
	}
	if _, local := scoped.Local(); local || scoped.WorkerID() != cloud.InstanceID {
		t.Fatal("cloud native identity changed")
	}
	for _, url := range []string{"", "localhost", "https://user:pass@host", "https://host?auth=secret"} {
		bad := cloud
		bad.ServerURL = url
		if _, e = NewCloudScope(bad); e == nil {
			t.Fatal("invalid cloud authority", url)
		}
	}
}
func TestLocalScopeGenuineBindingNoInventedCloudFields(t *testing.T) {
	root, binding := bindingFixture(t)
	scope, e := NewLocalScope(root, binding)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := json.Marshal(scope)
	if e != nil {
		t.Fatal(e)
	}
	for _, forbidden := range []string{"serverUrl", "tenantId", "accountId", "hostId", "runnerId", "bootId", "nativeAdmissionId"} {
		if bytes.Contains(wire, []byte(`"`+forbidden+`"`)) {
			t.Fatal("invented cloud authority field", forbidden)
		}
	}
	var parsed Scope
	if e = json.Unmarshal(wire, &parsed); e != nil || parsed != scope {
		t.Fatal("exact local comparable scope", e)
	}
	if parsed.Kind() != Local || parsed.WorkerID() != binding.Worker.WorkerID || parsed.OwnershipGeneration() != binding.Worker.OwnershipGeneration {
		t.Fatal("local/native generations confused")
	}
	foreign, _ := bindingFixture(t)
	if _, e = NewLocalScope(foreign, binding); e == nil {
		t.Fatal("unpinned foreign root")
	}
	binding.Worker.StateDirectoryID = "different-state-dir"
	if _, e = NewLocalScope(root, binding); e == nil {
		t.Fatal("same-root state directory assertion forged")
	}
}
func TestAuthorityWireRejectsMixedUnknownAndInvalidVariants(t *testing.T) {
	root, binding := bindingFixture(t)
	scope, e := NewLocalScope(root, binding)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := json.Marshal(scope)
	var fields map[string]json.RawMessage
	json.Unmarshal(wire, &fields)
	for _, mutate := range []func(map[string]json.RawMessage){
		func(m map[string]json.RawMessage) { m["cloud"] = json.RawMessage(`{}`) },
		func(m map[string]json.RawMessage) { m["cloud"] = json.RawMessage(`null`) },
		func(m map[string]json.RawMessage) { m["format"] = json.RawMessage(`"unknown"`) },
		func(m map[string]json.RawMessage) { m["unsignedPolicy"] = json.RawMessage(`{}`) },
	} {
		copy := map[string]json.RawMessage{}
		for k, v := range fields {
			copy[k] = v
		}
		mutate(copy)
		raw, _ := json.Marshal(copy)
		var parsed Scope
		if json.Unmarshal(raw, &parsed) == nil {
			t.Fatal("invalid authority wire accepted")
		}
	}
	if _, e = json.Marshal(Scope{}); e == nil {
		t.Fatal("zero authority emitted")
	}
	var parsed Scope
	if json.Unmarshal([]byte(`null`), &parsed) == nil {
		t.Fatal("null authority")
	}
}
