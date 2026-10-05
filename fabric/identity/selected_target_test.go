package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func TestSelectedNativeOfferSignedSourceSurvivesRegistryRestartAndRetirement(t *testing.T) {
	f := fixture(t)
	c := f.controller(t, 0, "selected-offer-A")
	b := f.binding(t, c)
	ref, _ := f.scope.Endpoint.WithOfferID(bytes.Repeat([]byte{18}, 32))
	rev, err := f.store.PutOffer(context.Background(), f.owner, fabric.OfferDescriptor{Ref: ref, Name: "Typed original", BindingID: f.scope.BindingID, InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false}`)}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, original, final := f.invocation(t)
	var before, after fabric.Envelope
	_ = json.Unmarshal(original, &before)
	_ = json.Unmarshal(final, &after)
	before.Target = &ref
	before.ExpectedRevision = rev
	after.Target = &ref
	after.ExpectedRevision = rev
	original, _ = json.Marshal(before)
	final, _ = json.Marshal(after)
	caller, err := fabric.NewAuthenticatedContext(localOwner, f.store.Namespace(), original)
	if err != nil {
		t.Fatal(err)
	}
	source, err := f.a.Admit(context.Background(), f.owner, c, b, caller, original, final, "offer-admission", "attempt", "replay")
	if err != nil {
		t.Fatal(err)
	}
	if source.Target != ref || source.TargetRevision != rev || source.Scope.Endpoint != f.scope.Endpoint || source.InputSchemaDigest == ([32]byte{}) {
		t.Fatal("selected offer not signed independently of physical source")
	}
	if _, err = f.store.RetireOffer(context.Background(), f.owner, ref, rev); err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.RegisterOrigin(context.Background(), f.owner, c, b, source, caller, original, final, "never-launched", "new-generation"); err == nil {
		t.Fatal("retired offer allowed new paid activation")
	}
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := registry.Open(context.Background(), f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	authority, err := New(opened, f.fence)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := authority.RestoreOriginalCaller(context.Background(), f.owner, source, original, final)
	if err != nil || restored.PrincipalView() != localOwner {
		t.Fatal("history lost selected offer provenance", err)
	}
	tampered := source
	tampered.Target = f.scope.Endpoint
	if _, err = authority.RestoreOriginalCaller(context.Background(), f.owner, tampered, original, final); err == nil {
		t.Fatal("signed selected target substituted")
	}
}
