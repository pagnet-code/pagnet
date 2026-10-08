package node

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// The production integration: the real registry store is the descriptor store,
// so the node discloses the friendly handle plus its truthful persisted label
// on explicit request only, with canonical references and revisions unchanged.
func TestDescribeDisclosesReferenceHandleOnlyOnExplicitRequest(t *testing.T) {
	ctx := context.Background()
	owner := fabric.Principal{Ref: "spiffe://local/owner", Kind: "local.owner", Issuer: "local.test"}
	store, e := registry.Bootstrap(ctx, filepath.Join(t.TempDir(), "domain"), owner)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	c, e := fabric.NewAuthenticatedContext(owner, store.Namespace(), []byte("trusted original request"))
	if e != nil {
		t.Fatal(e)
	}
	ref, e := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	d := fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Maria", Description: "Private research agent", Bindings: []fabric.BindingSummary{{ID: "local", Protocol: "local.native", Version: "1"}}}
	rev, e := store.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	view, e := store.AllocateReferenceHandle(ctx, c, ref, "Maria")
	if e != nil {
		t.Fatal(e)
	}
	service, e := New(Config{Audience: store.Namespace(), Authenticator: fixtureAuth{owner}, Descriptors: store})
	if e != nil {
		t.Fatal(e)
	}
	describe := func(include bool) fabric.Description {
		t.Helper()
		env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "describe-1", Principal: owner, Source: owner.Ref, CreatedAt: time.Now().UTC(), Operation: fabric.OperationDescribe, Context: fabric.EnvelopeContext{Origin: owner.Ref}}
		raw, err := json.Marshal(fabric.DescribeRequest{Selections: []fabric.DescribeSelection{{Ref: ref, IncludeReferenceHandle: include}}})
		if err != nil {
			t.Fatal(err)
		}
		env.Payload = raw
		result, err := execute(t, service, env)
		if err != nil || result.Describe == nil || len(result.Describe.Descriptions) != 1 {
			t.Fatal(result, err)
		}
		return result.Describe.Descriptions[0]
	}
	// Explicit request: handle + truthful persisted label + exact target.
	item := describe(true)
	if item.Endpoint == nil || item.Error != nil || item.ReferenceHandle == nil {
		t.Fatalf("requested disclosure: %+v", item)
	}
	if *item.ReferenceHandle != view || item.ReferenceHandle.Revision != rev {
		t.Fatalf("disclosed %+v, want %+v", item.ReferenceHandle, view)
	}
	// The canonical reference and revision are unchanged by the handle.
	if item.Endpoint.Ref != ref || item.Endpoint.Revision != rev {
		t.Fatalf("canonical descriptor changed: %+v", item.Endpoint)
	}
	// No explicit request: nothing disclosed.
	if item = describe(false); item.ReferenceHandle != nil || item.Endpoint == nil {
		t.Fatalf("disclosed without request: %+v", item)
	}
	// Descriptor update: the disclosed revision follows the canonical one and
	// the handle text advances; the descriptor stays DESCRIBE-only.
	d2 := d
	d2.Name = "Renamed"
	rev2, e := store.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d2, ExpectedRevision: rev})
	if e != nil {
		t.Fatal(e)
	}
	item = describe(true)
	if item.Endpoint.Revision != rev2 || item.ReferenceHandle == nil || item.ReferenceHandle.Revision != rev2 || item.ReferenceHandle.Handle != "#1.r2" || item.ReferenceHandle.Ref != ref || item.ReferenceHandle.Label != "Maria" {
		t.Fatalf("post-update disclosure: %+v", item)
	}
	// A registered endpoint without an allocated handle discloses nothing.
	ref2, e := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	d3 := fabric.EndpointDescriptor{Ref: ref2, Kind: "agent.local", Name: "No Handle", Description: "No allocation", Bindings: d.Bindings}
	if _, e = store.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d3}); e != nil {
		t.Fatal(e)
	}
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "describe-2", Principal: owner, Source: owner.Ref, CreatedAt: time.Now().UTC(), Operation: fabric.OperationDescribe, Context: fabric.EnvelopeContext{Origin: owner.Ref}}
	raw, err := json.Marshal(fabric.DescribeRequest{Selections: []fabric.DescribeSelection{{Ref: ref2, IncludeReferenceHandle: true}}})
	if err != nil {
		t.Fatal(err)
	}
	env.Payload = raw
	result, err := execute(t, service, env)
	if err != nil || result.Describe == nil {
		t.Fatal(result, err)
	}
	if item = result.Describe.Descriptions[0]; item.Endpoint == nil || item.ReferenceHandle != nil {
		t.Fatalf("fabricated or failed: %+v", item)
	}
}

// The read barrier: an extension cannot disclose a handle that was not
// explicitly requested, substitute its target, backdate its revision or fake
// its label.
func TestDescribeReferenceHandleDisclosureBarrier(t *testing.T) {
	_, envelope, _, store, _ := setup(t)
	ref := store.endpoint.Ref
	makeEnv := func(selections []fabric.DescribeSelection) fabric.Envelope {
		e := envelope
		e.Operation = fabric.OperationDescribe
		raw, err := json.Marshal(fabric.DescribeRequest{Selections: selections})
		if err != nil {
			t.Fatal(err)
		}
		e.Payload = raw
		return e
	}
	makeOutcome := func(descriptions []fabric.Description) extension.Outcome {
		raw, err := json.Marshal(fabric.DescribeResult{Descriptions: descriptions})
		if err != nil {
			t.Fatal(err)
		}
		return extension.Outcome{Response: raw}
	}
	handle := &fabric.ReferenceHandleView{Handle: "#1.r1", Label: "Maria", Ref: ref, Revision: store.endpoint.Revision}
	bad := func(name string, env fabric.Envelope, outcome extension.Outcome) {
		t.Helper()
		_, err := decodeReadOutcome(env, outcome)
		if err == nil {
			t.Fatalf("%s: tampered read accepted", name)
		}
		var f *fabric.Error
		if !errors.As(err, &f) || f.Code != fabric.CodeProtocolError {
			t.Fatalf("%s: %v", name, err)
		}
	}
	selection := fabric.DescribeSelection{Ref: ref, ExpectedRevision: store.endpoint.Revision}
	requested := selection
	requested.IncludeReferenceHandle = true
	description := fabric.Description{Ref: ref, Endpoint: &store.endpoint, ReferenceHandle: handle}
	// Disclosed without the explicit request.
	bad("unrequested", makeEnv([]fabric.DescribeSelection{selection}), makeOutcome([]fabric.Description{description}))
	// Not requested on a successful selection.
	if _, err := decodeReadOutcome(makeEnv([]fabric.DescribeSelection{selection}), makeOutcome([]fabric.Description{{Ref: ref, Endpoint: &store.endpoint}})); err != nil {
		t.Fatal(err)
	}
	// Requested and exact: accepted.
	if _, err := decodeReadOutcome(makeEnv([]fabric.DescribeSelection{requested}), makeOutcome([]fabric.Description{description})); err != nil {
		t.Fatal(err)
	}
	// Substituted target.
	foreign := *handle
	foreign.Ref = store.offer.Ref
	bad("foreign ref", makeEnv([]fabric.DescribeSelection{requested}), makeOutcome([]fabric.Description{{Ref: ref, Endpoint: &store.endpoint, ReferenceHandle: &foreign}}))
	// Backdated revision.
	backdated := *handle
	backdated.Revision = "forged"
	bad("backdated revision", makeEnv([]fabric.DescribeSelection{requested}), makeOutcome([]fabric.Description{{Ref: ref, Endpoint: &store.endpoint, ReferenceHandle: &backdated}}))
	// Non-canonical handle text.
	sloppy := *handle
	sloppy.Handle = "#01.r1"
	bad("sloppy text", makeEnv([]fabric.DescribeSelection{requested}), makeOutcome([]fabric.Description{{Ref: ref, Endpoint: &store.endpoint, ReferenceHandle: &sloppy}}))
	// Empty or oversized label.
	forgedLabel := *handle
	forgedLabel.Label = ""
	bad("empty label", makeEnv([]fabric.DescribeSelection{requested}), makeOutcome([]fabric.Description{{Ref: ref, Endpoint: &store.endpoint, ReferenceHandle: &forgedLabel}}))
	// An offer selection never carries a handle.
	offerSelection := fabric.DescribeSelection{Ref: store.offer.Ref, ExpectedRevision: store.offer.Revision}
	offerSelection.IncludeReferenceHandle = true
	bad("offer handle", makeEnv([]fabric.DescribeSelection{offerSelection}), makeOutcome([]fabric.Description{{Ref: store.offer.Ref, Offer: &store.offer, ReferenceHandle: handle}}))
	// An error selection never carries a handle.
	bad("error handle", makeEnv([]fabric.DescribeSelection{selection}), makeOutcome([]fabric.Description{{Ref: ref, Error: &fabric.Error{Code: fabric.CodeNotFound}, ReferenceHandle: handle}}))
}
