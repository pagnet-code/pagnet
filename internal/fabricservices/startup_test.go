package fabricservices

import (
	"context"
	"fmt"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func TestStartupExplicitAtomicPagedChoicesCapacityAndReopen(t *testing.T) {
	p, _, owner, directory := serviceFixture(t)
	i, s, e := BootstrapServiceState(t.Context(), p, DefaultInvocationConfig(), servicePolicyFixture{p.root.Owner}, 40)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = BootstrapServiceState(t.Context(), p, DefaultInvocationConfig(), servicePolicyFixture{p.root.Owner}, 40); e == nil {
		t.Fatal("bootstrap reset retained state")
	}
	if _, e = OpenStartup(t.Context(), i, 39); e == nil {
		t.Fatal("changed manifest capacity accepted")
	}
	for n := 0; n < 41; n++ {
		ref, _ := fabric.NewEndpointRef(p.root.PublicKey)
		revision, e := p.store.Register(t.Context(), owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "tool.mcp", Name: fmt.Sprintf("Choice %d", n), Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "2026-07-28", Cancellation: true}}}})
		if e != nil {
			t.Fatal(e)
		}
		selected := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "mcp"}
		if _, e = p.Install(t.Context(), selected, serviceProfile()); e != nil {
			t.Fatal(e)
		}
		_, e = s.Select(t.Context(), selected)
		if n == 40 {
			if e == nil {
				t.Fatal("manifest exceeded selected connection capacity")
			}
		} else if e != nil {
			t.Fatal(e)
		}
	}
	choices, e := s.Selections(t.Context())
	if e != nil || len(choices) != 40 {
		t.Fatal("paged immutable choices", len(choices), e)
	}
	for n := 1; n < len(choices); n++ {
		if connectionKey(choices[n-1].Scope) >= connectionKey(choices[n].Scope) {
			t.Fatal("unstable startup order")
		}
	}
	first := choices[0]
	if selected, e := s.Select(t.Context(), first.Scope); e != nil || selected != first {
		t.Fatal("exact selection retry", e)
	}
	if e = p.store.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := registry.Open(t.Context(), directory)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { reopened.Close() })
	profiles, e := NewProfileStore(t.Context(), reopened, func(context.Context) (fabric.ExecutionContext, error) { return owner, nil }, p.protector)
	if e != nil {
		t.Fatal(e)
	}
	i, e = OpenInvocations(t.Context(), profiles, DefaultInvocationConfig(), servicePolicyFixture{p.root.Owner})
	if e != nil {
		t.Fatal(e)
	}
	opened, e := OpenStartup(t.Context(), i, 40)
	if e != nil {
		t.Fatal(e)
	}
	s = opened
	got, e := opened.Selections(t.Context())
	if e != nil || len(got) != 40 {
		t.Fatal("retained startup did not reopen", e)
	}
	if e = s.Remove(t.Context(), first.Scope); e != nil {
		t.Fatal(e)
	}
	got, e = s.Selections(t.Context())
	if e != nil || len(got) != 39 || got[0] == first {
		t.Fatal("explicit removal", e)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e = s.Select(cancelled, first.Scope); e == nil {
		t.Fatal("cancelled selection committed")
	}
	got, e = s.Selections(t.Context())
	if e != nil || len(got) != 39 {
		t.Fatal("cancelled choice mutated manifest", e)
	}
}
func TestStartupMissingAndSignedMalformedPageNeverInitializes(t *testing.T) {
	p, scope, _, _ := serviceFixture(t)
	i := invocationFixture(t, p)
	if _, e := OpenStartup(t.Context(), i, 2); !missing(e) {
		t.Fatal("missing startup manifest invented", e)
	}
	s, e := BootstrapStartup(t.Context(), i, 2)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Install(t.Context(), scope, serviceProfile()); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Select(t.Context(), scope); e != nil {
		t.Fatal(e)
	}
	e = i.with(t.Context(), registry.DescriptorBatchScope{}, func(_ context.Context, tx *registry.AuthorityTx) error {
		row, e := tx.Get(serviceKey(startupID(0)))
		if e != nil {
			return e
		}
		v, e := i.encode(startupID(0), startupPage{Generation: 9, Selections: nil})
		if e != nil {
			return e
		}
		_, e = tx.CAS(serviceKey(startupID(0)), row.Revision, v, false)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Selections(t.Context()); e == nil {
		t.Fatal("signed but inconsistent page accepted")
	}
	if _, e = OpenStartup(t.Context(), i, 2); e == nil {
		t.Fatal("corrupt startup header silently reopened")
	}
}
