package extension

import (
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func manifestWith(ids ...string) ExtensionManifest {
	m := ExtensionManifest{ManifestVersion: "1.0", ID: "acme.security", Version: "1.0.0", MinProtocol: "1.0", MaxProtocol: "1.9"}
	for _, id := range ids {
		m.Interceptors = append(m.Interceptors, Registration{ID: "acme.security." + id, Match: Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Placement: PlacementSource, Phases: []Phase{PhaseRequest, PhaseResponse, PhaseError}, TimeoutMillis: 1000, Binding: "private.binding"})
	}
	return m
}
func selectedIDs(plan *Plan, ctx MatchContext) []string {
	var ids []string
	for _, r := range plan.Select(ctx) {
		ids = append(ids, r.Registration.ID)
	}
	return ids
}
func dispatchContext() MatchContext {
	return MatchContext{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch", Placement: PlacementSource}
}

func TestCompiledOrderDependenciesAndPriority(t *testing.T) {
	m := manifestWith("c", "a", "b", "d")
	m.Interceptors[0].Before = []string{"acme.security.a"}
	m.Interceptors[1].Priority = -10
	m.Interceptors[2].Priority = -2
	m.Interceptors[3].Priority = -2
	plan, err := Compile([]ExtensionManifest{m}, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"acme.security.b", "acme.security.d", "acme.security.c", "acme.security.a"}
	if got := selectedIDs(plan, dispatchContext()); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	// Configuration mutation never changes an already installed chain.
	m.Interceptors[0].Before[0] = "invalid"
	m.Interceptors[0].Match.Stage = "invalid"
	selected := plan.Select(dispatchContext())
	selected[0].Registration.Phases[0] = PhaseChunk
	selected[0].Registration.Match.Stage = "invalid"
	if got := selectedIDs(plan, dispatchContext()); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	for i := 0; i < 50; i++ {
		again, e := Compile([]ExtensionManifest{manifestWith("z", "b", "a")}, 100)
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(selectedIDs(again, dispatchContext()), []string{"acme.security.a", "acme.security.b", "acme.security.z"}) {
			t.Fatal("unstable map ordering")
		}
	}
}

func TestCompileRejectsCyclesMissingDependenciesAndExposure(t *testing.T) {
	cases := map[string]func(*ExtensionManifest){
		"cycle": func(m *ExtensionManifest) {
			m.Interceptors[0].After = []string{m.Interceptors[1].ID}
			m.Interceptors[1].After = []string{m.Interceptors[0].ID}
		},
		"self":    func(m *ExtensionManifest) { m.Interceptors[0].Before = []string{m.Interceptors[0].ID} },
		"missing": func(m *ExtensionManifest) { m.Interceptors[0].Before = []string{"other.extension.missing"} },
		"relay plaintext": func(m *ExtensionManifest) {
			m.Interceptors[0].Placement = PlacementRelay
			m.Interceptors[0].NeedsPlaintext = true
		},
		"duplicate":    func(m *ExtensionManifest) { m.Interceptors[1].ID = m.Interceptors[0].ID },
		"foreign id":   func(m *ExtensionManifest) { m.Interceptors[0].ID = "other.extension.interceptor" },
		"timeout":      func(m *ExtensionManifest) { m.Interceptors[0].TimeoutMillis = 0 },
		"incompatible": func(m *ExtensionManifest) { m.MinProtocol = "1.1" },
		"bad failure":  func(m *ExtensionManifest) { m.Interceptors[0].FailureMode = "ignore-everything" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := manifestWith("a", "b")
			mutate(&m)
			_, err := Compile([]ExtensionManifest{m}, 100)
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if name == "cycle" || name == "self" {
				var e *fabric.Error
				if !errors.As(err, &e) || e.Code != fabric.CodeExtensionCycle {
					t.Fatal(err)
				}
			}
		})
	}
	if _, err := Compile([]ExtensionManifest{manifestWith("a", "b")}, 1); err == nil {
		t.Fatal("capacity ignored")
	}
}

func TestSelectIndexedStageAndRecursion(t *testing.T) {
	m := manifestWith("a", "b", "c")
	m.Interceptors[0].Match.TargetKinds = []string{"service.mcp"}
	m.Interceptors[0].Match.Tags = []string{"private"}
	m.Interceptors[1].Match.Stage = "invoke.endpoint"
	m.Interceptors[2].AllowSelfRecursion = true
	plan, err := Compile([]ExtensionManifest{m}, 100)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dispatchContext()
	ctx.TargetKind = "service.mcp"
	ctx.Tags = []string{"private"}
	if got := selectedIDs(plan, ctx); len(got) != 2 {
		t.Fatal(got)
	}
	ctx.ExecutingInterceptors = []string{"acme.security.a", "acme.security.c"}
	if got := selectedIDs(plan, ctx); !reflect.DeepEqual(got, []string{"acme.security.c"}) {
		t.Fatal(got)
	}
	ctx.Stage = "future.unknown"
	if got := selectedIDs(plan, ctx); len(got) != 0 {
		t.Fatal(got)
	}
	ctx.Stage = "invoke.dispatch"
	ctx.ExecutingInterceptors = nil
	ctx.Tags = nil
	if got := selectedIDs(plan, ctx); !reflect.DeepEqual(got, []string{"acme.security.c"}) {
		t.Fatal(got)
	}
}

func TestManifestCapacitySupportsFiveHundredAndNamespacesAreExclusive(t *testing.T) {
	m := manifestWith()
	for i := 0; i < 500; i++ {
		r := manifestWith("a").Interceptors[0]
		r.ID = "acme.security.i" + strconv.Itoa(i)
		m.Interceptors = append(m.Interceptors, r)
	}
	plan, err := Compile([]ExtensionManifest{m}, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Select(dispatchContext())) != 500 {
		t.Fatal("large installed chain lost registrations")
	}
	nested := manifestWith("other")
	nested.ID = "acme.security.nested"
	nested.Interceptors[0].ID = nested.ID + ".other"
	if _, err := Compile([]ExtensionManifest{m, nested}, 501); err == nil {
		t.Fatal("metadata namespace overlap accepted")
	}
}
