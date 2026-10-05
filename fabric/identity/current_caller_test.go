package identity

import (
	"context"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"testing"
)

type currentCallerFence struct {
	facts   registry.NativeCallerAuthority
	before  func()
	missing bool
	closed  bool
}

func (f currentCallerFence) WithAdmission(_ context.Context, a AdmissionFacts, next func(Witness) error) error {
	if f.before != nil {
		f.before()
	}
	w := Witness{Version: "current.fixture.v1", FinalizedDigest: a.FinalizedDigest, Value: json.RawMessage(`{}`), CurrentCallerKind: "local-peer.managed", CurrentCallerOpen: func() bool { return !f.closed }}
	if !f.missing {
		facts := f.facts
		w.CurrentCallerAuthority = &facts
	}
	return next(w)
}
func TestCurrentManagedCallerRetiredBetweenPreflightAndAdmissionCannotSign(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	caller, original, final := f.invocation(t)
	admitted, err := f.a.Admit(ctx, f.owner, c, b, caller, original, final, "original-source", "attempt", "replay")
	if err != nil {
		t.Fatal(err)
	}
	origin, err := f.a.RegisterOrigin(ctx, f.owner, c, b, admitted, caller, original, final, "original-origin", "original-generation")
	if err != nil {
		t.Fatal(err)
	}
	principal := fabric.Principal{Ref: f.scope.Endpoint.String(), Kind: "agent.local", Issuer: f.store.Namespace()}
	var env fabric.Envelope
	if err = json.Unmarshal(final, &env); err != nil {
		t.Fatal(err)
	}
	env.Principal = principal
	env.Source = principal.Ref
	env.Context.Origin = principal.Ref
	env.ID = "managed-invocation"
	raw, _ := json.Marshal(env)
	managed, _ := fabric.NewAuthenticatedContext(principal, f.store.Namespace(), raw)
	facts := registry.NativeCallerAuthority{Principal: principal, Endpoint: f.scope.Endpoint, DescriptorRevision: f.scope.DescriptorRevision, BindingID: f.scope.BindingID, NativeGeneration: origin.NativeGeneration, Controller: c.Proof, Binding: b.Proof, Origin: origin.Proof}
	for _, mode := range []string{"valid", "missing", "closed", "retired"} {
		fence := currentCallerFence{facts: facts, missing: mode == "missing", closed: mode == "closed"}
		if mode == "retired" {
			fence.before = func() {
				if _, e := f.a.RetireOrigin(ctx, f.owner, origin, "retired after preflight"); e != nil {
					t.Fatal(e)
				}
			}
		}
		authority, e := New(f.store, fence)
		if e != nil {
			t.Fatal(e)
		}
		got, e := authority.Admit(ctx, f.owner, c, b, managed, raw, raw, "destination-"+mode, "attempt", "replay")
		if mode == "valid" {
			if e != nil {
				t.Fatal("valid current managed caller denied", e)
			}
			encoded, _ := json.Marshal(got)
			var persisted Admission
			if json.Unmarshal(encoded, &persisted) != nil || persisted.Witness.CurrentCallerAuthority != nil || persisted.Witness.CurrentCallerKind != "" {
				t.Fatal("private current caller authority serialized")
			}
		}
		if mode != "valid" {
			if e == nil || got.ID != "" {
				t.Fatal("missing/retired source signed new admission", mode, e)
			}
			err = f.a.transact(ctx, f.owner, f.scope, true, func(tx *registry.AuthorityTx) error {
				_, e := tx.Get(admissionKey(f.scope, "destination-"+mode))
				return e
			})
			if err == nil {
				t.Fatal("rejected admission persisted")
			}
		}
	}
}
func TestCurrentCallerWitnessDetachedRecords(t *testing.T) {
	original := Witness{CurrentCallerKind: "local-peer.managed", CurrentCallerOpen: func() bool { return true }, CurrentCallerAuthority: &registry.NativeCallerAuthority{Controller: registry.AuthorityRecord{Value: []byte("value"), Signature: []byte("proof")}}, Value: json.RawMessage(`{}`)}
	copy := cloneWitness(original)
	original.CurrentCallerAuthority.Controller.Value[0] = 'X'
	original.CurrentCallerAuthority.Controller.Signature[0] = 'X'
	original.Value[0] = 'X'
	if string(copy.CurrentCallerAuthority.Controller.Value) != "value" || string(copy.CurrentCallerAuthority.Controller.Signature) != "proof" || string(copy.Value) != "{}" {
		t.Fatal("fence caller storage aliases commit witness")
	}
}

type currentSourceFence struct {
	currentCallerFence
	during func()
}

func (f *currentSourceFence) CurrentNativeCallerWitness(context.Context, fabric.ExecutionContext) (Witness, error) {
	facts := f.facts
	return Witness{CurrentCallerKind: "local-peer.managed", CurrentCallerAuthority: &facts, CurrentCallerOpen: func() bool { return !f.closed }}, nil
}
func (f *currentSourceFence) WithNativeSourceRead(_ context.Context, _ NativeSourceReadFacts, next func() error) error {
	if f.during != nil {
		f.during()
	}
	return next()
}
func (f *currentSourceFence) WithNativeCancellation(_ context.Context, _ NativeCancellationFacts, next func() error) error {
	if f.during != nil {
		f.during()
	}
	return next()
}
func TestCurrentRequestingManagedOriginRetiredBeforeHistoryOrStopTransaction(t *testing.T) {
	for _, action := range []string{"page", "cancel"} {
		t.Run(action, func(t *testing.T) {
			f := fixture(t)
			ctx := context.Background()
			c := f.controller(t, 0, "A")
			b := f.binding(t, c)
			ownerCaller, one, two := f.invocation(t)
			first, e := f.a.Admit(ctx, f.owner, c, b, ownerCaller, one, two, "activation", "attempt", "replay")
			if e != nil {
				t.Fatal(e)
			}
			origin, e := f.a.RegisterOrigin(ctx, f.owner, c, b, first, ownerCaller, one, two, "requesting-origin", "native-generation")
			if e != nil {
				t.Fatal(e)
			}
			principal := fabric.Principal{Ref: f.scope.Endpoint.String(), Kind: "agent.local", Issuer: f.store.Namespace()}
			var env fabric.Envelope
			_ = json.Unmarshal(one, &env)
			env.ID = "managed-source"
			env.Principal = principal
			env.Source = principal.Ref
			env.Context.Origin = principal.Ref
			raw, _ := json.Marshal(env)
			caller, _ := fabric.NewAuthenticatedContext(principal, f.store.Namespace(), raw)
			policy := &currentSourceFence{currentCallerFence: currentCallerFence{facts: registry.NativeCallerAuthority{Principal: principal, Endpoint: f.scope.Endpoint, DescriptorRevision: f.scope.DescriptorRevision, BindingID: f.scope.BindingID, NativeGeneration: origin.NativeGeneration, Controller: c.Proof, Binding: b.Proof, Origin: origin.Proof}}}
			authority, e := New(f.store, policy)
			if e != nil {
				t.Fatal(e)
			}
			source, e := authority.Admit(ctx, f.owner, c, b, caller, raw, raw, "managed-admission", "attempt", "replay")
			if e != nil {
				t.Fatal(e)
			}
			reservation, e := authority.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, raw, raw, dispatchSpec(b))
			if e != nil {
				t.Fatal(e)
			}
			calls := 0
			invoke := func() error {
				if action == "page" {
					return authority.FenceNativeSourceRead(ctx, f.owner, caller, c, b, b, source, reservation, NativeSourcePage, func(context.Context) error { calls++; return nil })
				}
				return authority.FenceNativeCancellation(ctx, f.owner, caller, c, b, b, source, reservation, func(context.Context) error { calls++; return nil })
			}
			if e = invoke(); e != nil || calls != 1 {
				t.Fatal("valid current managed history authority denied", e, calls)
			}
			policy.during = func() {
				if _, e = f.a.RetireOrigin(ctx, f.owner, origin, "retired between actual preflight and history transaction"); e != nil {
					t.Fatal(e)
				}
			}
			if e = invoke(); e == nil || calls != 1 {
				t.Fatal("retired requesting source reached IPC", action, e, calls)
			}
		})
	}
}
