//go:build linux || darwin

package fabricauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestCurrentLocalAssociationActualPeerCloseForeignAndRecursiveCalls(t *testing.T) {
	a, _, path := ownerFixture(t)
	conn, _ := ownerSocket(t, path)
	session, err := a.BindOwner(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	original, proof, err := session.Build(context.Background(), discoverCall())
	if err != nil {
		t.Fatal(err)
	}
	caller := authenticate(t, a, original, proof)
	if !a.AssociationOpen(caller) {
		t.Fatal("actual association not open")
	}
	if err = a.WithCurrentFacts(context.Background(), caller, func(ctx context.Context, f CurrentCallerFacts) error {
		if f.Principal != caller.PrincipalView() || f.Process.PID == 0 || f.Managed != nil {
			t.Fatal("owner current facts fabricated")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = a.WithCurrentCaller(context.Background(), caller, original, func(ctx context.Context) error {
		calls++
		return a.WithCurrentContext(ctx, caller, func(context.Context) error { calls++; return nil })
	})
	if err != nil || calls != 2 {
		t.Fatal("genuine recursively composed current association failed", err)
	}
	if _, err = json.Marshal(caller.AuthenticationEvidence()); err == nil {
		t.Fatal("private association serialized")
	}
	setup, _ := fabric.NewAuthenticatedContext(caller.PrincipalView(), caller.Audience(), original)
	for _, wrong := range []fabric.ExecutionContext{setup, {}} {
		if a.WithCurrentContext(context.Background(), wrong, func(context.Context) error { t.Fatal("unauthenticated callback"); return nil }) == nil {
			t.Fatal("static/empty context gained local authority")
		}
	}
	other := *a
	if other.WithCurrentContext(context.Background(), caller, func(context.Context) error { t.Fatal("foreign authority callback"); return nil }) == nil {
		t.Fatal("association transferred across actual authority")
	}
	if a.WithCurrentCaller(context.Background(), caller, append(original, ' '), func(context.Context) error { t.Fatal("changed original callback"); return nil }) == nil {
		t.Fatal("changed raw caller bytes accepted")
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	if a.AssociationOpen(caller) {
		t.Fatal("closed association remains open")
	}
	if a.WithCurrentContext(context.Background(), caller, func(context.Context) error { t.Fatal("closed actual session callback"); return nil }) == nil {
		t.Fatal("session close did not revoke current evidence")
	}
}
