package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

type contextFailureFence struct{ err error }

func (f contextFailureFence) WithAdmission(context.Context, AdmissionFacts, func(Witness) error) error {
	return f.err
}
func TestAdmissionFencePreservesContextFailureAndNeverCommits(t *testing.T) {
	f := fixture(t)
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	caller, original, final := f.invocation(t)
	for _, v := range []struct {
		err  error
		code fabric.ErrorCode
	}{{context.DeadlineExceeded, fabric.CodeDeadlineExceeded}, {context.Canceled, fabric.CodeCancelled}} {
		a, e := New(f.store, contextFailureFence{v.err})
		if e != nil {
			t.Fatal(e)
		}
		issued, e := a.Admit(t.Context(), f.owner, c, b, caller, original, final, "context-failed", "attempt", "replay")
		var typed *fabric.Error
		if !errors.As(e, &typed) || typed.Code != v.code || issued.Proof.Revision != 0 {
			t.Fatal("wrong failure/committed admission", e, issued.Proof)
		}
	}
	// Failure cannot leave a phantom reservation or authorize a paid retry.
	if _, e := f.a.Admit(t.Context(), f.owner, c, b, caller, original, final, "context-failed", "attempt", "replay"); e != nil {
		t.Fatal("context failure mutated original ledger", e)
	}
}
