package identity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

type swallowedAdmissionFence struct{ invalidWitness bool }

func (f swallowedAdmissionFence) WithAdmission(_ context.Context, facts AdmissionFacts, next func(Witness) error) error {
	w := Witness{Version: "test.admission.v1", FinalizedDigest: facts.FinalizedDigest, Value: json.RawMessage(`{}`)}
	if f.invalidWitness {
		w.FinalizedDigest = [32]byte{}
	}
	_ = next(w)
	return nil
}
func TestAdmissionCannotSwallowCommitOrWitnessFailure(t *testing.T) {
	for _, invalidWitness := range []bool{false, true} {
		f := fixture(t)
		f.a.fence = swallowedAdmissionFence{invalidWitness}
		calls := 0
		err := f.a.withFence(t.Context(), AdmissionFacts{FinalizedDigest: sha256.Sum256([]byte("actual finalized request"))}, func(Witness) error {
			calls++
			return fabric.NewError(fabric.CodeTargetUnavailable, "Actual durable commit failed")
		})
		if err == nil || invalidWitness && calls != 0 || !invalidWitness && calls != 1 {
			t.Fatal("admission swallowed failed commit or invalid witness", err, calls)
		}
	}
}

type swallowedAcknowledgementFence struct {
	*ownerFence
	repeat bool
}

func (f swallowedAcknowledgementFence) WithNativeControl(_ context.Context, _ NativeControlFacts, next func() error) error {
	_ = next()
	if f.repeat {
		_ = next()
	}
	return nil
}
func (f swallowedAcknowledgementFence) WithNativeCancellation(_ context.Context, _ NativeCancellationFacts, next func() error) error {
	_ = next()
	if f.repeat {
		_ = next()
	}
	return nil
}

func TestCurrentNativeFencesCannotSwallowFailedOrRepeatedAcknowledgements(t *testing.T) {
	for _, mode := range []string{"failed", "repeated"} {
		for _, operation := range []string{"control", "cancel", "origin"} {
			t.Run(mode+"/"+operation, func(t *testing.T) {
				f := fixture(t)
				ctx := t.Context()
				A := f.controller(t, 0, "A")
				binding := f.binding(t, A)
				source, caller, original, final := dispatchAdmission(t, f, A, binding, "genuine-ack-source")
				reservation, e := f.a.ReserveNativeDispatch(ctx, f.owner, A, binding, source, caller, original, final, dispatchSpec(binding))
				if e != nil {
					t.Fatal(e)
				}
				origin, e := f.a.RegisterOrigin(ctx, f.owner, A, binding, source, caller, original, final, "genuine-ack-origin", "native-generation")
				if e != nil {
					t.Fatal(e)
				}
				f.a.fence = swallowedAcknowledgementFence{f.fence, mode == "repeated"}
				calls := 0
				ack := func(context.Context) error {
					calls++
					if mode == "failed" {
						return fabric.NewError(fabric.CodeTargetUnavailable, "Actual private ACK failed")
					}
					return nil
				}
				switch operation {
				case "control":
					e = f.a.FenceNativeControl(ctx, f.owner, A, binding, ack)
				case "cancel":
					e = f.a.FenceNativeCancellation(ctx, f.owner, caller, A, binding, binding, source, reservation, ack)
				case "origin":
					e = f.a.FenceCurrentNativeOrigin(ctx, f.owner, binding.Scope, origin, ack)
				}
				if e == nil || calls != 1 {
					t.Fatal("Fence reported success or repeated actual effect", calls, e)
				}
			})
		}
	}
}
