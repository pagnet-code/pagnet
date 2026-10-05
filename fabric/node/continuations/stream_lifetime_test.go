package continuations

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
)

func TestClaimBindingLivesThroughOuterCompletionAndRelease(t *testing.T) {
	for _, mode := range []string{"complete", "hook_reject", "persistence_failure"} {
		t.Run(mode, func(t *testing.T) {
			r := fixture(t)
			r.deferWork()
			var released, completions atomic.Int32
			authority := r.config.ResumeAuthority
			r.config.ResumeAuthority = func(ctx context.Context, resumer, caller fabric.ExecutionContext, claim *ResumeClaim, next func(context.Context, fabric.ExecutionContext) error) error {
				if err := claim.OnRelease(func() { released.Add(1) }); err != nil {
					return err
				}
				return authority(ctx, resumer, caller, claim, next)
			}
			if mode == "persistence_failure" {
				r.config.VerifyEvidence = func(context.Context, fabric.ExecutionContext, Evidence) (continuation.Outcome, error) {
					return continuation.Outcome{}, errors.New("trusted receipt verification unavailable")
				}
			}
			var err error
			r.recorder, err = New(r.config)
			if err != nil {
				t.Fatal(err)
			}
			claim := claimID("outer-lifetime")
			r.engine = r.makeEngine(r.manifests, handlerFunc(func(_ context.Context, request extension.InterceptRequest) (extension.Decision, error) {
				if released.Load() != 0 {
					t.Error("claim released before outer hook")
				}
				if request.Phase == extension.PhaseCompletion {
					completions.Add(1)
					receipt, found, e := r.store.ClaimReceipt(background, r.resumer, r.notifications[0].ID, claim)
					if e != nil || !found || receipt.State != continuation.Complete {
						t.Errorf("target evidence not durable before outer hook: %v %v %v", found, receipt.State, e)
					}
					if mode == "hook_reject" {
						return extension.Decision{}, errors.New("outer hook rejected output")
					}
				}
				return extension.Decision{Action: extension.Continue}, nil
			}))
			source := &frames{closed: make(chan struct{}), items: []fabric.InvocationFrame{{InvocationID: "invocation:one", Sequence: 0, Kind: fabric.FrameStart}, {InvocationID: "invocation:one", Sequence: 1, Kind: fabric.FrameComplete, Data: r.targetProof}}}
			result, e := r.recorder.Resume(background, r.resumer, r.notifications[0].Capability.Token(), claim, r.engine, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (extension.Outcome, error) {
				return extension.Outcome{Stream: source}, nil
			})
			if e != nil || result.Outcome.Stream == nil {
				t.Fatal(e)
			}
			if _, e = result.Outcome.Stream.Next(background); e != nil {
				t.Fatal(e)
			}
			_, e = result.Outcome.Stream.Next(background)
			if (mode == "complete") != (e == nil) {
				t.Fatalf("terminal mode %s: %v", mode, e)
			}
			if released.Load() != 1 {
				t.Fatal("claim not released after outer terminal", released.Load())
			}
			if mode != "persistence_failure" && completions.Load() != 1 {
				t.Fatal("outer completion not called", completions.Load())
			}
			_ = result.Outcome.Stream.Close()
			if released.Load() != 1 {
				t.Fatal("claim released twice")
			}
		})
	}
}
