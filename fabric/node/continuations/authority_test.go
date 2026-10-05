package continuations

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
)

func TestMandatoryConfiguredAdmissionAndResumeAuthorityDenyMissingComposition(t *testing.T) {
	r := fixture(t)
	for _, missing := range []func(*Config){func(c *Config) { c.ConfiguredPlan = nil }, func(c *Config) { c.SaveDeferredAdmission = nil }, func(c *Config) { c.ResumeAuthority = nil }} {
		config := r.config
		missing(&config)
		if _, err := New(config); err == nil {
			t.Fatal("incomplete original/current authority composition accepted")
		}
	}
}

func TestResumeAuthorityCannotSwallowErrorsRepeatOrEscapeCallback(t *testing.T) {
	var effect atomic.Int32
	want := errors.New("actual downstream denied")
	for _, authority := range []ResumeAuthority{
		func(ctx context.Context, r, o fabric.ExecutionContext, p *ResumeClaim, next func(context.Context, fabric.ExecutionContext) error) error {
			_ = next(ctx, o)
			return nil
		},
		func(ctx context.Context, r, o fabric.ExecutionContext, p *ResumeClaim, next func(context.Context, fabric.ExecutionContext) error) error {
			_ = next(ctx, o)
			_ = next(ctx, o)
			return nil
		},
	} {
		effect.Store(0)
		err := runResumeAuthority(authority, t.Context(), fabric.ExecutionContext{}, fabric.ExecutionContext{}, nil, func(context.Context, fabric.ExecutionContext) error { effect.Add(1); return want })
		if !errors.Is(err, want) || effect.Load() != 1 {
			t.Fatal("swallowed original/repeated callback", effect.Load(), err)
		}
	}
	var escaped func(context.Context, fabric.ExecutionContext) error
	err := runResumeAuthority(func(_ context.Context, _, _ fabric.ExecutionContext, _ *ResumeClaim, next func(context.Context, fabric.ExecutionContext) error) error {
		escaped = next
		return nil
	}, t.Context(), fabric.ExecutionContext{}, fabric.ExecutionContext{}, nil, func(context.Context, fabric.ExecutionContext) error { effect.Add(1); return nil })
	if err == nil {
		t.Fatal("authority omitted authorization")
	}
	effect.Store(0)
	if escaped(t.Context(), fabric.ExecutionContext{}) == nil || effect.Load() != 0 {
		t.Fatal("escaped callback executed")
	}
}

func TestPrivateResumeBindingReleaseAfterSettlementFailureAndRetryNoReactivation(t *testing.T) {
	r := fixture(t)
	var released atomic.Int32
	r.config.ResumeAuthority = func(ctx context.Context, resumer, original fabric.ExecutionContext, claim *ResumeClaim, next func(context.Context, fabric.ExecutionContext) error) error {
		if _, _, err := claim.Consume(resumer); err != nil {
			return err
		}
		if err := claim.OnRelease(func() { released.Add(1) }); err != nil {
			return err
		}
		return next(ctx, original)
	}
	var err error
	r.recorder, err = New(r.config)
	if err != nil {
		t.Fatal(err)
	}
	r.engine = r.makeEngine(r.manifests, nil)
	r.deferWork()
	r.config.VerifyEvidence = func(context.Context, fabric.ExecutionContext, Evidence) (out continuation.Outcome, err error) {
		return out, errors.New("actual evidence unavailable")
	}
	r.recorder.config.VerifyEvidence = r.config.VerifyEvidence
	result, err := r.recorder.Resume(background, r.resumer, r.notifications[0].Capability.Token(), claimID("release-failure"), r.engine, r.downstream())
	if err == nil || released.Load() != 1 || result.Claim.Receipt.ID == "" {
		t.Fatal("settlement failure retained executable capability", err, released.Load())
	}
	before := r.targets.Load()
	retry, err := r.recorder.Resume(background, r.resumer, r.notifications[0].Capability.Token(), claimID("release-failure"), r.engine, r.downstream())
	if err != nil || retry.Claim.Fresh || r.targets.Load() != before || released.Load() != 1 {
		t.Fatal("retry reactivated", err)
	}
}
