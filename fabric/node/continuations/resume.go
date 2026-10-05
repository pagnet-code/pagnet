package continuations

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
)

type ResumeResult struct {
	Claim   continuation.ClaimResult
	Outcome extension.Outcome
}

// Resume makes at most one engine entry for a fresh durable claim. A claimed
// recovery or exact retry returns evidence only and never restores or executes.
func (r *Recorder) Resume(ctx context.Context, resumer fabric.ExecutionContext, token, claimID string, engine *extension.Engine, downstream extension.Downstream) (ResumeResult, error) {
	if ctx == nil || engine == nil || downstream == nil {
		return ResumeResult{}, invalid("Missing resume composition")
	}
	claim, e := r.config.Store.Claim(ctx, resumer, token, claimID)
	if e != nil {
		return ResumeResult{}, e
	}
	result := ResumeResult{Claim: claim}
	if !claim.Fresh {
		return result, nil
	}
	settlement := &settler{recorder: r, resumer: resumer, claim: claim.Receipt, lifetime: ctx}
	snapshot, e := claim.Claim.Consume(ctx, r.config.Store, resumer, claim.Receipt)
	if e != nil {
		return result, settlement.fail(e, Evidence{Kind: NoTarget})
	}
	current, e := configuredPlan(ctx, r.config.ConfiguredPlan, r.config.SnapshotLimits)
	if e != nil || current.Plan.Revision() != r.planRevision || string(current.Evidence) != string(r.pipeline) {
		return result, settlement.fail(stale(), Evidence{Kind: NoTarget})
	}
	var stored persistedState
	limits := r.config.SnapshotLimits
	if snapshot.PlanVersion != "pagnet.extension-plan.v1" || string(snapshot.PlanRevision) != r.planRevision || snapshot.PlanDigest != hash(r.pipeline) || string(snapshot.Pipeline) != string(r.pipeline) || fabric.DecodeJSONWithLimits(snapshot.State, &stored, limits) != nil || stored.Format != "pagnet.node-continuation.v1" || stored.State.DeferralID != claim.Receipt.ID || stored.State.PlanRevision != r.planRevision {
		return result, settlement.fail(stale(), Evidence{Kind: NoTarget})
	}
	admission := HistoricalAdmission{SnapshotDigest: claim.Receipt.SnapshotDigest, Principal: snapshot.OriginalPrincipal, Audience: r.config.Audience, OriginalBytes: append([]byte(nil), snapshot.OriginalEnvelope...), Provenance: stored.Provenance, Claim: claim.Receipt}
	admission.SnapshotCommitment, e = SnapshotCommitment(snapshot)
	if e != nil {
		return result, settlement.fail(e, Evidence{Kind: NoTarget})
	}
	admission.DeferredProof = append([]byte(nil), snapshot.DeferredAdmission...)
	admission.PlanRevision = snapshot.PlanRevision
	caller, e := r.config.RestoreOriginal(ctx, admission)
	if e != nil {
		return result, settlement.fail(fabric.NewError(fabric.CodeUnauthenticated, "Historical original admission restoration failed"), Evidence{Kind: NoTarget})
	}
	if caller.PrincipalView() != snapshot.OriginalPrincipal || caller.VerifyAuthenticated(r.config.Audience) != nil {
		return result, settlement.fail(fabric.NewError(fabric.CodeUnauthenticated, "Historical original admission mismatch"), Evidence{Kind: NoTarget})
	}
	if _, e = caller.DecodeVerifiedEnvelope(snapshot.OriginalEnvelope, r.config.Audience); e != nil {
		return result, settlement.fail(e, Evidence{Kind: NoTarget})
	}
	settlement.caller = caller
	settlement.invocationID = stored.State.Envelope.ID
	permit, e := extension.NewVerifiedResumePermit(caller, snapshot.OriginalEnvelope, stored.State)
	if e != nil {
		return result, settlement.fail(e, Evidence{Kind: NoTarget})
	}
	invoked := false
	wrapped := func(callCtx context.Context, c fabric.ExecutionContext, envelope fabric.Envelope) (extension.Outcome, error) {
		invoked = true
		target, e := downstream(callCtx, c, envelope)
		if target.Stream != nil {
			checked, checkErr := fabric.NewCheckedStream(callCtx, envelope.ID, target.Stream)
			if checkErr != nil {
				target.Stream.Close()
				return extension.Outcome{}, checkErr
			}
			target.Stream = &targetStream{InvocationStream: checked, settlement: settlement}
			return target, e
		}
		kind := TargetUnary
		if e != nil {
			kind = TargetFailure
		}
		if settleErr := settlement.record(Evidence{Kind: kind, InvocationID: envelope.ID, Response: append([]byte(nil), target.Response...), Failure: e}); settleErr != nil {
			return extension.Outcome{}, settleErr
		}
		return target, e
	}
	var outcome extension.Outcome
	resumeClaim := &ResumeClaim{snapshot: snapshot, receipt: claim.Receipt}
	settlement.release = resumeClaim.Release
	e = runResumeAuthority(r.config.ResumeAuthority, ctx, resumer, caller, resumeClaim, func(authorized context.Context, original fabric.ExecutionContext) error {
		if original.PrincipalView() != caller.PrincipalView() || original.VerifyAuthenticatedData(snapshot.OriginalEnvelope, r.config.Audience) != nil {
			return stale()
		}
		var engineErr error
		outcome, engineErr = engine.ResumeStage(authorized, permit, original, snapshot.OriginalEnvelope, stored.State, wrapped)
		return engineErr
	})
	result.Outcome = outcome
	if outcome.Stream != nil && e == nil {
		result.Outcome.Stream = &resultStream{InvocationStream: outcome.Stream, settlement: settlement}
		return result, nil
	}
	if !settlement.done() {
		kind := Abandoned
		if !invoked {
			kind = NoTarget
		}
		if settleErr := settlement.record(Evidence{Kind: kind, InvocationID: settlement.invocationID, Response: append([]byte(nil), outcome.Response...), Failure: e}); settleErr != nil {
			return result, settleErr
		}
	}
	return result, e
}

type settler struct {
	mu           sync.Mutex
	recorder     *Recorder
	resumer      fabric.ExecutionContext
	caller       fabric.ExecutionContext
	claim        continuation.Receipt
	lifetime     context.Context
	invocationID string
	settled      bool
	release      func()
}

func (s *settler) done() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.settled }
func (s *settler) record(evidence Evidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled {
		return nil
	}
	if s.release != nil {
		defer s.release()
	}
	// Persistence is independently bounded even when the consumer's context has
	// cancelled. Failure leaves the claim uncertain; it never grants another resume.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(s.lifetime), s.recorder.config.SettlementTimeout)
	defer cancel()
	outcome, e := s.recorder.config.VerifyEvidence(ctx, s.caller, evidence)
	if e != nil {
		return fabric.NewError(fabric.CodeProtocolError, "Continuation effect evidence rejected")
	}
	if _, e = s.recorder.config.Store.Complete(ctx, s.resumer, s.claim, outcome); e != nil {
		return e
	}
	s.settled = true
	return nil
}
func (s *settler) fail(cause error, evidence Evidence) error {
	if e := s.record(evidence); e != nil {
		return e
	}
	return cause
}

// This type is deliberately not a serialized authenticated context or permit.
func (Result ResumeResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Receipt           continuation.Receipt  `json:"receipt"`
		State             continuation.State    `json:"state"`
		Fresh             bool                  `json:"fresh"`
		Outcome           *continuation.Outcome `json:"outcome,omitempty"`
		DeferredID        string                `json:"deferredId,omitempty"`
		NotificationError *fabric.Error         `json:"deferredNotificationError,omitempty"`
	}{Result.Claim.Receipt, Result.Claim.State, Result.Claim.Fresh, Result.Claim.Outcome, Result.Outcome.DeferredID, Result.Outcome.DeferredNotificationError})
}
