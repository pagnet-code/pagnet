package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/node/continuations"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

// LocalContinuationAuthority is explicitly installed trusted composition. It
// uses the actual retained root and one configured-plan publication; neither a
// serialized principal nor historical admission creates a current peer session.
type LocalContinuationAuthority struct {
	boundary   *LocalBoundary
	plans      continuations.ConfiguredPlanProvider
	verifyPlan func(*registry.AuthorityTx, string, []byte) error
}

type localResumeBinding struct {
	authority     *LocalContinuationAuthority
	resumer       fabric.ExecutionContext
	original      fabric.Principal
	originalBytes []byte
	snapshot      continuation.Snapshot
	proof         registry.AuthorityRecord
	commitment    [32]byte
	released      atomic.Bool
	dispatched    atomic.Bool
}

// VerifyResumeDispatch qualifies only the exact private once-claim binding.
// Node owns installing its finalized request capability after this check; no
// wire caller or generic historical constructor can enter that path.
func (a *LocalContinuationAuthority) VerifyResumeDispatch(ctx context.Context, caller fabric.ExecutionContext, original []byte, final fabric.Envelope) error {
	if a == nil || ctx == nil || ctx.Err() != nil || final.Validate() != nil || final.Operation != fabric.OperationInvoke || final.Target == nil || final.ExpectedRevision == "" || final.Target.Domain() != a.boundary.root.Namespace {
		return localDenied()
	}
	p, ok := a.boundary.resumeBinding(caller)
	if !ok || p.authority != a || !bytes.Equal(original, p.originalBytes) || final.Principal != p.original {
		return localDenied()
	}
	before, err := caller.DecodeVerifiedEnvelope(original, a.boundary.root.Namespace)
	if err != nil {
		return err
	}
	if final.ID != before.ID || final.Context.Deadline == nil && before.Context.Deadline != nil {
		return localDenied()
	}
	left, right := before, final
	left.Payload = nil
	right.Payload = nil
	left.Metadata = nil
	right.Metadata = nil
	left.Target = nil
	right.Target = nil
	left.ExpectedRevision = ""
	right.ExpectedRevision = ""
	lraw, _ := json.Marshal(left)
	rraw, _ := json.Marshal(right)
	if !bytes.Equal(lraw, rraw) {
		return localDenied()
	}
	if final.Context.Deadline != nil && !time.Now().Before(*final.Context.Deadline) {
		return fabric.NewError(fabric.CodeDeadlineExceeded, "Original resumed dispatch deadline expired")
	}
	if final.Target.IsOffer() {
		if _, err = a.boundary.store.GetOffer(ctx, *final.Target, final.ExpectedRevision); err != nil {
			return err
		}
	} else if _, err = a.boundary.store.GetEndpoint(ctx, *final.Target, final.ExpectedRevision); err != nil {
		return err
	}
	err = a.boundary.callerFacts(ctx, p.resumer, func(current context.Context, facts fabricauth.CurrentCallerFacts) error {
		b := a.boundary
		return b.store.WithNativeAuthority(current, b.owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 4096}, func(tx *registry.AuthorityTx) error {
			if err := p.verifyTx(tx); err != nil {
				return err
			}
			b.mu.RLock()
			sessions := b.sessions
			b.mu.RUnlock()
			if sessions == nil || !sessions.AssociationOpen(p.resumer) {
				return localDenied()
			}
			if facts.Managed != nil {
				return tx.VerifyCurrentNativeCaller(facts.Managed.Authority)
			}
			if facts.Principal != b.root.Owner {
				return localDenied()
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	if !p.dispatched.CompareAndSwap(false, true) {
		return localDenied()
	}
	return nil
}

func (a *LocalContinuationAuthority) WithResume(ctx context.Context, resumer, original fabric.ExecutionContext, claim *continuations.ResumeClaim, next func(context.Context, fabric.ExecutionContext) error) error {
	if a == nil || ctx == nil || next == nil {
		return localDenied()
	}
	snapshot, receipt, err := claim.Consume(resumer)
	if err != nil {
		return err
	}
	commitment, err := continuations.SnapshotCommitment(snapshot)
	if err != nil {
		return err
	}
	if receipt.ID != snapshot.DeferralID || original.PrincipalView() != snapshot.OriginalPrincipal || original.VerifyAuthenticatedData(snapshot.OriginalEnvelope, a.boundary.root.Namespace) != nil {
		return localDenied()
	}
	var proof registry.AuthorityRecord
	if fabric.DecodeJSON(snapshot.DeferredAdmission, &proof) != nil {
		return localDenied()
	}
	p := &localResumeBinding{authority: a, resumer: resumer, original: original.PrincipalView(), originalBytes: append([]byte(nil), snapshot.OriginalEnvelope...), snapshot: snapshot, proof: proof, commitment: commitment}
	a.boundary.mu.RLock()
	sessions := a.boundary.sessions
	a.boundary.mu.RUnlock()
	if sessions == nil {
		return localDenied()
	}
	release, err := sessions.RetainOwnerResumer(ctx, resumer)
	if err != nil {
		return err
	}
	if err = claim.OnRelease(func() { p.released.Store(true); release() }); err != nil {
		release()
		return err
	}
	return a.boundary.callerFacts(ctx, resumer, func(current context.Context, facts fabricauth.CurrentCallerFacts) error {
		b := a.boundary
		err := b.store.WithNativeAuthority(current, b.owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 4096}, func(tx *registry.AuthorityTx) error {
			if err := p.verifyTx(tx); err != nil {
				return err
			}
			b.mu.RLock()
			sessions := b.sessions
			b.mu.RUnlock()
			if sessions == nil || !sessions.AssociationOpen(resumer) {
				return localDenied()
			}
			if facts.Managed != nil {
				return tx.VerifyCurrentNativeCaller(facts.Managed.Authority)
			}
			if facts.Principal != b.root.Owner {
				return localDenied()
			}
			return nil
		})
		if err != nil {
			return err
		}
		bound, err := fabric.NewAuthenticatedForwardContextWithEvidence(p.original, b.root.Namespace, p.originalBytes, original.ProvenanceView(), p)
		if err != nil {
			return err
		}
		// Preserve the actual invocation lifetime, not the preflight timeout.
		if actors, ok := ctx.Value(extensionPhaseActorKey{}).(*extensionPhaseActors); ok && actors != nil && actors.runtime != nil && actors.runtime.authority == a {
			actors.current.Store(&extensionPhaseActor{bound, append([]byte(nil), p.originalBytes...)})
		}
		return next(ctx, bound)
	})
}

func (p *localResumeBinding) verifyTx(tx *registry.AuthorityTx) error {
	if p == nil || p.released.Load() {
		return localDenied()
	}
	facts, err := tx.VerifyDeferredAdmission(p.proof, p.originalBytes, p.commitment)
	if err != nil {
		return err
	}
	if facts.OriginalCaller != p.original || facts.DeferralID != p.snapshot.DeferralID || facts.PlanRevision != p.snapshot.PlanRevision {
		return localDenied()
	}
	allowed := false
	for _, principal := range p.snapshot.AllowedResumePrincipals {
		allowed = allowed || principal == p.resumer.PrincipalView()
	}
	if !allowed {
		return localDenied()
	}
	return p.authority.verifyPlan(tx, string(p.snapshot.PlanRevision), p.snapshot.Pipeline)
}

func (b *LocalBoundary) resumeBinding(caller fabric.ExecutionContext) (*localResumeBinding, bool) {
	p, ok := caller.AuthenticationEvidence().(*localResumeBinding)
	if !ok || p == nil || p.authority == nil || p.authority.boundary != b || p.released.Load() || caller.PrincipalView() != p.original || caller.VerifyAuthenticatedData(p.originalBytes, b.root.Namespace) != nil {
		return nil, false
	}
	return p, true
}

func (b *LocalBoundary) dispatchCallerFacts(ctx context.Context, caller fabric.ExecutionContext, next func(context.Context, fabricauth.CurrentCallerFacts) error) error {
	if p, ok := b.resumeBinding(caller); ok {
		return b.callerFacts(ctx, p.resumer, next)
	}
	return b.callerFacts(ctx, caller, next)
}

func (p *localResumeBinding) witness(facts fabricauth.CurrentCallerFacts) identity.Witness {
	b := p.authority.boundary
	b.mu.RLock()
	sessions := b.sessions
	b.mu.RUnlock()
	w := identity.Witness{CurrentCallerOpen: func() bool { return !p.released.Load() && sessions != nil && sessions.AssociationOpen(p.resumer) }, DeferredCaller: &identity.DeferredCallerWitness{Admission: p.proof, Original: p.originalBytes, SnapshotCommitment: p.commitment, Resumer: p.resumer.PrincipalView(), ClaimOpen: func() bool { return !p.released.Load() }, VerifyPlan: func(tx *registry.AuthorityTx) error { return p.verifyTx(tx) }}}
	if facts.Managed != nil {
		authority := facts.Managed.Authority
		w.CurrentCallerKind = "local-resume.managed"
		w.CurrentCallerAuthority = &authority
	} else {
		w.CurrentCallerKind = "local-resume.owner"
	}
	return w
}

func NewLocalContinuationAuthority(b *LocalBoundary, plans continuations.ConfiguredPlanProvider, verify func(*registry.AuthorityTx, string, []byte) error) (*LocalContinuationAuthority, error) {
	if b == nil || plans == nil || verify == nil {
		return nil, localDenied()
	}
	return &LocalContinuationAuthority{boundary: b, plans: plans, verifyPlan: verify}, nil
}

func (a *LocalContinuationAuthority) SaveDeferredAdmission(ctx context.Context, caller fabric.ExecutionContext, snapshot continuation.Snapshot) ([]byte, error) {
	if a == nil || ctx == nil || snapshot.OriginalPrincipal != caller.PrincipalView() || len(snapshot.DeferredAdmission) != 0 {
		return nil, localDenied()
	}
	plan, err := a.plans(ctx)
	if err != nil {
		return nil, err
	}
	if plan.Plan == nil || plan.Plan.Revision() != string(snapshot.PlanRevision) || !bytes.Equal(plan.Evidence, snapshot.Pipeline) {
		return nil, localDenied()
	}
	commitment, err := continuations.SnapshotCommitment(snapshot)
	if err != nil {
		return nil, err
	}
	b := a.boundary
	var record registry.AuthorityRecord
	err = b.callerFacts(ctx, caller, func(current context.Context, facts fabricauth.CurrentCallerFacts) error {
		b.mu.RLock()
		sessions := b.sessions
		b.mu.RUnlock()
		return b.store.WithNativeAuthority(current, b.owner, registry.AuthorityScope{MaxOperations: 4096}, func(tx *registry.AuthorityTx) error {
			if err := a.verifyPlan(tx, string(snapshot.PlanRevision), snapshot.Pipeline); err != nil {
				return err
			}
			if sessions == nil || !sessions.AssociationOpen(caller) {
				return localDenied()
			}
			if facts.Managed != nil {
				if facts.Managed.Authority.Principal != caller.PrincipalView() {
					return localDenied()
				}
				if e := tx.VerifyCurrentNativeCaller(facts.Managed.Authority); e != nil {
					return e
				}
			} else if facts.Principal != b.root.Owner {
				return localDenied()
			}
			var e error
			record, e = tx.RecordDeferredAdmission(caller, snapshot.OriginalEnvelope, registry.DeferredAdmission{Version: 1, DeferralID: snapshot.DeferralID, OriginalCaller: caller.PrincipalView(), Provenance: caller.ProvenanceView(), OriginalDigest: sha256.Sum256(snapshot.OriginalEnvelope), SnapshotCommitment: commitment, PlanRevision: snapshot.PlanRevision})
			return e
		})
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(record)
}

func (a *LocalContinuationAuthority) RestoreOriginal(ctx context.Context, admission continuations.HistoricalAdmission) (fabric.ExecutionContext, error) {
	var original fabric.ExecutionContext
	if a == nil || len(admission.DeferredProof) == 0 || len(admission.DeferredProof) > 64<<10 || admission.Audience != a.boundary.root.Namespace {
		return original, localDenied()
	}
	var proof registry.AuthorityRecord
	if fabric.DecodeJSON(admission.DeferredProof, &proof) != nil {
		return original, localDenied()
	}
	err := a.boundary.store.WithNativeAuthority(ctx, a.boundary.owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 8}, func(tx *registry.AuthorityTx) error {
		facts, err := tx.VerifyDeferredAdmission(proof, admission.OriginalBytes, admission.SnapshotCommitment)
		if err != nil {
			return err
		}
		left, _ := json.Marshal(facts.Provenance)
		right, _ := json.Marshal(admission.Provenance)
		if facts.DeferralID != admission.Claim.ID || facts.OriginalCaller != admission.Principal || facts.PlanRevision != admission.PlanRevision || !bytes.Equal(left, right) {
			return localDenied()
		}
		original, err = fabric.NewAuthenticatedForwardContext(facts.OriginalCaller, admission.Audience, admission.OriginalBytes, facts.Provenance)
		if err != nil {
			return err
		}
		_, err = original.DecodeVerifiedEnvelope(admission.OriginalBytes, admission.Audience)
		return err
	})
	if err != nil {
		return fabric.ExecutionContext{}, err
	}
	return original, nil
}
