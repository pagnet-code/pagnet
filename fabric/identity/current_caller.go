package identity

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// CurrentNativeCallerWitness is a trusted local preflight port. Actual concrete
// session proof is captured outside SQL; the destination transaction consumes
// only its immutable source proofs and cheap association-revocation predicate.
// It grants no authority independently of the purpose-specific fence.
type CurrentNativeCallerWitness interface {
	CurrentNativeCallerWitness(context.Context, fabric.ExecutionContext) (Witness, error)
}

func (a *Authority) currentCallerWitness(ctx context.Context, caller fabric.ExecutionContext) (Witness, error) {
	provider, ok := a.fence.(CurrentNativeCallerWitness)
	if !ok {
		return Witness{}, nil
	}
	w, err := provider.CurrentNativeCallerWitness(ctx, caller)
	if err != nil {
		return Witness{}, err
	}
	return cloneWitness(w), nil
}
func (a *Authority) verifyCurrentCallerTx(tx *registry.AuthorityTx, w Witness, principal fabric.Principal) error {
	if err := verifyCurrentPlanTx(tx, w); err != nil {
		return err
	}
	if w.DeferredCaller != nil {
		return a.verifyDeferredCallerTx(tx, w, principal)
	}
	if w.RemoteCaller != nil {
		return a.verifyRemoteCallerTx(tx, w, principal)
	}
	switch w.CurrentCallerKind {
	case "":
		if w.CurrentCallerAuthority != nil || w.CurrentCallerOpen != nil {
			return invalid("Current caller witness kind missing")
		}
	case "local-peer.owner":
		if w.CurrentCallerOpen == nil || !w.CurrentCallerOpen() {
			return invalid("Current local peer association is closed")
		}
		if w.CurrentCallerAuthority != nil || principal != a.root.Owner {
			return invalid("Current owner peer witness differs")
		}
	case "local-peer.managed":
		if w.CurrentCallerOpen == nil || !w.CurrentCallerOpen() {
			return invalid("Current local peer association is closed")
		}
		if w.CurrentCallerAuthority == nil || w.CurrentCallerAuthority.Principal != principal {
			return invalid("Current managed peer witness missing")
		}
		return tx.VerifyCurrentNativeCaller(*w.CurrentCallerAuthority)
	default:
		return invalid("Current caller witness kind unsupported")
	}
	return nil
}
