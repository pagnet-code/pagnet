package identity

import (
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// DeferredCallerWitness is ephemeral trusted infrastructure evidence. The
// original principal is authenticated by the retained DEFER record; permission
// comes separately from the genuinely current allowed resumer and current plan.
// It is never persisted as admission JSON or manufactured from wire receipts.
type DeferredCallerWitness struct {
	Admission          registry.AuthorityRecord
	Original           []byte
	SnapshotCommitment [32]byte
	Resumer            fabric.Principal
	ClaimOpen          func() bool
	VerifyPlan         func(*registry.AuthorityTx) error
}

func (a *Authority) verifyDeferredCallerTx(tx *registry.AuthorityTx, w Witness, original fabric.Principal) error {
	d := w.DeferredCaller
	if d == nil || d.ClaimOpen == nil || !d.ClaimOpen() || d.VerifyPlan == nil || w.CurrentCallerOpen == nil || !w.CurrentCallerOpen() {
		return invalid("Current continuation claim/resumer required")
	}
	facts, err := tx.VerifyDeferredAdmission(d.Admission, d.Original, d.SnapshotCommitment)
	if err != nil {
		return err
	}
	if facts.OriginalCaller != original {
		return invalid("Deferred original principal differs")
	}
	if err = d.VerifyPlan(tx); err != nil {
		return err
	}
	switch w.CurrentCallerKind {
	case "local-resume.owner":
		if d.Resumer != a.root.Owner || w.CurrentCallerAuthority != nil {
			return invalid("Current continuation owner resumer differs")
		}
	case "local-resume.managed":
		if w.CurrentCallerAuthority == nil || w.CurrentCallerAuthority.Principal != d.Resumer {
			return invalid("Current continuation managed resumer differs")
		}
		return tx.VerifyCurrentNativeCaller(*w.CurrentCallerAuthority)
	default:
		return invalid("Continuation witness purpose unsupported")
	}
	return nil
}
