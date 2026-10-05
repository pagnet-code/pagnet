package identity

import (
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// HostedCallerWitness is supplied by the trusted current kernel-session fence.
// Its verifier consumes the actual signed original-worker association in the
// SAME destination transaction. It is neither remote authentication nor a local
// native launch profile, and cannot survive serialization as authority.
type HostedCallerWitness struct {
	Principal         fabric.Principal
	AssociationDigest [32]byte
	VerifyCurrent     func(*registry.AuthorityTx) error
}

func (HostedCallerWitness) MarshalJSON() ([]byte, error) {
	return nil, invalid("Hosted witness is private")
}
func (*HostedCallerWitness) UnmarshalJSON([]byte) error { return invalid("Hosted witness is private") }

func (a *Authority) verifyHostedCallerTx(tx *registry.AuthorityTx, w Witness, principal fabric.Principal) error {
	h := w.HostedCaller
	if h == nil || w.CurrentCallerKind != "local-peer.hosted" || w.CurrentCallerAuthority != nil || w.RemoteCaller != nil || w.DeferredCaller != nil || w.CurrentCallerOpen == nil || !w.CurrentCallerOpen() || h.Principal != principal || h.Principal == a.root.Owner || h.AssociationDigest == ([32]byte{}) || h.VerifyCurrent == nil {
		return invalid("Current original hosted caller witness differs")
	}
	if err := h.VerifyCurrent(tx); err != nil {
		return err
	}
	if !w.CurrentCallerOpen() {
		return invalid("Current hosted association closed during transaction")
	}
	return nil
}
