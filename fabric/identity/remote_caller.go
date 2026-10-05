package identity

import (
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// RemoteCallerWitness is ephemeral trusted composition evidence, never a wire
// identity or an original paid receipt. A finite freshly authenticated source
// assertion is bound to the exact encrypted channel/request and bilateral pins.
// It does not claim instantaneous remote kernel revocation after issuance.
// VerifyCurrent must check SAME-transaction peer pins and explicitly published
// exposure integrity; business authorization belongs to extensions. External IO
// or nested Store calls are forbidden in that callback.
type RemoteCallerWitness struct {
	Principal       fabric.Principal
	RequestDigest   [32]byte
	AssertionDigest [32]byte
	AssociationOpen func() bool
	VerifyCurrent   func(*registry.AuthorityTx) error
}

func (a *Authority) verifyRemoteCallerTx(tx *registry.AuthorityTx, w Witness, principal fabric.Principal) error {
	r := w.RemoteCaller
	if r == nil || w.DeferredCaller != nil || w.CurrentCallerKind != "remote-peer.request" || w.CurrentCallerAuthority != nil || w.CurrentCallerOpen == nil || !w.CurrentCallerOpen() || r.Principal != principal || r.RequestDigest == ([32]byte{}) || r.AssertionDigest == ([32]byte{}) || r.AssociationOpen == nil || !r.AssociationOpen() || r.VerifyCurrent == nil {
		return invalid("Current remote request evidence required")
	}
	if err := r.VerifyCurrent(tx); err != nil {
		return err
	}
	if !w.CurrentCallerOpen() || !r.AssociationOpen() {
		return invalid("Current remote request association closed")
	}
	return nil
}
