package fabricnative

import (
	"context"
	"crypto/subtle"

	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

func (m *ManagedPeers) CurrentCallerFacts(ctx context.Context, peer fabricauth.ManagedPeer) (fabricauth.ManagedCallerFacts, error) {
	var facts fabricauth.ManagedCallerFacts
	local, ok := peer.Activation.Scope.Local()
	if !ok {
		return facts, guardDenied()
	}
	activation, principal, err := m.checkedWithFacts(ctx, managedKey{local.Endpoint, local.WorkerID, local.OwnershipGeneration}, &facts)
	if err != nil || activation.Scope != peer.Activation.Scope || activation.RootPID != peer.Activation.RootPID || activation.StartIdentity != peer.Activation.StartIdentity || activation.NativeGeneration != peer.Activation.NativeGeneration || activation.NativeSessionID != peer.Activation.NativeSessionID || subtle.ConstantTimeCompare([]byte(activation.Nonce), []byte(peer.Activation.Nonce)) != 1 || facts.Authority.Principal != principal {
		return fabricauth.ManagedCallerFacts{}, guardDenied()
	}
	return facts, nil
}
