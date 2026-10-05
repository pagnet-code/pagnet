package fabricnode

import (
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

// This association retains original CLOUD scope. It is not a native local
// adoption proof and cannot mint operator authority or an original turn source.
func hostedCallerWitness(a *fabricauth.HostedCallerAuthority) *identity.HostedCallerWitness {
	if a == nil {
		return nil
	}
	return &identity.HostedCallerWitness{Principal: a.PrincipalView(), AssociationDigest: a.Digest(), VerifyCurrent: a.VerifyTx}
}
