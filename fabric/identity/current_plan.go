package identity

import "github.com/pagnet-code/pagnet/fabric/registry"

// A plan witness does not authorize its caller or selected target. The trusted
// destination consumes it alongside those separate checks inside the SAME root
// transaction, before durable reservation, ACK or origin creation.
func verifyCurrentPlanTx(tx *registry.AuthorityTx, w Witness) error {
	if w.CurrentPlanVerifier == nil {
		return nil
	}
	return w.CurrentPlanVerifier(tx)
}
