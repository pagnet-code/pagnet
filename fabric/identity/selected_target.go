package identity

import (
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// A selected target is immutable signed source provenance. This helper is used
// ONLY before a new native effect, never to authorize historical reads or stop.
func verifySelectedSource(tx *registry.AuthorityTx, source Admission, env fabric.Envelope, prepared *registry.PreparedInvocationTarget) error {
	if env.Target == nil || *env.Target != source.Target || env.ExpectedRevision != source.TargetRevision || source.Target.Endpoint() != source.Scope.Endpoint {
		return invalid("Selected native target differs from original admission")
	}
	digest, err := tx.VerifyInvocationTarget(source.Target, source.TargetRevision, env.Payload, prepared)
	if err != nil {
		return err
	}
	if digest != source.InputSchemaDigest {
		return conflict("Selected native schema differs from original admission")
	}
	return nil
}
