package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// RestoreOriginalCaller restores only authenticated historical provenance from
// an exact admission still retained in the actual live registry. Envelopes must
// come from the sealed original source checkpoint, not reconstructed current
// metadata. Expiry does not erase history; every effect/resume still requires
// its separate current authorization and deadline checks.
func (a *Authority) RestoreOriginalCaller(ctx context.Context, owner fabric.ExecutionContext, source Admission, original, finalized []byte) (fabric.ExecutionContext, error) {
	var restored fabric.ExecutionContext
	if a == nil || ctx == nil || len(original) == 0 || len(finalized) == 0 || sha256.Sum256(original) != source.OriginalDigest || sha256.Sum256(finalized) != source.FinalizedDigest {
		return restored, invalid("Original admission bytes differ")
	}
	err := a.transact(ctx, owner, source.Scope, true, func(tx *registry.AuthorityTx) error {
		if err := a.originalAdmission(tx, source); err != nil {
			return err
		}
		var before, after fabric.Envelope
		if fabric.DecodeJSON(original, &before) != nil || before.Validate() != nil || fabric.DecodeJSON(finalized, &after) != nil || after.Validate() != nil {
			return invalid("Original admission envelopes invalid")
		}
		deadline := ""
		if after.Context.Deadline != nil {
			deadline = after.Context.Deadline.UTC().Format(time.RFC3339Nano)
		}
		if before.Principal != source.OriginalCaller || after.Principal != source.OriginalCaller || before.ID != source.InvocationID || after.ID != source.InvocationID || after.Operation != fabric.OperationInvoke || after.Target == nil || *after.Target != source.Scope.Endpoint || after.ExpectedRevision != source.Scope.DescriptorRevision || source.Deadline != deadline {
			return invalid("Original admission identity or target differs")
		}
		x, y := before, after
		x.Payload = nil
		y.Payload = nil
		x.Metadata = nil
		y.Metadata = nil
		x.Target = nil
		y.Target = nil
		x.ExpectedRevision = ""
		y.ExpectedRevision = ""
		xraw, _ := json.Marshal(x)
		yraw, _ := json.Marshal(y)
		if sha256.Sum256(xraw) != sha256.Sum256(yraw) {
			return invalid("Original admission system fields changed")
		}
		cf := source.CallerFrame
		df := source.DispatchFrame
		if cf.SourceDomain != a.root.Namespace || cf.AudienceDomain != a.root.Namespace || cf.IssuerKeyRevision != a.root.KeyRevision || cf.CallerRef != source.OriginalCaller.Ref || cf.Operation != before.Operation || cf.OriginalEnvelopeID != before.ID || cf.OriginalEnvelopeDigest != source.OriginalDigest || cf.ReplayID != source.ReplayID || cf.Deadline != deadline || df.SourceDomain != a.root.Namespace || df.AudienceDomain != a.root.Namespace || df.CallerRef != source.OriginalCaller.Ref || df.InvocationID != source.InvocationID || df.AttemptID != source.AttemptID || df.ReplayID != source.ReplayID || df.FinalizedDispatchDigest != source.FinalizedDigest || df.Deadline != deadline {
			return invalid("Original admission signing commitments differ")
		}
		callerFrame, err := cf.SigningBytes()
		if err != nil || !ed25519.Verify(a.root.PublicKey, callerFrame, source.CallerSignature) {
			return invalid("Original caller admission signature invalid")
		}
		dispatchFrame, err := df.SigningBytes()
		if err != nil || !ed25519.Verify(a.root.PublicKey, dispatchFrame, source.DispatchSignature) {
			return invalid("Original dispatch admission signature invalid")
		}
		restored, err = fabric.NewAuthenticatedForwardContext(source.OriginalCaller, a.root.Namespace, original, source.Provenance)
		if err != nil {
			return err
		}
		_, err = restored.DecodeVerifiedEnvelope(original, a.root.Namespace)
		return err
	})
	if err != nil {
		return fabric.ExecutionContext{}, err
	}
	return restored, nil
}
