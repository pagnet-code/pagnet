// Production federation control verifiers for the installed destination
// serving (E1 slice-2c). Both are bounded local retained-state checks that
// RECOMPUTE evidence inside the caller's transaction and compare it against
// the wire-claimed value; a received digest is never evidence by itself.
// Neither opens a Store, calls a provider or runs another registry
// transaction. The current caller's admission authorization (binding, peers,
// exposure) is already committed in the same transaction by the control
// admission policy (remoteFederationAdmissionPolicy.AuthorizeTx).

package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// federationCursorVerifier verifies an ACK's consumer cursor against the
// destination's retained final output: the frame at the cursor ordinal must
// exist and its recomputed committed digest must equal the cursor's claimed
// frame digest. The consumer floor itself is committed by ControlLedger.Begin
// in this same transaction after this check passes.
type federationCursorVerifier struct {
	outputs *FinalOutputs
}

var _ federation.CursorVerifier = (*federationCursorVerifier)(nil)

func (v *federationCursorVerifier) VerifyCursorTx(ctx context.Context, tx *registry.AuthorityTx, facts federation.AdmissionFacts, association federation.Association, cursor federation.ConsumerCursor) error {
	if v == nil || v.outputs == nil || ctx == nil || ctx.Err() != nil || tx == nil || cursor.Ordinal < 0 || cursor.FrameDigest == ([32]byte{}) {
		return localDenied()
	}
	ref, e := controlFinalOutputReference(facts.Principal, facts.InvocationID, association)
	if e != nil {
		return e
	}
	digest, e := v.outputs.VerifyFrameTx(ctx, tx, ref, uint64(cursor.Ordinal))
	if e != nil {
		return e
	}
	if digest != cursor.FrameDigest {
		return localDenied()
	}
	return nil
}

// federationControlResultVerifier recomputes a committed control result's
// retained-state evidence inside the ControlLedger.Complete transaction and
// compares it against the result's claimed digest. An ACK result is verified
// against the retained cursor and the final frame at that cursor; a cancel
// result is verified against the committed stop intent's head state.
type federationControlResultVerifier struct {
	admissions *federation.AdmissionLedger
	outputs    *FinalOutputs
}

var _ federation.ControlResultVerifier = (*federationControlResultVerifier)(nil)

func (v *federationControlResultVerifier) VerifyControlResultTx(ctx context.Context, tx *registry.AuthorityTx, facts federation.AdmissionFacts, request federation.ControlRequest, result federation.ControlResult) error {
	if v == nil || v.admissions == nil || v.outputs == nil || ctx == nil || ctx.Err() != nil || tx == nil || result.ResponseDigest == ([32]byte{}) {
		return localDenied()
	}
	status, e := v.admissions.StatusTx(ctx, tx, facts.Principal, facts.InvocationID)
	if e != nil {
		return e
	}
	switch request.Proof.Frame.Action {
	case "ack":
		if status.Association == nil || result.Cursor == nil || *result.Cursor != status.Cursor {
			return localDenied()
		}
		ref, e := controlFinalOutputReference(facts.Principal, facts.InvocationID, *status.Association)
		if e != nil {
			return e
		}
		digest, e := v.outputs.VerifyFrameTx(ctx, tx, ref, uint64(result.Cursor.Ordinal))
		if e != nil {
			return e
		}
		if digest != result.ResponseDigest {
			return localDenied()
		}
		return nil
	case "cancel":
		if !status.CancelRequested {
			return localDenied()
		}
		if controlHeadStateDigest(status) != result.ResponseDigest {
			return localDenied()
		}
		return nil
	default:
		return localDenied()
	}
}

// controlFinalOutputReference rebuilds the exact retained final-output
// reference from the committed admission association: the private reference
// carries the source key and immutable commitment; the principal/invocation
// identity comes from the admission facts the control admission policy
// already bound to the current caller. Every field is cross-checked; the
// reference is still re-verified against the retained head on every use.
func controlFinalOutputReference(principal fabric.Principal, invocation string, association federation.Association) (FinalOutputReference, error) {
	if association.Protocol != "pagnet.final-output.v1" || association.BindingDigest == ([32]byte{}) || len(association.PrivateReference) == 0 {
		return FinalOutputReference{}, localDenied()
	}
	var ref FinalOutputReference
	// The private reference is {"Version", "sourceKey", "Commitment"} where
	// Commitment is a [32]byte marshaled as a 32-element JSON array, so the
	// member bound counts 3 object members plus 32 array elements.
	if fabric.DecodeJSONWithLimits(association.PrivateReference, &ref, fabric.WireLimits{MaxBytes: 4096, MaxDepth: 4, MaxMembers: 64}) != nil || ref.Version != 1 || ref.SourceKey == "" || ref.Commitment == ([32]byte{}) {
		return FinalOutputReference{}, localDenied()
	}
	ref.Principal = principal
	ref.InvocationID = invocation
	if ref.SourceKey != finalOutputID(ref.Principal, ref.InvocationID) || association.BindingDigest != ref.Commitment {
		return FinalOutputReference{}, localDenied()
	}
	return ref, nil
}

// controlHeadStateDigest is the canonical committed-head-state digest the
// cancel actuation returns and the result verifier recomputes: purpose-tagged
// sealed JSON over the exact retained admission head.
func controlHeadStateDigest(status federation.AdmissionStatus) [32]byte {
	raw, _ := json.Marshal(struct {
		Purpose         string                    `json:"purpose"`
		Attempted       bool                      `json:"attempted"`
		CancelRequested bool                      `json:"cancelRequested"`
		Association     *federation.Association   `json:"association"`
		Cursor          federation.ConsumerCursor `json:"cursor"`
	}{"pagnet.federation.control-head-state.v1", status.Attempted, status.CancelRequested, status.Association, status.Cursor})
	return sha256.Sum256(raw)
}
