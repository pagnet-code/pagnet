package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
)

// The first uncertain effect is globally fenced inside this trust domain, not
// separately by adapter, target, private account, replay label or transport.
// This is infrastructure state, not planning or business task state. Source and
// response verification must NEVER create this claim.
type originalDispatchClaim struct {
	Format                     int              `json:"format"`
	Principal                  fabric.Principal `json:"principal"`
	InvocationID               string           `json:"invocationId"`
	OriginalSHA, FinalizedSHA  [32]byte
	Target                     fabric.EndpointRef `json:"target"`
	Revision, EndpointRevision fabric.Revision
	BindingID                  string `json:"bindingId"`
	BindingSHA, DispatchSHA    [32]byte
}

func originalDispatchKey(principal fabric.Principal, invocation string) AuthorityKey {
	raw, _ := json.Marshal(struct {
		Principal  fabric.Principal
		Invocation string
	}{principal, invocation})
	hash := sha256.Sum256(raw)
	return AuthorityKey{Kind: AuthorityNativeCheckpoint, ID: "original-dispatch/" + hex.EncodeToString(hash[:])}
}

// claimOriginalDispatch is called only by initial SignDispatchAdmission while
// its transaction mutex is held, after exact current caller/system/target checks.
// A rolled-back receipt rolls back this claim too. A retry never adds a row.
func (a *AuthorityTx) claimOriginalDispatch(c fabric.ExecutionContext, original, finalized, dispatch []byte, envelope fabric.Envelope) error {
	if a.scope.HistoryOnly || a.scope.BindingID == "" || envelope.Target == nil {
		return invalid("Original dispatch requires exact current executable binding")
	}
	object, err := loadObject(a.ctx, a.tx, a.scope.Endpoint.String())
	if err != nil || object.retired || object.revision != a.scope.ExpectedRevision {
		return conflict("Original dispatch endpoint is stale")
	}
	var descriptor fabric.EndpointDescriptor
	if err = a.store.decode(object.payload, &descriptor); err != nil {
		return err
	}
	var binding *fabric.BindingSummary
	for i := range descriptor.Bindings {
		if descriptor.Bindings[i].ID == a.scope.BindingID {
			binding = &descriptor.Bindings[i]
			break
		}
	}
	if binding == nil {
		return invalid("Original dispatch executable binding is absent")
	}
	encodedBinding, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	claim := originalDispatchClaim{Format: 1, Principal: c.PrincipalView(), InvocationID: envelope.ID, OriginalSHA: sha256.Sum256(original), FinalizedSHA: sha256.Sum256(finalized), Target: *envelope.Target, Revision: envelope.ExpectedRevision, EndpointRevision: descriptor.Revision, BindingID: binding.ID, BindingSHA: sha256.Sum256(encodedBinding), DispatchSHA: sha256.Sum256(dispatch)}
	raw, err := json.Marshal(claim)
	if err != nil {
		return err
	}
	key := originalDispatchKey(claim.Principal, claim.InvocationID)
	old, err := a.get(key)
	if err == nil {
		root := AuthorityIdentity{a.store.identity.Namespace, a.store.identity.StoreID, a.store.identity.Owner, a.store.identity.PublicKey, 1}
		if old.Retired || VerifyAuthorityRecord(root, old) != nil || !bytes.Equal(old.Value, raw) {
			return conflict("Original invocation already selected a different dispatch")
		}
		return nil
	}
	var typed *fabric.Error
	if !errors.As(err, &typed) || typed.Code != fabric.CodeNotFound {
		return err
	}
	_, err = a.cas(key, 0, raw, false)
	return err
}
