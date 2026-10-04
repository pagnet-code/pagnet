package identity

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// LookupNativeDispatch reads an exact original reservation from this actual
// registry. It grants no current authorization, admission or actuation. Missing
// means no retained reservation; callers must never replace that with new work.
func (a *Authority) LookupNativeDispatch(ctx context.Context, owner fabric.ExecutionContext, source Admission, originalBinding Binding) (NativeDispatchReservation, error) {
	var result NativeDispatchReservation
	if a == nil || ctx == nil || source.Scope != originalBinding.Scope || owner.VerifyAuthenticated(a.root.Namespace) != nil || owner.PrincipalView() != a.root.Owner {
		return result, invalid("Original native reservation lookup authority missing")
	}
	err := a.transact(ctx, owner, source.Scope, true, func(tx *registry.AuthorityTx) error {
		if err := a.originalAdmission(tx, source); err != nil {
			return err
		}
		record, err := tx.Get(dispatchKey(source.OriginalCaller, source.InvocationID))
		if err != nil {
			return err
		}
		if record.Retired || decodeValue(record, &result) != nil {
			return invalid("Original native reservation unavailable")
		}
		result.Proof = record
		return VerifyNativeDispatchReservation(a.root, result, source, originalBinding, result.Commitment())
	})
	if err != nil {
		return NativeDispatchReservation{}, err
	}
	return result, nil
}
