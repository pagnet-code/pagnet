package identity

import (
	"context"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// NativeIntentCommitment is supplied by a trusted native OperationBinder, after
// deriving exact operation bytes from the finalized envelope. This port never
// interprets caller JSON as an arbitrary executable operation.
type NativeIntentCommitment struct {
	CommandID       string   `json:"commandId"`
	Sequence        int64    `json:"sequence"`
	OperationDigest [32]byte `json:"operationDigest"`
	SelectorDigest  [32]byte `json:"selectorDigest"`
	SpecDigest      [32]byte `json:"specDigest"`
}

// NativeIntentReceipt is evidence from a genuinely authenticated worker's FULL
// journal admission ACK. It asserts no native completion or cloud receipt.
type NativeIntentReceipt struct {
	CommandID           string   `json:"commandId"`
	Sequence            int64    `json:"sequence"`
	OperationDigest     [32]byte `json:"operationDigest"`
	OriginalAdmissionID string   `json:"originalAdmissionId"`
	ControllerEpoch     uint64   `json:"controllerEpoch,string"`
	OwnershipGeneration string   `json:"ownershipGeneration"`
}

func (r NativeIntentReceipt) matches(i NativeIntentCommitment, c Controller, b Binding, source Admission) bool {
	// Exact authenticated journal readback retains the originally accepted epoch.
	// A fresh journal admission must itself require the current controller epoch;
	// it must not rewrite a historical ACK when B takes over from A.
	return r.CommandID == i.CommandID && r.Sequence == i.Sequence && r.OperationDigest == i.OperationDigest && r.OriginalAdmissionID == source.ID && r.ControllerEpoch >= source.OriginalControllerEpoch && r.ControllerEpoch > 0 && r.ControllerEpoch <= c.Epoch() && r.OwnershipGeneration == b.Worker.OwnershipGeneration
}

// FenceNativeIntent holds current registry/control/binding and external admission
// fences through ONLY the bounded worker durable-intent ACK. The callback must
// not await paid provider work. These two stores are not one distributed commit:
// a lost ACK is reconciled using the original sequence/digest and worker evidence,
// never by replaying native effects. A returned receipt remains truthful even if
// a configured fence subsequently fails; that error never authorizes new work.
func (a *Authority) FenceNativeIntent(ctx context.Context, owner fabric.ExecutionContext, c Controller, b Binding, source Admission, caller fabric.ExecutionContext, original, finalized []byte, intent NativeIntentCommitment, appendDurableIntent func(context.Context) (NativeIntentReceipt, error)) (receipt NativeIntentReceipt, err error) {
	if ctx == nil || appendDurableIntent == nil || source.Scope != c.Scope || b.Scope != c.Scope || !text(intent.CommandID) || intent.Sequence <= 0 || intent.Sequence == 9223372036854775807 || intent.OperationDigest == ([32]byte{}) || intent.SelectorDigest == ([32]byte{}) || intent.SpecDigest != b.Worker.ProfileDigest {
		return receipt, invalid("Incomplete native intent commitment")
	}
	lifetime, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	facts, env, e := a.facts(caller, c.Scope, original, finalized, source.AttemptID, source.ReplayID)
	if e != nil {
		return receipt, e
	}
	facts = withNativeSourceFacts(facts, PurposeNativeIntent, source)
	if facts.OriginalDigest != source.OriginalDigest || facts.FinalizedDigest != source.FinalizedDigest || facts.OriginalCaller != source.OriginalCaller {
		return receipt, invalid("Native intent original or final admission bytes differ")
	}
	prepared, e := a.store.PrepareInvocationTarget(ctx, source.Target, source.TargetRevision, env.Payload)
	if e != nil {
		return receipt, e
	}
	bindingDigest, e := digest(b)
	if e != nil || bindingDigest != source.BindingDigest {
		return receipt, conflict("Native intent original worker binding changed")
	}
	err = a.withFence(lifetime, facts, func(w Witness) error {
		return a.transact(lifetime, owner, c.Scope, false, func(tx *registry.AuthorityTx) error {
			if err := verifyCurrentPlanTx(tx, w); err != nil {
				return err
			}
			if e := a.currentController(tx, c); e != nil {
				return e
			}
			if e := a.currentBinding(tx, b); e != nil {
				return e
			}
			if e := a.originalAdmission(tx, source); e != nil {
				return e
			}
			if e := verifySelectedSource(tx, source, env, prepared); e != nil {
				return e
			}
			got, e := appendDurableIntent(lifetime)
			if got != (NativeIntentReceipt{}) {
				if !got.matches(intent, c, b, source) {
					return invalid("Native intent ACK evidence does not match exact admission")
				}
				receipt = got
			} else if e == nil {
				return invalid("Native intent ACK missing genuine journal evidence")
			}
			return e
		})
	})
	return receipt, err
}
