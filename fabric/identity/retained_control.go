package identity

import (
	"context"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// RetainedNativeControl reads the actual current control rows for trusted owner
// recovery when a descriptor has changed. Their original scopes are preserved;
// this read cannot renew a controller, authorize an old descriptor or establish
// process liveness. AcquireController and RenewWorkerBinding remain separate,
// explicit CAS operations before CurrentNativeState can authorize new work.
// It also exposes a partially committed controller takeover so recovery can
// finish the SAME physical binding renewal without creating a replacement.
// NativeControlState distinguishes unprovisioned and partially provisioned
// endpoints. These retained facts never establish process liveness.
type NativeControlState struct {
	Controller *Controller
	Binding    *Binding
}

func (a *Authority) RetainedNativeControlState(ctx context.Context, owner fabric.ExecutionContext, selected Scope) (NativeControlState, error) {
	var state NativeControlState
	if a == nil {
		return state, invalid("Missing native control authority")
	}
	err := a.transact(ctx, owner, selected, false, func(tx *registry.AuthorityTx) error {
		c, err := tx.Get(controllerKey(selected))
		if err != nil && !retainedMissing(err) {
			return err
		}
		if err == nil {
			var controller Controller
			if c.Retired || decodeValue(c, &controller) != nil || controller.Scope.Endpoint != selected.Endpoint || controller.Scope.BindingID != selected.BindingID {
				return invalid("Retained native controller differs")
			}
			controller.Proof = c
			if err := a.currentController(tx, controller); err != nil {
				return err
			}
			state.Controller = &controller
		}
		b, err := tx.Get(bindingKey(selected))
		if err != nil {
			if retainedMissing(err) {
				return nil
			}
			return err
		}
		if state.Controller == nil {
			return invalid("Native binding has no retained controller")
		}
		var binding Binding
		if b.Retired || decodeValue(b, &binding) != nil || binding.Scope.Endpoint != selected.Endpoint || binding.Scope.BindingID != selected.BindingID {
			return invalid("Retained physical native binding differs")
		}
		binding.Proof = b
		if err := a.currentBinding(tx, binding); err != nil {
			return err
		}
		state.Binding = &binding
		return nil
	})
	if err != nil {
		return NativeControlState{}, err
	}
	return state, nil
}
func retainedMissing(err error) bool {
	var typed *fabric.Error
	return errors.As(err, &typed) && typed.Code == fabric.CodeNotFound
}
func (a *Authority) RetainedNativeControl(ctx context.Context, owner fabric.ExecutionContext, selected Scope) (Controller, Binding, error) {
	state, err := a.RetainedNativeControlState(ctx, owner, selected)
	if err != nil {
		return Controller{}, Binding{}, err
	}
	if state.Controller == nil || state.Binding == nil {
		return Controller{}, Binding{}, fabric.NewError(fabric.CodeNotFound, "Native control has not been fully provisioned")
	}
	return *state.Controller, *state.Binding, nil
}
