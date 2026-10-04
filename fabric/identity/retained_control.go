package identity

import (
	"context"

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
func (a *Authority) RetainedNativeControl(ctx context.Context, owner fabric.ExecutionContext, selected Scope) (Controller, Binding, error) {
	var controller Controller
	var binding Binding
	if a == nil {
		return controller, binding, invalid("Missing native control authority")
	}
	err := a.transact(ctx, owner, selected, false, func(tx *registry.AuthorityTx) error {
		c, err := tx.Get(controllerKey(selected))
		if err != nil {
			return err
		}
		if c.Retired || decodeValue(c, &controller) != nil || controller.Scope.Endpoint != selected.Endpoint || controller.Scope.BindingID != selected.BindingID {
			return invalid("Retained native controller differs")
		}
		controller.Proof = c
		b, err := tx.Get(bindingKey(selected))
		if err != nil {
			return err
		}
		if b.Retired || decodeValue(b, &binding) != nil || binding.Scope.Endpoint != selected.Endpoint || binding.Scope.BindingID != selected.BindingID {
			return invalid("Retained physical native binding differs")
		}
		binding.Proof = b
		if err := a.currentController(tx, controller); err != nil {
			return err
		}
		return a.currentBinding(tx, binding)
	})
	if err != nil {
		return Controller{}, Binding{}, err
	}
	return controller, binding, nil
}
