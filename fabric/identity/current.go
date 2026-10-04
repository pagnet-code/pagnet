package identity

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// CurrentNativeState reads current controller and physical worker binding from
// the actual retained registry in one bounded transaction. A historical signed
// proof is not a replacement for this read. It establishes no native process
// liveness: the composing owner must independently authenticate its worker and
// verify real kernel PID/birth/session facts.
func (a *Authority) CurrentNativeState(ctx context.Context, owner fabric.ExecutionContext, scope Scope) (Controller, Binding, error) {
	var controller Controller
	var binding Binding
	err := a.transact(ctx, owner, scope, false, func(tx *registry.AuthorityTx) error {
		c, err := tx.Get(controllerKey(scope))
		if err != nil {
			return err
		}
		if c.Retired || decodeValue(c, &controller) != nil || controller.Scope != scope {
			return conflict("Current native controller does not match selected descriptor")
		}
		controller.Proof = c
		b, err := tx.Get(bindingKey(scope))
		if err != nil {
			return err
		}
		if b.Retired || decodeValue(b, &binding) != nil || binding.Scope != scope {
			return conflict("Current native worker does not match selected descriptor")
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
