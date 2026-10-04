package identity

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// VerifyCurrentNativeOrigin checks live descriptor/control/worker authority and
// an independently retained original generation in one bounded transaction.
// A descriptor may have renewed while the original native conversation remains
// unchanged. This grants no kernel liveness, caller identity or permission to
// submit work; the composing authenticator must still verify actual native IPC,
// process ancestry and configured current authorization.
func (a *Authority) VerifyCurrentNativeOrigin(ctx context.Context, owner fabric.ExecutionContext, current Scope, origin Origin) (Controller, Binding, error) {
	var controller Controller
	var binding Binding
	if current.Endpoint != origin.Scope.Endpoint || current.BindingID != origin.Scope.BindingID || !text(origin.ID) || !text(origin.NativeGeneration) {
		return controller, binding, invalid("Native origin differs from selected ownership")
	}
	err := a.transact(ctx, owner, current, false, func(tx *registry.AuthorityTx) error {
		var err error
		controller, binding, err = a.currentNativeOriginTx(tx, current, origin)
		return err
	})
	if err != nil {
		return Controller{}, Binding{}, err
	}
	return controller, binding, nil
}

func (a *Authority) currentNativeOriginTx(tx *registry.AuthorityTx, current Scope, origin Origin) (Controller, Binding, error) {
	var controller Controller
	var binding Binding

	c, err := tx.Get(controllerKey(current))
	if err != nil {
		return Controller{}, Binding{}, err
	}
	if c.Retired || decodeValue(c, &controller) != nil || controller.Scope != current {
		return Controller{}, Binding{}, conflict("Current native controller differs")
	}
	controller.Proof = c
	b, err := tx.Get(bindingKey(current))
	if err != nil {
		return Controller{}, Binding{}, err
	}
	if b.Retired || decodeValue(b, &binding) != nil || binding.Scope != current || binding.Worker != origin.Worker {
		return Controller{}, Binding{}, conflict("Current physical worker differs from original native generation")
	}
	binding.Proof = b
	if err = a.currentController(tx, controller); err != nil {
		return Controller{}, Binding{}, err
	}
	if err = a.currentBinding(tx, binding); err != nil {
		return Controller{}, Binding{}, err
	}
	if err = a.originalOrigin(tx, origin); err != nil {
		return Controller{}, Binding{}, err
	}
	_, err = tx.Get(retirementKey(origin.Scope, origin.ID))
	if err == nil {
		return Controller{}, Binding{}, conflict("Original native generation is retired")
	}
	var typed *fabric.Error
	if !errors.As(err, &typed) || typed.Code != fabric.CodeNotFound {
		return Controller{}, Binding{}, err
	}
	return controller, binding, nil
}

// FenceCurrentNativeOrigin also requires the explicitly configured current
// control-authority fence and holds registry revocation through a bounded
// supervisor/kernel check. The callback must not enter this registry or perform
// provider work. Historical origin signatures are not current authorization.
func (a *Authority) FenceCurrentNativeOrigin(ctx context.Context, owner fabric.ExecutionContext, current Scope, origin Origin, check func(context.Context) error) (err error) {
	if a == nil || ctx == nil || check == nil {
		return invalid("Missing native peer check")
	}
	fence, ok := a.fence.(NativeControlFence)
	if !ok {
		return fabric.NewError(fabric.CodeUnsupported, "Configured authority does not support native peer fencing")
	}
	controller, binding, err := a.VerifyCurrentNativeOrigin(ctx, owner, current, origin)
	if err != nil {
		return err
	}
	// Private copies prevent a callback from modifying retained signed evidence.
	var facts NativeControlFacts
	raw, err := json.Marshal(NativeControlFacts{Scope: current, Owner: a.root.Owner, Controller: controller, Binding: binding})
	if err != nil || fabric.DecodeJSON(raw, &facts) != nil {
		return invalid("Invalid native peer facts")
	}
	lifetime, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var mu sync.Mutex
	active := true
	calls := 0
	var callbackError error
	misused := false
	defer func() {
		mu.Lock()
		active = false
		mu.Unlock()
		if recover() != nil {
			err = fabric.NewError(fabric.CodeProtocolError, "Native peer fence panicked")
		}
	}()
	err = fence.WithNativeControl(lifetime, facts, func() error {
		mu.Lock()
		defer mu.Unlock()
		if !active || calls != 0 {
			misused = true
			return invalid("Native peer fence callback closed or reused")
		}
		calls++
		callbackError = a.transact(lifetime, owner, current, false, func(tx *registry.AuthorityTx) error {
			c, b, e := a.currentNativeOriginTx(tx, current, origin)
			if e != nil {
				return e
			}
			// A takeover between preparation and the actual authorization fence must
			// not combine an old external decision with new current control facts.
			if c.Epoch() != controller.Epoch() || b.Proof.Revision != binding.Proof.Revision {
				return conflict("Native peer control changed")
			}
			return check(lifetime)
		})
		return callbackError
	})
	mu.Lock()
	active = false
	if err == nil && callbackError != nil {
		err = callbackError
	}
	if err == nil && (calls != 1 || misused) {
		err = invalid("Native peer fence did not authorize a check")
	}
	mu.Unlock()
	if err != nil {
		var typed *fabric.Error
		if !errors.As(err, &typed) {
			return fabric.NewError(fabric.CodeProtocolError, "Native peer authorization failed")
		}
	}
	return err
}
