package identity

import (
	"context"
	"errors"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// NativeControlFacts authorize a bounded current-controller refresh, never a
// synthetic invocation or provider effect. The selected fence must explicitly
// support this purpose and its current policy/revocation linearization.
type NativeControlFacts struct {
	Scope      Scope
	Owner      fabric.Principal
	Controller Controller
	Binding    Binding
}
type NativeControlFence interface {
	WithNativeControl(context.Context, NativeControlFacts, func() error) error
}

// FenceNativeControl holds actual current registry and configured authorization
// through ONLY a bounded FULL worker control ACK. Original source/capture scope
// remains independent. A signed controller alone is not current authority.
func (a *Authority) FenceNativeControl(ctx context.Context, owner fabric.ExecutionContext, c Controller, b Binding, ack func(context.Context) error) (err error) {
	if a == nil || ctx == nil || ack == nil || c.Scope != b.Scope || c.Epoch() == 0 {
		return invalid("Missing current native control")
	}
	if owner.VerifyAuthenticated(a.root.Namespace) != nil || owner.PrincipalView() != a.root.Owner {
		return invalid("Native control owner differs")
	}
	fence, ok := a.fence.(NativeControlFence)
	if !ok {
		return fabric.NewError(fabric.CodeUnsupported, "Configured authority does not support native control fencing")
	}
	lifetime, cancel := context.WithTimeout(ctx, 5e9)
	defer cancel()
	facts := NativeControlFacts{Scope: c.Scope, Owner: a.root.Owner, Controller: c, Binding: b}
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
			err = fabric.NewError(fabric.CodeProtocolError, "Native control fence panicked")
		}
	}()
	err = fence.WithNativeControl(lifetime, facts, func() error {
		mu.Lock()
		defer mu.Unlock()
		if !active || calls != 0 {
			misused = true
			return invalid("Native control fence callback closed or reused")
		}
		calls++
		callbackError = a.transact(lifetime, owner, c.Scope, false, func(tx *registry.AuthorityTx) error {
			if e := a.currentController(tx, c); e != nil {
				return e
			}
			if e := a.currentBinding(tx, b); e != nil {
				return e
			}
			return ack(lifetime)
		})
		return callbackError
	})
	mu.Lock()
	active = false
	if err == nil && callbackError != nil {
		err = callbackError
	}
	if err == nil && (calls != 1 || misused) {
		err = invalid("Native control fence did not authorize ACK")
	}
	mu.Unlock()
	if err != nil {
		var typed *fabric.Error
		if !errors.As(err, &typed) {
			return fabric.NewError(fabric.CodeProtocolError, "Native control fence failed")
		}
	}
	return err
}
