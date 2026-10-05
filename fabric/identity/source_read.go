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

// NativeSourceReadOperation distinguishes private stream reads from evidence
// retirement. Neither operation permits native execution or renews a deadline.
type NativeSourceReadOperation string

const (
	NativeSourcePage NativeSourceReadOperation = "page"
	NativeSourceAck  NativeSourceReadOperation = "ack"
)

// NativeSourceReadFacts require a separate configured current disclosure policy.
// Signed historical provenance alone never authorizes disclosure.
type NativeSourceReadFacts struct {
	CurrentCaller   fabric.ExecutionContext `json:"-"`
	Operation       NativeSourceReadOperation
	Owner           fabric.Principal
	Caller          fabric.Principal
	Controller      Controller
	CurrentBinding  Binding
	OriginalBinding Binding
	Admission       Admission
	Reservation     NativeDispatchReservation
}

type NativeSourceReadFence interface {
	WithNativeSourceRead(context.Context, NativeSourceReadFacts, func() error) error
}

// CurrentNativeSourceCallerWitness captures current caller evidence against the
// exact original source, after reservation validation and before SQL. It does
// not establish paid authority or permit IO inside the transaction verifier.
type CurrentNativeSourceCallerWitness interface {
	CurrentNativeSourceCallerWitness(context.Context, fabric.ExecutionContext, NativeSourceReadFacts) (Witness, error)
}

// FenceNativeSourceRead holds current controller/binding, exact original source
// and reservation retirement through ONLY bounded private IPC Page/ACK. Prepare
// identity lookups outside this callback; it must not reenter the registry.
func (a *Authority) FenceNativeSourceRead(ctx context.Context, owner, caller fabric.ExecutionContext, current Controller, currentBinding, originalBinding Binding, source Admission, reservation NativeDispatchReservation, operation NativeSourceReadOperation, ack func(context.Context) error) (err error) {
	if a == nil || ctx == nil || ack == nil || (operation != NativeSourcePage && operation != NativeSourceAck) || current.Scope != currentBinding.Scope || source.Scope != originalBinding.Scope || source.Scope.Endpoint != current.Scope.Endpoint || source.Scope.BindingID != current.Scope.BindingID || originalBinding.Worker != currentBinding.Worker || owner.VerifyAuthenticated(a.root.Namespace) != nil || owner.PrincipalView() != a.root.Owner || caller.VerifyAuthenticated(a.root.Namespace) != nil {
		return invalid("Missing current source read authority")
	}
	fence, ok := a.fence.(NativeSourceReadFence)
	if !ok {
		return fabric.NewError(fabric.CodeUnsupported, "Configured authority does not support native source reads")
	}
	if err = VerifyNativeDispatchReservation(a.root, reservation, source, originalBinding, reservation.Commitment()); err != nil {
		return err
	}
	var facts NativeSourceReadFacts
	raw, err := json.Marshal(NativeSourceReadFacts{Operation: operation, Owner: a.root.Owner, Caller: caller.PrincipalView(), Controller: current, CurrentBinding: currentBinding, OriginalBinding: originalBinding, Admission: source, Reservation: reservation})
	if err != nil || fabric.DecodeJSON(raw, &facts) != nil {
		return invalid("Invalid source read facts")
	}
	facts.CurrentCaller = caller
	var callerWitness Witness
	var e error
	if provider, ok := a.fence.(CurrentNativeSourceCallerWitness); ok {
		callerWitness, e = provider.CurrentNativeSourceCallerWitness(ctx, caller, facts)
		callerWitness = cloneWitness(callerWitness)
	} else {
		callerWitness, e = a.currentCallerWitness(ctx, caller)
	}
	if e != nil {
		return e
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
			err = fabric.NewError(fabric.CodeProtocolError, "Native source read fence panicked")
		}
	}()
	err = fence.WithNativeSourceRead(lifetime, facts, func() error {
		mu.Lock()
		defer mu.Unlock()
		if !active || calls != 0 {
			misused = true
			return invalid("Native source read callback closed or reused")
		}
		calls++
		callbackError = a.transact(lifetime, owner, current.Scope, false, func(tx *registry.AuthorityTx) error {
			if e := a.verifyCurrentCallerTx(tx, callerWitness, caller.PrincipalView()); e != nil {
				return e
			}
			if err := a.currentController(tx, current); err != nil {
				return err
			}
			if err := a.currentBinding(tx, currentBinding); err != nil {
				return err
			}
			if err := a.originalAdmission(tx, source); err != nil {
				return err
			}
			if _, err := exactRecord(tx, a.root, reservation.Proof, dispatchKey(source.OriginalCaller, source.InvocationID)); err != nil {
				return err
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
		err = invalid("Native source read was not authorized")
	}
	mu.Unlock()
	if err != nil {
		var typed *fabric.Error
		if !errors.As(err, &typed) {
			return fabric.NewError(fabric.CodeProtocolError, "Native source read authorization failed")
		}
	}
	return err
}

// NativeSourceReadVerifier is purpose-bound prepared current disclosure
// evidence. Preparing performs external caller checks; VerifyTx performs only
// exact signed source/control lookups inside the caller's same transaction.
type NativeSourceReadVerifier struct {
	authority   *Authority
	caller      fabric.Principal
	witness     Witness
	current     Controller
	binding     Binding
	source      Admission
	original    Binding
	reservation NativeDispatchReservation
}

func (a *Authority) PrepareNativeSourceReadVerifier(ctx context.Context, caller fabric.ExecutionContext, current Controller, b Binding, original Binding, source Admission, r NativeDispatchReservation) (*NativeSourceReadVerifier, error) {
	if a == nil || ctx == nil || caller.VerifyAuthenticated(a.root.Namespace) != nil || current.Scope != b.Scope || source.Scope != original.Scope || original.Worker != b.Worker || original.Scope.Endpoint != b.Scope.Endpoint || original.Scope.BindingID != b.Scope.BindingID {
		return nil, invalid("Current source verifier invalid")
	}
	if err := VerifyNativeDispatchReservation(a.root, r, source, original, r.Commitment()); err != nil {
		return nil, err
	}
	var facts NativeSourceReadFacts
	raw, err := json.Marshal(NativeSourceReadFacts{Operation: NativeSourcePage, Owner: a.root.Owner, Caller: caller.PrincipalView(), Controller: current, CurrentBinding: b, OriginalBinding: original, Admission: source, Reservation: r})
	if err != nil || fabric.DecodeJSON(raw, &facts) != nil {
		return nil, invalid("Invalid prepared source read facts")
	}
	facts.CurrentCaller = caller
	var w Witness
	if p, ok := a.fence.(CurrentNativeSourceCallerWitness); ok {
		w, err = p.CurrentNativeSourceCallerWitness(ctx, caller, facts)
		w = cloneWitness(w)
	} else {
		w, err = a.currentCallerWitness(ctx, caller)
	}
	if err != nil {
		return nil, err
	}
	return &NativeSourceReadVerifier{a, caller.PrincipalView(), w, facts.Controller, facts.CurrentBinding, facts.Admission, facts.OriginalBinding, facts.Reservation}, nil
}
func (v *NativeSourceReadVerifier) VerifyTx(tx *registry.AuthorityTx) error {
	if v == nil || v.authority == nil || tx == nil {
		return invalid("Source verifier unavailable")
	}
	a := v.authority
	if err := a.verifyCurrentCallerTx(tx, v.witness, v.caller); err != nil {
		return err
	}
	if err := a.currentController(tx, v.current); err != nil {
		return err
	}
	if err := a.currentBinding(tx, v.binding); err != nil {
		return err
	}
	if err := a.originalAdmission(tx, v.source); err != nil {
		return err
	}
	_, err := exactRecord(tx, a.root, v.reservation.Proof, dispatchKey(v.source.OriginalCaller, v.source.InvocationID))
	return err
}

// Scope is prepared actual current binding metadata for same-root transaction
// composition, not caller-supplied scope or a standalone authorization.
func (v *NativeSourceReadVerifier) Scope() Scope {
	if v == nil {
		return Scope{}
	}
	return v.current.Scope
}
