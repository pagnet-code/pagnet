package fabricnode

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
)

// Remote source control is target-aware. A generic peer assertion cannot stand
// in for the exact retained original paid source and current exposed revision.
func (b *RemoteBoundary) CurrentNativeCallerWitness(ctx context.Context, caller fabric.ExecutionContext) (identity.Witness, error) {
	if _, ok := caller.AuthenticationEvidence().(*remoteRequestBinding); ok {
		return identity.Witness{}, localDenied()
	}
	return b.local.CurrentNativeCallerWitness(ctx, caller)
}
func (b *RemoteBoundary) sourceWitness(ctx context.Context, caller fabric.ExecutionContext, admission identity.Admission, current identity.Binding, original identity.Binding) (identity.Witness, error) {
	r, err := b.binding(caller)
	if err != nil {
		return identity.Witness{}, err
	}
	if r.principal != admission.OriginalCaller || r.invocation != admission.InvocationID || admission.Scope != original.Scope || current.Scope.Endpoint != original.Scope.Endpoint || current.Scope.BindingID != original.Scope.BindingID || current.Worker != original.Worker {
		return identity.Witness{}, localDenied()
	}
	// The original target/revision must remain explicitly exposed through the
	// actual current binding. Authority separately checks current descriptor,
	// original source and genuine reservation without relabeling their identity.
	w, err := b.witness(caller, admission.Target, admission.TargetRevision, current.Scope.BindingID)
	if err != nil {
		return identity.Witness{}, err
	}
	var selected identity.Witness
	err = b.local.selectedPlanWitness(ctx, &admission, w, func(value identity.Witness) error { selected = value; return nil })
	return selected, err
}
func (b *RemoteBoundary) CurrentNativeSourceCallerWitness(ctx context.Context, caller fabric.ExecutionContext, f identity.NativeSourceReadFacts) (identity.Witness, error) {
	if _, ok := caller.AuthenticationEvidence().(*remoteRequestBinding); !ok {
		return b.local.CurrentNativeCallerWitness(ctx, caller)
	}
	if f.CurrentCaller.PrincipalView() != caller.PrincipalView() || f.Owner != b.local.root.Owner || f.Caller != caller.PrincipalView() || (f.Operation != identity.NativeSourcePage && f.Operation != identity.NativeSourceAck) {
		return identity.Witness{}, localDenied()
	}
	return b.sourceWitness(ctx, caller, f.Admission, f.CurrentBinding, f.OriginalBinding)
}
func (b *RemoteBoundary) CurrentNativeCancellationCallerWitness(ctx context.Context, caller fabric.ExecutionContext, f identity.NativeCancellationFacts) (identity.Witness, error) {
	if _, ok := caller.AuthenticationEvidence().(*remoteRequestBinding); !ok {
		return b.local.CurrentNativeCallerWitness(ctx, caller)
	}
	if f.CurrentCaller.PrincipalView() != caller.PrincipalView() || f.Owner != b.local.root.Owner || f.Caller != caller.PrincipalView() {
		return identity.Witness{}, localDenied()
	}
	return b.sourceWitness(ctx, caller, f.Admission, f.CurrentBinding, f.OriginalBinding)
}
func (b *RemoteBoundary) WithNativeSourceRead(ctx context.Context, f identity.NativeSourceReadFacts, next func() error) error {
	if _, ok := f.CurrentCaller.AuthenticationEvidence().(*remoteRequestBinding); !ok {
		return b.local.WithNativeSourceRead(ctx, f, next)
	}
	if next == nil {
		return localDenied()
	}
	if _, err := b.CurrentNativeSourceCallerWitness(ctx, f.CurrentCaller, f); err != nil {
		return err
	}
	return next()
}
func (b *RemoteBoundary) WithNativeCancellation(ctx context.Context, f identity.NativeCancellationFacts, next func() error) error {
	if _, ok := f.CurrentCaller.AuthenticationEvidence().(*remoteRequestBinding); !ok {
		return b.local.WithNativeCancellation(ctx, f, next)
	}
	if next == nil {
		return localDenied()
	}
	if _, err := b.CurrentNativeCancellationCallerWitness(ctx, f.CurrentCaller, f); err != nil {
		return err
	}
	return next()
}
