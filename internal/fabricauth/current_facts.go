package fabricauth

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/localpeer"
)

// ManagedCallerFacts must be produced by actual current worker IPC and retained
// root verification, not a claimed endpoint/generation from a protocol request.
type ManagedCallerFacts struct {
	Authority registry.NativeCallerAuthority
}
type ManagedFactsProvider func(context.Context, ManagedPeer) (ManagedCallerFacts, error)

type CurrentCallerFacts struct {
	Principal fabric.Principal
	Process   localpeer.ProcessSnapshot
	Managed   *ManagedCallerFacts
}

func (CurrentCallerFacts) MarshalJSON() ([]byte, error) { return nil, denied() }
func (*CurrentCallerFacts) UnmarshalJSON([]byte) error  { return denied() }

// WithCurrentFacts captures current kernel facts before the destination SQL
// transaction. Managed retirement/control records are rechecked there using
// VerifyCurrentNativeCaller. A process can still exit after the kernel snapshot;
// this method does not promise impossible atomicity with the OS scheduler.
func (a *Authority) WithCurrentFacts(ctx context.Context, caller fabric.ExecutionContext, next func(context.Context, CurrentCallerFacts) error) error {
	if a == nil || ctx == nil || next == nil || !a.RecognizesCurrentCaller(caller) {
		return denied()
	}
	b := caller.AuthenticationEvidence().(*sessionBinding)
	checked, cancel := context.WithTimeout(ctx, a.config.CheckTimeout)
	defer cancel()
	s := b.session
	s.mu.Lock()
	principal, err := s.verify(checked)
	facts := CurrentCallerFacts{Principal: principal, Process: s.process}
	if err == nil && s.activation != nil {
		if a.config.ManagedFacts == nil {
			err = denied()
		} else {
			root := a.config.Root
			root.PublicKey = append([]byte(nil), root.PublicKey...)
			var managed ManagedCallerFacts
			managed, err = a.config.ManagedFacts(checked, ManagedPeer{s.process, *s.activation, root})
			if err == nil && managed.Authority.Principal != principal {
				err = denied()
			}
			if err == nil {
				facts.Managed = &managed
			}
		}
	}
	if err == nil {
		principal, err = s.verify(checked)
		if principal != facts.Principal {
			err = denied()
		}
	}
	s.mu.Unlock()
	if err != nil || principal != b.principal {
		return denied()
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return next(ctx, facts)
}
