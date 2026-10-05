package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

// OriginalPhaseVerifier consumes an active concrete accepted-source capability
// inside the selected Root transaction. No provider work is performed here.
// CurrentPhaseWitness captures a genuine destination current-caller witness
// outside SQL and returns its exact SAME-Root transaction verifier. The
// configured provider must bind original proof and the selected phase envelope;
// nil/static historical evidence never qualifies. No external IO in returned guard.
type CurrentPhaseWitness func(context.Context, fabric.ExecutionContext, []byte, fabric.Envelope) (func(*registry.AuthorityTx) error, error)

type OriginalPhaseVerifier func(context.Context, *registry.AuthorityTx, fabric.OriginalSourceOwnership, fabric.Envelope) error

func NewOriginalExtensionPhaseVerifier(native *fabricnative.Adapter, services *fabricservices.Invocations) OriginalPhaseVerifier {
	return func(ctx context.Context, tx *registry.AuthorityTx, ownership fabric.OriginalSourceOwnership, env fabric.Envelope) error {
		encoded, err := json.Marshal(env)
		if err != nil {
			return localDenied()
		}
		switch source := ownership.(type) {
		case *fabricnative.OriginalCaptureOwnership:
			if native == nil {
				return localDenied()
			}
			if err = native.VerifyOriginalCaptureTx(ctx, tx, source); err != nil {
				return err
			}
			checkpoint, err := source.Checkpoint()
			if err != nil {
				return err
			}
			if sha256.Sum256(encoded) != checkpoint.Admission.FinalizedDigest || env.Principal != checkpoint.Admission.OriginalCaller || env.ID != checkpoint.Admission.InvocationID {
				return localDenied()
			}
		case *fabricservices.OriginalCaptureOwnership:
			if services == nil {
				return localDenied()
			}
			if err = services.VerifyOriginalCaptureTx(ctx, tx, source); err != nil {
				return err
			}
			facts, err := source.Facts()
			if err != nil {
				return err
			}
			if sha256.Sum256(encoded) != facts.FinalizedSHA || env.Principal != facts.Principal || env.ID != facts.InvocationID {
				return localDenied()
			}
		default:
			return localDenied()
		}
		return nil
	}
}

func originalExtensionPhaseScope(ownership fabric.OriginalSourceOwnership) (registry.AuthorityScope, error) {
	scope := registry.AuthorityScope{HistoryOnly: true, MaxOperations: 16}
	switch source := ownership.(type) {
	case *fabricnative.OriginalCaptureOwnership:
		checkpoint, err := source.Checkpoint()
		if err != nil {
			return scope, err
		}
		scope.Endpoint = checkpoint.OriginalBinding.Scope.Endpoint
		scope.ExpectedRevision = checkpoint.OriginalBinding.Scope.DescriptorRevision
		scope.BindingID = checkpoint.OriginalBinding.Scope.BindingID
	case *fabricservices.OriginalCaptureOwnership:
		facts, err := source.Facts()
		if err != nil {
			return scope, err
		}
		scope.Endpoint = facts.Scope.Endpoint
		scope.ExpectedRevision = facts.Scope.ExpectedEndpointRevision
		scope.BindingID = facts.Scope.BindingID
	default:
		return scope, localDenied()
	}
	return scope, nil
}

type extensionPhaseActorKey struct{}
type extensionPhaseActor struct {
	caller   fabric.ExecutionContext
	original []byte
}
type extensionPhaseActors struct {
	runtime *ExtensionRuntime
	current atomic.Pointer[extensionPhaseActor]
}
type extensionPhaseSourceKey struct{}
type extensionPhaseSource struct {
	runtime   *ExtensionRuntime
	ownership fabric.OriginalSourceOwnership
}

// Only these captured private values are overlaid; incoming exact source-token
// values, cancellation and deadlines are preserved.
type extensionPhaseContext struct {
	context.Context
	captured context.Context
}

func (c extensionPhaseContext) Value(key any) any {
	switch key.(type) {
	case extensionPhaseActorKey, extensionPlanContextKey:
		if c.captured == nil {
			return nil
		}
		return c.captured.Value(key)
	}
	return c.Context.Value(key)
}
func (r *ExtensionRuntime) phaseActor(ctx context.Context, caller fabric.ExecutionContext, original []byte) context.Context {
	actors := &extensionPhaseActors{runtime: r}
	actors.current.Store(&extensionPhaseActor{caller, append([]byte(nil), original...)})
	return context.WithValue(ctx, extensionPhaseActorKey{}, actors)
}
func (r *ExtensionRuntime) authorizePhase(ctx context.Context, request extension.InterceptRequest) error {
	if ctx == nil || ctx.Err() != nil || request.Envelope.Validate() != nil {
		return localDenied()
	}
	if request.Envelope.Context.Deadline != nil && !time.Now().Before(*request.Envelope.Context.Deadline) {
		return fabric.NewError(fabric.CodeDeadlineExceeded, "Original extension phase deadline expired")
	}
	selected, err := r.gate.fromContext(ctx)
	if err != nil {
		return err
	}
	if source, ok := ctx.Value(extensionPhaseSourceKey{}).(*extensionPhaseSource); ok {
		if source == nil || source.runtime != r || source.ownership == nil || r.config.VerifyOriginalPhase == nil || request.Phase == extension.PhaseRequest {
			return localDenied()
		}
		scope, err := originalExtensionPhaseScope(source.ownership)
		if err != nil {
			return err
		}
		return r.installation.Store.WithNativeAuthority(ctx, r.boundary.owner, scope, func(tx *registry.AuthorityTx) error {
			if err := selected.verify(tx); err != nil {
				return err
			}
			return r.config.VerifyOriginalPhase(ctx, tx, source.ownership, request.Envelope)
		})
	}
	actors, ok := ctx.Value(extensionPhaseActorKey{}).(*extensionPhaseActors)
	if !ok || actors == nil || actors.runtime != r {
		return localDenied()
	}
	actor := actors.current.Load()
	if actor == nil {
		return localDenied()
	}
	original, err := actor.caller.DecodeVerifiedEnvelope(actor.original, r.boundary.root.Namespace)
	if err != nil {
		return err
	}
	if request.Envelope.ID != original.ID || request.Envelope.Principal != original.Principal {
		return localDenied()
	}
	if r.config.CurrentPhaseWitness != nil {
		encoded, err := json.Marshal(request.Envelope)
		if err != nil {
			return localDenied()
		}
		var owned fabric.Envelope
		if fabric.DecodeJSON(encoded, &owned) != nil {
			return localDenied()
		}
		verify, err := r.config.CurrentPhaseWitness(ctx, actor.caller, append([]byte(nil), actor.original...), owned)
		if err != nil {
			return err
		}
		if verify == nil {
			return localDenied()
		}
		return r.installation.Store.WithNativeAuthority(ctx, r.boundary.owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 16}, func(tx *registry.AuthorityTx) error {
			if err := selected.verify(tx); err != nil {
				return err
			}
			return verify(tx)
		})
	}
	return r.current(ctx, actor.caller, func(current context.Context) error {
		return r.installation.Store.WithNativeAuthority(current, r.boundary.owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 16}, func(tx *registry.AuthorityTx) error {
			if err := selected.verify(tx); err != nil {
				return err
			}
			facts, ok := current.Value(currentFactsKey{}).(fabricauth.CurrentCallerFacts)
			if !ok {
				return localDenied()
			}
			b := r.boundary
			b.mu.RLock()
			sessions := b.sessions
			b.mu.RUnlock()
			authenticated := actor.caller
			resume, _ := b.resumeBinding(actor.caller)
			if resume != nil {
				authenticated = resume.resumer
				if err := resume.verifyTx(tx); err != nil {
					return err
				}
			}
			if sessions == nil || !sessions.AssociationOpen(authenticated) || facts.Principal != authenticated.PrincipalView() {
				return localDenied()
			}
			if facts.Hosted != nil {
				return facts.Hosted.VerifyTx(tx)
			}
			if facts.Managed != nil {
				return tx.VerifyCurrentNativeCaller(facts.Managed.Authority)
			}
			if facts.Principal != b.root.Owner {
				return localDenied()
			}
			return nil
		})
	})
}
