package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/a2a"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

// LocalOperator is a protected installation capability, not a principal-name
// predicate. Implementations must reverify their actual OS identity, retained
// root and private operator evidence. Historical/static contexts must not pass.
type LocalOperator interface {
	WithCurrentOperator(context.Context, fabric.ExecutionContext, func(context.Context) error) error
}

// LocalBoundary is the explicitly selected single-installation local trust
// boundary. It grants no default trust to remote/federated authenticators. The
// private builder seals the actual peer authority before any node ports escape.
// Peer checks do not hold Session.mu or SQL across recursive composition; actual
// destination admission still performs its own SAME-TX source/binding checks.
type LocalBoundary struct {
	store    *registry.Store
	root     registry.AuthorityIdentity
	owner    fabric.ExecutionContext
	operator LocalOperator
	timeout  time.Duration
	mu       sync.RWMutex
	sessions *fabricauth.Authority
	planGate *extensionPlanGate
	closed   bool
}

func localDenied() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Current configured local trust boundary required")
}

func newLocalBoundary(ctx context.Context, store *registry.Store, owner fabric.ExecutionContext, operator LocalOperator, timeout time.Duration) (*LocalBoundary, error) {
	if ctx == nil || store == nil || operator == nil {
		return nil, localDenied()
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if timeout < time.Millisecond || timeout > 5*time.Minute {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid local boundary operation bound")
	}
	root, err := store.CurrentAuthorityIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if owner.VerifyAuthenticated(root.Namespace) != nil || owner.PrincipalView() != root.Owner {
		return nil, localDenied()
	}
	boundary := &LocalBoundary{store: store, root: root, owner: owner, operator: operator, timeout: timeout}
	if err = boundary.operatorCurrent(ctx, owner, func(context.Context) error { return nil }); err != nil {
		return nil, err
	}
	return boundary, nil
}
func (b *LocalBoundary) currentRoot(ctx context.Context) error {
	if b == nil || ctx == nil || ctx.Err() != nil {
		return localDenied()
	}
	b.mu.RLock()
	closed := b.closed
	b.mu.RUnlock()
	if closed {
		return localDenied()
	}
	current, err := b.store.CurrentAuthorityIdentity(ctx)
	if err != nil || current.Namespace != b.root.Namespace || current.StoreID != b.root.StoreID || current.KeyRevision != b.root.KeyRevision || current.Owner != b.root.Owner || !bytes.Equal(current.PublicKey, b.root.PublicKey) {
		return localDenied()
	}
	return nil
}

// guardedBoundary preserves callback errors and rejects repeated/escaped use,
// even if a faulty installed verifier swallows those errors.
func guardedBoundary(ctx context.Context, verify func(context.Context, func(context.Context) error) error, next func(context.Context) error) (err error) {
	if ctx == nil || next == nil {
		return localDenied()
	}
	var mu sync.Mutex
	active, calls, misused := true, 0, false
	var callbackErr error
	defer func() {
		mu.Lock()
		active = false
		mu.Unlock()
		if recover() != nil {
			err = fabric.NewError(fabric.CodeProtocolError, "Local trust boundary callback panicked")
		}
	}()
	err = verify(ctx, func(current context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if !active || calls != 0 {
			misused = true
			return localDenied()
		}
		calls++
		if current == nil || current.Err() != nil {
			callbackErr = localDenied()
			return callbackErr
		}
		callbackErr = next(current)
		return callbackErr
	})
	mu.Lock()
	defer mu.Unlock()
	if misused || calls != 1 {
		if !misused && err != nil {
			return err
		}
		return localDenied()
	}
	if callbackErr != nil {
		return callbackErr
	}
	return err
}
func (b *LocalBoundary) operatorCurrent(ctx context.Context, caller fabric.ExecutionContext, next func(context.Context) error) error {
	if b.currentRoot(ctx) != nil {
		return localDenied()
	}
	lifetime, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	return guardedBoundary(lifetime, func(current context.Context, n func(context.Context) error) error {
		return b.operator.WithCurrentOperator(current, caller, n)
	}, next)
}
func (b *LocalBoundary) callerCurrent(ctx context.Context, caller fabric.ExecutionContext, next func(context.Context) error) error {
	if b.currentRoot(ctx) != nil {
		return localDenied()
	}
	b.mu.RLock()
	sessions := b.sessions
	b.mu.RUnlock()
	if sessions == nil {
		return localDenied()
	}
	lifetime, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	return guardedBoundary(lifetime, func(current context.Context, n func(context.Context) error) error {
		return sessions.WithCurrentContext(current, caller, n)
	}, next)
}

func (b *LocalBoundary) WithCurrentOwner(ctx context.Context, caller fabric.ExecutionContext, next func(context.Context) error) error {
	return b.operatorCurrent(ctx, caller, next)
}
func (b *LocalBoundary) WithCurrent(ctx context.Context, caller fabric.ExecutionContext, descriptor fabric.EndpointDescriptor, next func(context.Context) error) error {
	if b == nil || descriptor.Ref.IsOffer() || descriptor.Ref.Domain() != b.root.Namespace || descriptor.Revision == "" {
		return localDenied()
	}
	if resume, ok := b.resumeBinding(caller); ok {
		actual, original, final, qualified := node.FinalizedRequestFromContext(ctx)
		var env fabric.Envelope
		if !qualified || actual.PrincipalView() != resume.original || !bytes.Equal(original, resume.originalBytes) || fabric.DecodeJSON(final, &env) != nil || env.Operation != fabric.OperationInvoke || env.Target == nil || env.Target.Endpoint() != descriptor.Ref || !resume.dispatched.Load() {
			return localDenied()
		}
		return b.callerCurrent(ctx, resume.resumer, next)
	}
	// Protected operator setup/recovery is a separate concrete capability. Never
	// replace an incoming caller with the configured owner to make it pass.
	if caller.AuthenticationEvidence() != nil {
		b.mu.RLock()
		sessions := b.sessions
		b.mu.RUnlock()
		if sessions != nil && sessions.RecognizesCurrentCaller(caller) {
			return b.callerCurrent(ctx, caller, next)
		}
	}
	return b.operatorCurrent(ctx, caller, next)
}

// verifyFacts validates a paid admission or pre-activation origin request.
// "Historical" origin preserves source identity across binding changes but still
// precedes Driver.Activate; it cannot restart expired paid work. Existing native
// history/read/stop uses the separate source fences and never calls this check.
func (b *LocalBoundary) verifyFacts(f identity.AdmissionFacts) error {
	if f.Caller.VerifyAuthenticatedDigest(f.OriginalDigest, b.root.Namespace) != nil || f.Caller.PrincipalView() != f.OriginalCaller || sha256.Sum256(f.OriginalBytes) != f.OriginalDigest || sha256.Sum256(f.FinalizedBytes) != f.FinalizedDigest {
		return localDenied()
	}
	if _, err := f.Caller.DecodeVerifiedEnvelope(f.OriginalBytes, b.root.Namespace); err != nil {
		return err
	}
	var env fabric.Envelope
	if fabric.DecodeJSON(f.FinalizedBytes, &env) != nil || env.Validate() != nil || env.Operation != fabric.OperationInvoke || env.Target == nil || *env.Target != f.Target || env.ExpectedRevision != f.TargetRevision || env.Target.Endpoint() != f.Scope.Endpoint || env.ID != f.InvocationID || env.Principal != f.OriginalCaller {
		return localDenied()
	}
	if env.Context.Deadline != nil && !time.Now().Before(*env.Context.Deadline) {
		return fabric.NewError(fabric.CodeDeadlineExceeded, "Final local invocation expired")
	}
	return nil
}
func (b *LocalBoundary) verifySource(f identity.AdmissionFacts) error {
	s := f.Source
	if s == nil || s.Scope != f.Scope || s.Target != f.Target || s.TargetRevision != f.TargetRevision || s.OriginalCaller != f.OriginalCaller || s.OriginalDigest != f.OriginalDigest || s.FinalizedDigest != f.FinalizedDigest || s.InvocationID != f.InvocationID || s.Proof.Retired || s.Proof.Key.Kind != registry.AuthorityAdmission || s.Proof.Key.Endpoint != s.Scope.Endpoint || s.Proof.Key.ID != s.ID || registry.VerifyAuthorityRecord(b.root, s.Proof) != nil {
		return localDenied()
	}
	var signed identity.Admission
	if fabric.DecodeJSON(s.Proof.Value, &signed) != nil {
		return localDenied()
	}
	signed.Proof = s.Proof
	expected, _ := json.Marshal(s)
	actual, _ := json.Marshal(signed)
	if !bytes.Equal(expected, actual) {
		return localDenied()
	}
	return nil
}
func (b *LocalBoundary) WithAdmission(ctx context.Context, f identity.AdmissionFacts, next func(identity.Witness) error) error {
	if b != nil && next != nil {
		originalNext := next
		next = func(w identity.Witness) error { return b.selectedPlanWitness(ctx, f.Source, w, originalNext) }
	}
	if b == nil || next == nil {
		return localDenied()
	}
	if err := b.verifyFacts(f); err != nil {
		return err
	}
	run := func(context.Context) error {
		return next(identity.Witness{Version: "pagnet.local-boundary.v1", FinalizedDigest: f.FinalizedDigest, Value: json.RawMessage(`{"boundary":"local-installation"}`)})
	}
	switch f.Purpose {
	case identity.PurposeInvokeAdmission:
		caller, original, final, ok := node.FinalizedRequestFromContext(ctx)
		if !ok || caller.PrincipalView() != f.OriginalCaller || !bytes.Equal(original, f.OriginalBytes) || !bytes.Equal(final, f.FinalizedBytes) || caller.VerifyAuthenticatedDigest(f.OriginalDigest, b.root.Namespace) != nil || f.Source != nil {
			return localDenied()
		}
		return b.dispatchCallerFacts(ctx, f.Caller, func(current context.Context, facts fabricauth.CurrentCallerFacts) error {
			if resume, ok := b.resumeBinding(f.Caller); ok {
				w := resume.witness(facts)
				w.Version = "pagnet.local-boundary.resume.v1"
				w.FinalizedDigest = f.FinalizedDigest
				w.Value = json.RawMessage(`{"boundary":"local-continuation"}`)
				return next(w)
			}
			b.mu.RLock()
			association := b.sessions
			b.mu.RUnlock()
			w := identity.Witness{CurrentCallerOpen: func() bool { return association != nil && association.AssociationOpen(f.Caller) }, Version: "pagnet.local-boundary.v1", FinalizedDigest: f.FinalizedDigest, Value: json.RawMessage(`{"boundary":"local-installation"}`)}
			if facts.Managed != nil {
				authority := facts.Managed.Authority
				w.CurrentCallerKind = "local-peer.managed"
				w.CurrentCallerAuthority = &authority
			} else {
				if facts.Principal != b.root.Owner {
					return localDenied()
				}
				w.CurrentCallerKind = "local-peer.owner"
			}
			return next(w)
		})
	case identity.PurposeNativeReservation, identity.PurposeNativeIntent, identity.PurposeNativeOrigin:
		if b.verifySource(f) != nil {
			return localDenied()
		}
		// Exact retained source is rechecked by the authority inside its target
		// transaction. This explicit installation guard permits original-A recovery;
		// it does not authenticate the historical context as a current peer.
		return b.operatorCurrent(ctx, b.owner, run)
	default:
		return localDenied()
	}
}

func (b *LocalBoundary) WithDispatch(ctx context.Context, caller fabric.ExecutionContext, original, final []byte, endpoint fabric.EndpointDescriptor, offer *fabric.OfferDescriptor, selection dispatch.Selection, next func(context.Context) (fabric.InvocationStream, error)) (stream fabric.InvocationStream, err error) {
	actual, raw, transformed, ok := node.FinalizedRequestFromContext(ctx)
	if b == nil || !ok || next == nil || !bytes.Equal(raw, original) || !bytes.Equal(transformed, final) || actual.PrincipalView() != caller.PrincipalView() || actual.VerifyAuthenticatedData(original, b.root.Namespace) != nil || caller.VerifyAuthenticatedData(original, b.root.Namespace) != nil {
		return nil, localDenied()
	}
	var env fabric.Envelope
	if fabric.DecodeJSON(final, &env) != nil || env.Validate() != nil || env.Operation != fabric.OperationInvoke || env.Target == nil || env.Target.Endpoint() != endpoint.Ref || endpoint.Ref.Domain() != b.root.Namespace || endpoint.Revision != selection.EndpointRevision || selection.Adapter == nil || selection.Fingerprint == ([32]byte{}) {
		return nil, localDenied()
	}
	if env.Target.IsOffer() {
		if offer == nil || offer.Ref != *env.Target || offer.Revision != env.ExpectedRevision || offer.BindingID != selection.BindingID {
			return nil, localDenied()
		}
	} else if offer != nil || env.ExpectedRevision != endpoint.Revision {
		return nil, localDenied()
	}
	published := false
	for _, binding := range endpoint.Bindings {
		published = published || binding.ID == selection.BindingID
	}
	if !published {
		return nil, localDenied()
	}
	err = b.dispatchCallerFacts(ctx, caller, func(current context.Context, facts fabricauth.CurrentCallerFacts) error {
		// Refresh actual current descriptors before handing off. The adapter's SAME
		// transaction is the effect authority; no provider call runs under this read.
		currentEndpoint, e := b.store.GetEndpoint(current, endpoint.Ref, endpoint.Revision)
		if e != nil {
			return e
		}
		if currentEndpoint.Ref != endpoint.Ref {
			return localDenied()
		}
		if offer != nil {
			currentOffer, e := b.store.GetOffer(current, offer.Ref, offer.Revision)
			if e != nil {
				return e
			}
			if currentOffer.BindingID != selection.BindingID {
				return localDenied()
			}
		}
		b.mu.RLock()
		association := b.sessions
		b.mu.RUnlock()
		stamp := dispatchStamp{association: association, authenticatedCaller: caller, boundary: b, caller: caller.PrincipalView(), originalSHA: sha256.Sum256(original), finalizedSHA: sha256.Sum256(final), inputSHA: sha256.Sum256(env.Payload), invocationID: env.ID, target: *env.Target, revision: env.ExpectedRevision, scope: registry.DescriptorBatchScope{Endpoint: endpoint.Ref, ExpectedEndpointRevision: endpoint.Revision, BindingID: selection.BindingID}, fingerprint: selection.Fingerprint}
		if resume, ok := b.resumeBinding(caller); ok {
			stamp.resume = resume
			stamp.authenticatedCaller = resume.resumer
		}
		for _, binding := range endpoint.Bindings {
			if binding.ID == selection.BindingID && binding.Protocol == "a2a.jsonrpc" {
				var input a2a.Input
				if fabric.DecodeJSON(env.Payload, &input) == nil && (input.Operation == "get" || input.Operation == "cancel" || input.Operation == "subscribe") {
					stamp.associationInvocation = input.AssociationInvocation
				}
			}
		}
		if facts.Managed != nil {
			f := facts.Managed.Authority
			stamp.managed = &f
		} else if facts.Principal != b.root.Owner {
			return localDenied()
		}
		stream, e = next(context.WithValue(ctx, dispatchStampKey{}, &stamp))
		return e
	})
	return stream, err
}

func (b *LocalBoundary) WithNativeControl(ctx context.Context, f identity.NativeControlFacts, next func() error) error {
	if b == nil || next == nil || f.Owner != b.root.Owner || f.Scope.Endpoint.Domain() != b.root.Namespace || f.Controller.Scope != f.Scope || f.Binding.Scope != f.Scope {
		return localDenied()
	}
	return b.operatorCurrent(ctx, b.owner, func(context.Context) error { return next() })
}
func (b *LocalBoundary) WithHistoricalNativeOrigin(ctx context.Context, f identity.HistoricalNativeOriginFacts, next func(identity.Witness) error) error {
	if b != nil && next != nil {
		originalNext := next
		next = func(w identity.Witness) error { return b.selectedPlanWitness(ctx, &f.Admission, w, originalNext) }
	}
	if b == nil || next == nil || f.Current.Owner != b.root.Owner || b.verifyFacts(f.Original) != nil || b.verifySource(f.Original) != nil || f.Admission.ID != f.Original.Source.ID {
		return localDenied()
	}
	return b.operatorCurrent(ctx, b.owner, func(context.Context) error {
		return next(identity.Witness{Version: "pagnet.local-boundary.history.v1", FinalizedDigest: f.Original.FinalizedDigest, Value: json.RawMessage(`{}`)})
	})
}
func (b *LocalBoundary) currentSourceCaller(ctx context.Context, caller fabric.ExecutionContext, next func(context.Context) error) error {
	if resume, ok := b.resumeBinding(caller); ok {
		return b.callerCurrent(ctx, resume.resumer, next)
	}
	b.mu.RLock()
	sessions := b.sessions
	b.mu.RUnlock()
	if sessions != nil && sessions.RecognizesCurrentCaller(caller) {
		return b.callerCurrent(ctx, caller, next)
	}
	return b.operatorCurrent(ctx, caller, next)
}
func (b *LocalBoundary) WithNativeSourceRead(ctx context.Context, f identity.NativeSourceReadFacts, next func() error) error {
	if resume, ok := b.resumeBinding(f.CurrentCaller); ok && sha256.Sum256(resume.originalBytes) != f.Admission.OriginalDigest {
		return localDenied()
	}
	if b == nil || next == nil || f.Owner != b.root.Owner || f.CurrentCaller.PrincipalView() != f.Caller || (f.Caller != f.Admission.OriginalCaller && f.Caller != b.root.Owner) || (f.Operation != identity.NativeSourcePage && f.Operation != identity.NativeSourceAck) {
		return localDenied()
	}
	return b.currentSourceCaller(ctx, f.CurrentCaller, func(context.Context) error { return next() })
}
func (b *LocalBoundary) WithNativeCancellation(ctx context.Context, f identity.NativeCancellationFacts, next func() error) error {
	if resume, ok := b.resumeBinding(f.CurrentCaller); ok && sha256.Sum256(resume.originalBytes) != f.Admission.OriginalDigest {
		return localDenied()
	}
	if b == nil || next == nil || f.Owner != b.root.Owner || f.CurrentCaller.PrincipalView() != f.Caller || (f.Caller != f.Admission.OriginalCaller && f.Caller != b.root.Owner) {
		return localDenied()
	}
	return b.currentSourceCaller(ctx, f.CurrentCaller, func(context.Context) error { return next() })
}

func (b *LocalBoundary) callerFacts(ctx context.Context, caller fabric.ExecutionContext, next func(context.Context, fabricauth.CurrentCallerFacts) error) error {
	if b.currentRoot(ctx) != nil {
		return localDenied()
	}
	b.mu.RLock()
	sessions := b.sessions
	b.mu.RUnlock()
	if sessions == nil {
		return localDenied()
	}
	lifetime, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	return guardedBoundary(lifetime, func(c context.Context, n func(context.Context) error) error {
		return sessions.WithCurrentFacts(c, caller, func(current context.Context, facts fabricauth.CurrentCallerFacts) error {
			return n(context.WithValue(current, currentFactsKey{}, facts))
		})
	}, func(c context.Context) error {
		facts, ok := c.Value(currentFactsKey{}).(fabricauth.CurrentCallerFacts)
		if !ok {
			return localDenied()
		}
		return next(c, facts)
	})
}

type currentFactsKey struct{}

// CurrentNativeCallerWitness runs only before destination SQL. Protected
// installation callers are verified by their purpose-specific operator fence,
// never relabelled as current peer contexts.
func (b *LocalBoundary) CurrentNativeCallerWitness(ctx context.Context, caller fabric.ExecutionContext) (identity.Witness, error) {
	if b == nil {
		return identity.Witness{}, localDenied()
	}
	if resume, ok := b.resumeBinding(caller); ok {
		var witness identity.Witness
		err := b.callerFacts(ctx, resume.resumer, func(_ context.Context, facts fabricauth.CurrentCallerFacts) error {
			witness = resume.witness(facts)
			return nil
		})
		return witness, err
	}
	b.mu.RLock()
	association := b.sessions
	b.mu.RUnlock()
	if association == nil {
		return identity.Witness{}, localDenied()
	}
	if !association.RecognizesCurrentCaller(caller) {
		return identity.Witness{}, nil
	}
	var witness identity.Witness
	err := b.callerFacts(ctx, caller, func(c context.Context, facts fabricauth.CurrentCallerFacts) error {
		witness.CurrentCallerOpen = func() bool { return association.AssociationOpen(caller) }
		if facts.Managed != nil {
			authority := facts.Managed.Authority
			witness.CurrentCallerKind = "local-peer.managed"
			witness.CurrentCallerAuthority = &authority
		} else {
			if facts.Principal != b.root.Owner {
				return localDenied()
			}
			witness.CurrentCallerKind = "local-peer.owner"
		}
		return nil
	})
	return witness, err
}
