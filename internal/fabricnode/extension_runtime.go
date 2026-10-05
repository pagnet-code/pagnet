package fabricnode

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/node/continuations"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

type ExtensionRuntimeConfig struct {
	// Lifetime is the owned installed server lifetime, not startup/request timeout.
	Lifetime         context.Context
	Credentials      extension.CredentialProvider
	Bindings         dispatch.BindingResolver
	ResolvePrincipal continuations.PrincipalResolver
	VerifyEvidence   continuations.EvidenceValidator
	// Optional explicit destination authority composition; local defaults use
	// the genuine bound kernel/resumer path. Remote evidence is never local owner.
	CurrentCaller func(context.Context, fabric.ExecutionContext, func(context.Context) error) error
}
type extensionRuntimeBundle struct {
	selected   *extensionPlanSelection
	engine     *extension.Engine
	recorder   *continuations.Recorder
	handlers   []*extension.HTTPHandler
	references int
}

// ExtensionRuntime owns only configured providers and original stream lifetimes.
// It does not install software, manufacture callers, or execute setup effects.
type ExtensionRuntime struct {
	installation    *localinstallation.Installation
	boundary        *LocalBoundary
	infrastructure  *extensionInfrastructure
	config          ExtensionRuntimeConfig
	gate            *extensionPlanGate
	authority       *LocalContinuationAuthority
	notifications   *ExtensionNotifications
	bundle          atomic.Pointer[extensionRuntimeBundle]
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	reloadMu        sync.Mutex
	active          int
	closing, closed bool
	streams         map[*extensionRuntimeStream]struct{}
	bundles         []*extensionRuntimeBundle
	work            sync.WaitGroup
	providers       sync.WaitGroup
	closeAttempt    *extensionCloseAttempt
	changed         chan struct{}
}

// NewExtensionRuntime opens exact ready state; missing-all is explicitly
// disabled, while partial/corrupt state denies startup without repair.
func NewExtensionRuntime(ctx context.Context, i *localinstallation.Installation, b *LocalBoundary, c ExtensionRuntimeConfig) (*ExtensionRuntime, error) {
	if ctx == nil || i == nil || b == nil || b.store != i.Store {
		return nil, localDenied()
	}
	state, e := openExtensionInfrastructure(ctx, i)
	if e != nil || state == nil {
		return nil, e
	}
	cleanup := func() { state.Continuations.Close(); state.Registry.Close() }
	if c.Lifetime == nil || c.Lifetime.Err() != nil || c.Bindings == nil || b.planGate != nil {
		cleanup()
		return nil, localDenied()
	}
	lifetime, cancel := context.WithCancel(c.Lifetime)
	r := &ExtensionRuntime{installation: i, boundary: b, infrastructure: state, config: c, gate: &extensionPlanGate{registry: state.Registry}, ctx: lifetime, cancel: cancel, streams: map[*extensionRuntimeStream]struct{}{}, changed: make(chan struct{})}
	r.notifications, e = newExtensionNotifications(ctx, i, state.Continuations, b)
	if e != nil {
		cancel()
		cleanup()
		return nil, e
	}
	plans := func(context.Context) (continuations.ConfiguredPlan, error) {
		current := r.gate.current.Load()
		if current == nil {
			return continuations.ConfiguredPlan{}, localDenied()
		}
		return continuations.ConfiguredPlan{Plan: current.snapshot.Plan, Evidence: append([]byte(nil), current.snapshot.Evidence...)}, nil
	}
	r.authority, e = NewLocalContinuationAuthority(b, plans, state.Registry.VerifyConfiguredPlanTx)
	if e != nil {
		cancel()
		cleanup()
		return nil, e
	}
	if c.CurrentCaller == nil {
		r.config.CurrentCaller = func(current context.Context, caller fabric.ExecutionContext, next func(context.Context) error) error {
			return b.dispatchCallerFacts(current, caller, func(checked context.Context, _ fabricauth.CurrentCallerFacts) error { return next(checked) })
		}
	}
	if e = r.reload(ctx); e != nil {
		cancel()
		cleanup()
		return nil, e
	}
	// Private constructor publication precedes actual node/listener exposure.
	b.planGate = r.gate
	return r, nil
}

type extensionSelectedCredential struct {
	provider          extension.CredentialProvider
	binding, selector string
}

func (c extensionSelectedCredential) Authorization(ctx context.Context, binding string) (string, error) {
	if ctx == nil || ctx.Err() != nil || binding != c.binding {
		return "", localDenied()
	}
	if c.selector == "credentials.none" {
		return "", nil
	}
	if c.provider == nil {
		return "", fabric.NewError(fabric.CodeUnsupported, "Selected interceptor credential provider unavailable")
	}
	return c.provider.Authorization(ctx, c.selector)
}

type extensionOwnedHandler struct {
	runtime *ExtensionRuntime
	handler *extension.HTTPHandler
}

func (h extensionOwnedHandler) Intercept(ctx context.Context, request extension.InterceptRequest) (extension.Decision, error) {
	r := h.runtime
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return extension.Decision{}, localDenied()
	}
	r.providers.Add(1)
	r.mu.Unlock()
	defer r.providers.Done()
	return h.handler.Intercept(ctx, request)
}

func (r *ExtensionRuntime) reload(ctx context.Context) error {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	owner, e := r.installation.Operator(ctx)
	if e != nil {
		return e
	}
	if e = r.infrastructure.Registry.Reload(ctx, owner); e != nil {
		return e
	}
	snapshot, e := r.infrastructure.Registry.ConfiguredSnapshot()
	if e != nil {
		return e
	}
	selected := r.gate.selection(snapshot)
	registry := extension.NewHandlerRegistry()
	var handlers []*extension.HTTPHandler
	closeHandlers := func() {
		for _, h := range handlers {
			h.Close()
		}
	}
	seen := map[string]extregistry.Binding{}
	for cursor := ""; ; {
		page, e := r.infrastructure.Registry.List(ctx, owner, cursor, 64)
		if e != nil {
			closeHandlers()
			return e
		}
		for _, reference := range page.Entries {
			_, installation, e := r.infrastructure.Registry.Inspect(ctx, owner, reference.ID)
			if e != nil {
				closeHandlers()
				return e
			}
			for _, binding := range installation.Bindings {
				if prior, exists := seen[binding.ID]; exists {
					if prior != binding {
						closeHandlers()
						return localDenied()
					}
					continue
				}
				if binding.Protocol != extensionHTTPProtocol || (r.config.Credentials == nil && binding.Selector != "credentials.none") {
					closeHandlers()
					return fabric.NewError(fabric.CodeUnsupported, "Selected interceptor provider unavailable")
				}
				profile, e := r.infrastructure.Profiles.Get(ctx, binding.ProfileDigest)
				if e != nil || profile.Protocol != binding.Protocol || binding.Selector != profile.CredentialSelector {
					closeHandlers()
					return localDenied()
				}
				h, e := extension.NewHTTPHandler(profile.URL, binding.ID, extensionSelectedCredential{r.config.Credentials, binding.ID, profile.CredentialSelector}, profile.MaxConcurrency)
				if e != nil {
					closeHandlers()
					return e
				}
				handlers = append(handlers, h)
				seen[binding.ID] = binding
				if e = registry.Set(binding.ID, extensionOwnedHandler{r, h}); e != nil {
					closeHandlers()
					return e
				}
			}
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	// Publish exact configured selection for recorder construction. Existing
	// target transactions still verify the actual signed Root generation.
	previous := r.gate.current.Load()
	r.gate.current.Store(selected)
	planProvider := func(context.Context) (continuations.ConfiguredPlan, error) {
		current := r.gate.current.Load()
		if current == nil {
			return continuations.ConfiguredPlan{}, localDenied()
		}
		return continuations.ConfiguredPlan{Plan: current.snapshot.Plan, Evidence: append([]byte(nil), current.snapshot.Evidence...)}, nil
	}
	resolver := r.config.ResolvePrincipal
	if resolver == nil {
		resolver = func(_ context.Context, ref string) (fabric.Principal, error) {
			if ref != r.boundary.root.Owner.Ref {
				return fabric.Principal{}, localDenied()
			}
			return r.boundary.root.Owner, nil
		}
	}
	evidence := r.config.VerifyEvidence
	if evidence == nil {
		evidence = func(_ context.Context, _ fabric.ExecutionContext, proof continuations.Evidence) (continuation.Outcome, error) {
			effect := fabric.EffectUnknown
			if proof.Kind == continuations.NoTarget {
				effect = fabric.EffectNotStarted
			}
			return continuation.Outcome{Effect: effect, Data: []byte(`{}`)}, nil
		}
	}
	recorder, e := continuations.New(continuations.Config{Store: r.infrastructure.Continuations, Audience: r.boundary.root.Namespace, ConfiguredPlan: planProvider, SaveDeferredAdmission: r.authority.SaveDeferredAdmission, ResumeAuthority: r.authority.WithResume, ResolvePrincipal: resolver, RestoreOriginal: r.authority.RestoreOriginal, Notify: r.notifications.Publish, VerifyEvidence: evidence, SettlementTimeout: r.infrastructure.Settings.SettlementTimeout})
	if e != nil {
		r.gate.current.Store(previous)
		closeHandlers()
		return e
	}
	executor, e := extension.NewExecutor(r.infrastructure.Settings.ExecutorConcurrency)
	if e != nil {
		r.gate.current.Store(previous)
		closeHandlers()
		return e
	}
	engine, e := extension.NewEngine(snapshot.Plan, registry, executor, r.match, r.validateFinal, recorder, r.infrastructure.Settings.MaxRedirects)
	if e != nil {
		r.gate.current.Store(previous)
		closeHandlers()
		return e
	}
	newBundle := &extensionRuntimeBundle{selected: selected, engine: engine, recorder: recorder, handlers: handlers}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		closeHandlers()
		return localDenied()
	}
	r.bundles = append(r.bundles, newBundle)
	r.bundle.Store(newBundle)
	r.pruneBundlesLocked()
	return nil
}

func (r *ExtensionRuntime) current(ctx context.Context, caller fabric.ExecutionContext, next func(context.Context) error) error {
	return guardedBoundary(ctx, func(c context.Context, checked func(context.Context) error) error {
		return r.config.CurrentCaller(c, caller, checked)
	}, next)
}
func (r *ExtensionRuntime) match(ctx context.Context, caller fabric.ExecutionContext, envelope fabric.Envelope, stage string, placement extension.Placement) (extension.MatchContext, error) {
	result := extension.MatchContext{Operation: envelope.Operation, Stage: stage, Placement: placement, SourceKind: caller.PrincipalView().Kind, Domain: r.boundary.root.Namespace}
	e := r.current(ctx, caller, func(current context.Context) error {
		if envelope.Target == nil {
			return nil
		}
		endpoint, offer, e := r.selectedTarget(current, envelope)
		if e != nil {
			return e
		}
		result.TargetKind = endpoint.Kind
		if offer != nil {
			result.Tags = append([]string(nil), offer.Tags...)
		}
		selected, e := r.config.Bindings.Select(current, caller, endpoint, offer)
		if e != nil {
			return e
		}
		for _, binding := range endpoint.Bindings {
			if binding.ID == selected.BindingID {
				result.TargetProtocol = binding.Protocol
				return nil
			}
		}
		return localDenied()
	})
	return result, e
}
func (r *ExtensionRuntime) selectedTarget(ctx context.Context, envelope fabric.Envelope) (fabric.EndpointDescriptor, *fabric.OfferDescriptor, error) {
	if envelope.Target == nil || envelope.Target.Domain() != r.boundary.root.Namespace {
		return fabric.EndpointDescriptor{}, nil, localDenied()
	}
	if !envelope.Target.IsOffer() {
		endpoint, e := r.installation.Store.GetEndpoint(ctx, *envelope.Target, envelope.ExpectedRevision)
		return endpoint, nil, e
	}
	offer, e := r.installation.Store.GetOffer(ctx, *envelope.Target, envelope.ExpectedRevision)
	if e != nil {
		return fabric.EndpointDescriptor{}, nil, e
	}
	endpoint, e := r.installation.Store.GetEndpoint(ctx, envelope.Target.Endpoint(), "")
	return endpoint, &offer, e
}
func (r *ExtensionRuntime) validateFinal(ctx context.Context, caller fabric.ExecutionContext, envelope fabric.Envelope) error {
	return r.current(ctx, caller, func(c context.Context) error {
		selected, e := r.gate.fromContext(ctx)
		if e != nil {
			return e
		}
		if envelope.Operation == fabric.OperationInvoke {
			if _, _, e = r.selectedTarget(c, envelope); e != nil {
				return e
			}
		}
		return r.installation.Store.WithNativeAuthority(c, r.boundary.owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 2}, selected.verify)
	})
}

func (r *ExtensionRuntime) begin(ctx context.Context) (context.Context, func(), *extensionRuntimeBundle, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, nil, localDenied()
	}
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return nil, nil, nil, localDenied()
	}
	bundle := r.bundle.Load()
	if bundle == nil {
		r.mu.Unlock()
		return nil, nil, nil, localDenied()
	}
	if r.active >= r.infrastructure.Settings.MaxActiveInvocations {
		r.mu.Unlock()
		return nil, nil, nil, fabric.NewError(fabric.CodeTargetUnavailable, "Configured extension invocation capacity reached")
	}
	r.active++
	bundle.references++
	r.work.Add(1)
	r.mu.Unlock()
	owned, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	var once sync.Once
	release := func() {
		once.Do(func() {
			stop()
			cancel()
			r.mu.Lock()
			r.active--
			r.pulseLocked()
			bundle.references--
			r.pruneBundlesLocked()
			r.mu.Unlock()
			r.work.Done()
		})
	}
	return context.WithValue(owned, extensionPlanContextKey{}, bundle.selected), release, bundle, nil
}
func (r *ExtensionRuntime) ExecuteStage(ctx context.Context, caller fabric.ExecutionContext, original []byte, audience, stage string, placement extension.Placement, downstream extension.Downstream) (extension.Outcome, error) {
	owned, release, bundle, e := r.begin(ctx)
	if e != nil {
		return extension.Outcome{}, e
	}
	out, e := bundle.engine.ExecuteStage(owned, caller, original, audience, stage, placement, downstream)
	if e != nil || out.Stream == nil {
		release()
		return out, e
	}
	stream := &extensionRuntimeStream{runtime: r, upstream: out.Stream, release: release}
	r.mu.Lock()
	r.streams[stream] = struct{}{}
	r.pulseLocked()
	closing := r.closing
	r.mu.Unlock()
	if closing {
		stream.Close()
		return extension.Outcome{}, localDenied()
	}
	out.Stream = stream
	return out, nil
}

func (r *ExtensionRuntime) ExecuteReadProjection(ctx context.Context, caller fabric.ExecutionContext, original []byte, audience, stage string, placement extension.Placement, payload json.RawMessage, downstream extension.Downstream) (extension.Outcome, error) {
	owned, release, bundle, e := r.begin(ctx)
	if e != nil {
		return extension.Outcome{}, e
	}
	defer release()
	out, e := bundle.engine.ExecuteReadProjection(owned, caller, original, audience, stage, placement, payload, downstream)
	if out.Stream != nil {
		out.Stream.Close()
		return extension.Outcome{}, fabric.NewError(fabric.CodeProtocolError, "Read projection returned a stream")
	}
	return out, e
}

type extensionRuntimeStream struct {
	runtime  *ExtensionRuntime
	upstream fabric.InvocationStream
	release  func()
	once     sync.Once
	closeMu  sync.Mutex
	closed   bool
}

func (s *extensionRuntimeStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	f, e := s.upstream.Next(ctx)
	if errors.Is(e, io.EOF) || e == nil && (f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError) {
		s.finish()
	}
	return f, e
}
func (s *extensionRuntimeStream) finish() {
	s.once.Do(func() {
		s.runtime.mu.Lock()
		delete(s.runtime.streams, s)
		s.runtime.pulseLocked()
		s.runtime.mu.Unlock()
		s.release()
	})
}
func (s *extensionRuntimeStream) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return nil
	}
	if e := s.upstream.Close(); e != nil {
		return e
	}
	s.closed = true
	s.finish()
	return nil
}

func (s *extensionRuntimeStream) OriginalSourceOwnership(ctx context.Context) (fabric.OriginalSourceOwnership, error) {
	return fabric.OriginalStreamOwnership(ctx, s.upstream)
}
func (s *extensionRuntimeStream) WithOriginalCapture(ctx context.Context, next func(context.Context) error) error {
	return fabric.WithOriginalSourceCapture(ctx, s.upstream, next)
}

type extensionCloseAttempt struct {
	done chan struct{}
	err  error
}

func (r *ExtensionRuntime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return localDenied()
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	attempt := r.closeAttempt
	if attempt != nil {
		select {
		case <-attempt.done:
			if attempt.err != nil {
				attempt = nil
			}
		default:
		}
	}
	if attempt == nil {
		r.closing = true
		r.cancel()
		attempt = &extensionCloseAttempt{done: make(chan struct{})}
		r.closeAttempt = attempt
		go func() { attempt.err = r.finishClose(); close(attempt.done) }()
	}
	r.mu.Unlock()
	select {
	case <-attempt.done:
		return attempt.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *ExtensionRuntime) pulseLocked() { close(r.changed); r.changed = make(chan struct{}) }
func (r *ExtensionRuntime) finishClose() error {
	for {
		r.mu.Lock()
		active, changed := r.active, r.changed
		streams := make([]*extensionRuntimeStream, 0, len(r.streams))
		for stream := range r.streams {
			streams = append(streams, stream)
		}
		r.mu.Unlock()
		for _, stream := range streams {
			if e := stream.Close(); e != nil {
				return e
			}
		}
		if active == 0 {
			break
		}
		<-changed
	}

	r.work.Wait()
	r.providers.Wait()
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	for _, bundle := range r.bundles {
		for _, handler := range bundle.handlers {
			handler.Close()
		}
	}
	if e := r.infrastructure.Continuations.Close(); e != nil {
		return e
	}
	if e := r.infrastructure.Registry.Close(); e != nil {
		return e
	}
	r.closed = true
	return nil
}

func (r *ExtensionRuntime) pruneBundlesLocked() {
	current := r.bundle.Load()
	kept := r.bundles[:0]
	for _, bundle := range r.bundles {
		if bundle == current || bundle.references > 0 {
			kept = append(kept, bundle)
		} else {
			for _, handler := range bundle.handlers {
				handler.Close()
			}
		}
	}
	clear(r.bundles[len(kept):])
	r.bundles = kept
}
