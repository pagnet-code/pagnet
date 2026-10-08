package fabricnode

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	cevent "github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
	"github.com/pagnet-code/pagnet/fabric/events/actions"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// actionAuthenticator is the installed adapter association's trusted boundary.
// It authenticates ONLY the exact admitted action (carried as private peer
// evidence by the node adapter) against the store's current source/definition
// authority and retained lineage. A caller context or wire assertion never
// establishes this identity.
type actionAuthenticator struct {
	audience string
	store    *actions.Store // wired after the store opens
}

func (a *actionAuthenticator) Authenticate(ctx context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	grant, ok := r.PeerEvidence.(*actions.ActionGrant)
	if !ok || a == nil || a.store == nil || r.Audience != a.audience {
		return fabric.ExecutionContext{}, localDenied()
	}
	return a.store.AuthenticateAction(ctx, grant.Request.Action, grant.Request.Source, r.ExactEnvelope, r.Audience)
}

// actionNodeAdapter is the production AdapterInvoker: it drives the actual
// node.Service (authenticate + dispatch to the real registered binding) for the
// exact admitted action. A replayed (already-admitted) action never reaches it,
// so a paid operation is never re-dispatched. lostReply/providerCrash are
// trusted crash-test seams (false in production) that model a committed reply
// lost in transit or a provider crash AFTER the durable admission commit.
type actionNodeAdapter struct {
	service       *node.Service
	lostReply     atomic.Bool
	providerCrash atomic.Bool
}

func (a *actionNodeAdapter) Invoke(ctx context.Context, request actions.AdmissionRequest) (fabric.InvocationStream, error) {
	result, err := a.service.Execute(ctx, request.Action.ExactEnvelope, &actions.ActionGrant{Request: request})
	if err != nil {
		return nil, err
	}
	if result.Stream == nil {
		return nil, fabric.NewError(fabric.CodeProtocolError, "Action dispatch produced no invocation stream")
	}
	if a.lostReply.Load() {
		_ = result.Stream.Close()
		return nil, fabric.NewError(fabric.CodeTargetUnavailable, "Committed action reply lost in transit")
	}
	if a.providerCrash.Load() {
		_ = result.Stream.Close()
		panic("action provider crashed mid-admission")
	}
	return result.Stream, nil
}

// actionsBindingResolver keeps the node's own bindings primary and consults an
// explicit extension set only when the primary cannot serve the selected
// binding's protocol. The extension set is an explicit composition input, never
// discovery, and never grants authority the primary denied.
type actionsBindingResolver struct {
	primary dispatch.BindingResolver
	extra   dispatch.BindingResolver
}

func (a *actionsBindingResolver) Select(ctx context.Context, caller fabric.ExecutionContext, endpoint fabric.EndpointDescriptor, offer *fabric.OfferDescriptor) (dispatch.Selection, error) {
	sel, err := a.primary.Select(ctx, caller, endpoint, offer)
	if err == nil {
		return sel, nil
	}
	if a.extra != nil {
		var structured *fabric.Error
		if errors.As(err, &structured) && (structured.Code == fabric.CodeUnsupported || structured.Code == fabric.CodeTargetUnavailable) {
			if extraSel, extraErr := a.extra.Select(ctx, caller, endpoint, offer); extraErr == nil {
				return extraSel, nil
			}
		}
	}
	return sel, err
}

var _ dispatch.BindingResolver = (*actionsBindingResolver)(nil)

// actionDispatchAdmission is the installed actions runtime's dispatch admission
// boundary. The durable ACK is the Admitter's SignDispatchAdmission (the
// registry authority), committed before any adapter effect; this boundary
// fences the bounded invocation rather than re-deriving that ACK. It verifies
// the caller is the genuine authenticated forward context bound to this exact
// original envelope, that the selected binding is the one published for the
// current endpoint revision, and that the finalized invoke targets that
// endpoint. It never trusts a wire peer or caller assertion.
type actionDispatchAdmission struct{ namespace string }

func (a actionDispatchAdmission) WithDispatch(ctx context.Context, caller fabric.ExecutionContext, original, final []byte, endpoint fabric.EndpointDescriptor, offer *fabric.OfferDescriptor, selection dispatch.Selection, next func(context.Context) (fabric.InvocationStream, error)) (fabric.InvocationStream, error) {
	if a.namespace == "" || next == nil || selection.Adapter == nil || selection.Fingerprint == ([32]byte{}) || len(original) == 0 || caller.VerifyAuthenticatedData(original, a.namespace) != nil || selection.EndpointRevision != endpoint.Revision || endpoint.Ref.Domain() != a.namespace {
		return nil, localDenied()
	}
	var env fabric.Envelope
	if fabric.DecodeJSON(final, &env) != nil || env.Validate() != nil || env.Operation != fabric.OperationInvoke || env.Target == nil || env.Target.Endpoint() != endpoint.Ref || env.ID == "" {
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
		if binding.ID == selection.BindingID {
			published = true
			break
		}
	}
	if !published {
		return nil, localDenied()
	}
	return next(ctx)
}

var _ dispatch.Admission = actionDispatchAdmission{}

// registryTargetScopeResolver resolves an action's exact current native
// authority scope from the registry: the physical (non-offer) endpoint at its
// current descriptor revision and a published binding it actually advertises.
// It never trusts a caller assertion.
type registryTargetScopeResolver struct{ store *registry.Store }

func (r registryTargetScopeResolver) ResolveTargetScope(ctx context.Context, target fabric.EndpointRef, revision fabric.Revision) (actions.TargetScope, error) {
	if r.store == nil || ctx == nil {
		return actions.TargetScope{}, localDenied()
	}
	if target.IsOffer() {
		return actions.TargetScope{}, fabric.NewError(fabric.CodeInvalidInput, "Action targets resolve to physical endpoints only")
	}
	endpoint, err := r.store.GetEndpoint(ctx, target, revision)
	if err != nil || len(endpoint.Bindings) == 0 {
		return actions.TargetScope{}, fabric.NewError(fabric.CodeTargetUnavailable, "Action target binding is unavailable")
	}
	return actions.TargetScope{Endpoint: endpoint.Ref, EndpointRevision: endpoint.Revision, BindingID: endpoint.Bindings[0].ID}, nil
}

// actionsCronIssuer mints the exact signed schedule tick for the internal cron
// provider. It is a trusted infrastructure capability: the proof verifies
// against the store's retained SourceAuthority. The deterministic event
// identity (derived from the tick) makes an identical retry idempotent.
type actionsCronIssuer struct {
	principal fabric.Principal
	key       ed25519.PrivateKey
	typ       string
}

func (c *actionsCronIssuer) Issue(_ context.Context, at time.Time) (actions.SourceInput, error) {
	if c == nil || len(c.key) != ed25519.PrivateKeySize || c.typ == "" {
		return actions.SourceInput{}, localDenied()
	}
	e := cevent.New("1.0")
	e.SetID(fmt.Sprintf("pagnet.actions.cron.%s.%s", c.principal.Ref, at.UTC().Format(time.RFC3339Nano)))
	e.SetSource(c.principal.Ref)
	e.SetType(c.typ)
	e.SetTime(at)
	if err := e.SetData("application/json", json.RawMessage(fmt.Sprintf(`{"tick":%q}`, at.UTC().Format(time.RFC3339Nano)))); err != nil {
		return actions.SourceInput{}, localDenied()
	}
	raw, err := events.Encode(e, 1<<20)
	if err != nil {
		return actions.SourceInput{}, localDenied()
	}
	proof, err := json.Marshal(ed25519.Sign(c.key, raw))
	if err != nil {
		return actions.SourceInput{}, localDenied()
	}
	return actions.SourceInput{ExactEvent: raw, Proof: proof}, nil
}

// ActionsRuntime owns the installed actions admission: the durable store, the
// durable Admitter, the real adapter association (node.Service over the node's
// own dispatch), and the optional webhook/cron providers + worker loop. It
// opens when the installed node opens and is joined before the runtime/store.
type ActionsRuntime struct {
	Store     *actions.Store
	Admitter  *actions.DurableAdmitter
	Webhook   *actions.Webhook
	Cron      *actions.Cron
	Workers   *durable.Workers
	Adapter   *actionNodeAdapter
	audience  string
	webhookLn net.Listener
	closeMu   sync.Mutex
	closed    bool
}

// OpenActionsRuntime composes the installed actions runtime over the loaded
// installation and the node's real dispatch. It never bootstraps missing
// identity; it opens only current retained state. A missing all-missing
// configuration is disabled (returns nil, nil).
func OpenActionsRuntime(ctx context.Context, i *localinstallation.Installation, settings ActionsSettings, bindings dispatch.BindingResolver, sourceAuthorityWrapper func(actions.SourceAuthority) actions.SourceAuthority) (*ActionsRuntime, error) {
	if ctx == nil || i == nil || i.Store == nil || i.Keys == nil || settings.empty() {
		return nil, localDenied()
	}
	scope := actionsScope(i)
	producers := make(map[string]actions.ProducerIdentity, len(settings.Producers))
	for _, p := range settings.Producers {
		producers[p.Principal.Ref] = actions.ProducerIdentity{Principal: p.Principal, PublicKey: p.PublicKey}
	}
	var sourceAuthority actions.SourceAuthority
	var err error
	sourceAuthority, err = actions.NewEd25519SourceAuthority(scope.Audience, producers)
	if err != nil {
		return nil, err
	}
	if sourceAuthorityWrapper != nil {
		sourceAuthority = sourceAuthorityWrapper(sourceAuthority)
	}
	definitionAuthority, err := actions.NewEd25519DefinitionAuthority(settings.DefinitionPublicKey, nil)
	if err != nil {
		return nil, err
	}
	authorizer := actions.NewEnvelopeAuthorizer()
	// The real dispatch path: the node's own binding resolver (the real
	// registered endpoint + private adapter) fenced by the actions dispatch
	// admission, the same association the installed node uses for a direct
	// dispatch. The durable ACK is the Admitter's SignDispatchAdmission.
	dispatcher, err := dispatch.New(dispatch.Config{Audience: scope.Audience, Descriptors: i.Store, Bindings: bindings, Admission: actionDispatchAdmission{namespace: scope.Audience}})
	if err != nil {
		return nil, err
	}
	authenticator := &actionAuthenticator{audience: scope.Audience}
	service, err := node.New(node.Config{Audience: scope.Audience, Authenticator: authenticator, Dispatcher: dispatcher})
	if err != nil {
		return nil, err
	}
	adapter := &actionNodeAdapter{service: service}
	targets := registryTargetScopeResolver{store: i.Store}
	owner := func(ctx context.Context) (fabric.ExecutionContext, error) { return i.Operator(ctx) }
	admitter, err := actions.NewDurableAdmitter(i.Store, scope, owner, sourceAuthority, targets, adapter)
	if err != nil {
		return nil, err
	}
	dir, err := actionsDirectory(ctx, i)
	if err != nil {
		return nil, err
	}
	config := actions.DefaultConfig(scope)
	config.Definitions = append([]actions.TriggerDefinition(nil), settings.Definitions...)
	config.MaxDefinitions = settings.MaxDefinitions
	config.MaxFanout = settings.MaxFanout
	config.MaxProofBytes = settings.MaxProofBytes
	config.MaxEnvelopeBytes = settings.MaxEnvelopeBytes
	config.Queue = settings.Queue
	config.SourceAuthority = sourceAuthority
	config.DefinitionAuthority = definitionAuthority
	config.Authorizer = authorizer
	config.Admitter = admitter
	config.Protector = i.Keys
	store, err := actions.Open(ctx, dir, config)
	if err != nil {
		return nil, err
	}
	r := &ActionsRuntime{Store: store, Admitter: admitter, Adapter: adapter, audience: scope.Audience}
	defer func() {
		if err != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if closeErr := r.CloseContext(closeCtx); closeErr != nil {
				err = &ActionsRuntimeOpenError{cause: errors.Join(err, closeErr), retained: r}
			}
		}
	}()
	// The store now exists: the authenticator can verify against it.
	authenticator.store = store
	r.Workers, err = store.StartWorkers(ctx)
	if err != nil {
		return nil, err
	}
	if settings.Webhook != nil {
		w, e := actions.NewWebhook(actions.WebhookConfig{
			ID: settings.Webhook.ID, Mode: settings.Webhook.Mode, Target: settings.Webhook.Target, TargetRevision: settings.Webhook.TargetRevision,
			Store: store, MaxEventBytes: settings.Webhook.MaxEventBytes, MaxProofBytes: settings.Webhook.MaxProofBytes,
			Timeout: settings.Webhook.Timeout, MaxConcurrent: settings.Webhook.MaxConcurrent,
		})
		if e != nil {
			return nil, e
		}
		r.Webhook = w
	}
	if settings.Cron != nil {
		definitionType := ""
		for _, d := range settings.Definitions {
			if d.Source == settings.Cron.IssuerPrincipal.Ref {
				definitionType = d.Type
				break
			}
		}
		issuer := &actionsCronIssuer{principal: settings.Cron.IssuerPrincipal, key: settings.Cron.IssuerKey, typ: definitionType}
		c, e := actions.NewCron(actions.CronConfig{
			ID: settings.Cron.ID, Store: store, Mode: settings.Cron.Mode, Target: settings.Cron.Target, Revision: settings.Cron.Revision,
			Issuer: issuer, Interval: settings.Cron.Interval, Timeout: settings.Cron.Timeout,
		})
		if e != nil {
			return nil, e
		}
		c.Start(ctx)
		r.Cron = c
	}
	return r, nil
}

// openActionsStoreOnly opens (or bootstraps) the actions store with a genuine
// authority composition but NO Admitter, for explicit setup verification. It
// never starts workers or dispatches.
func openActionsStoreOnly(ctx context.Context, dir string, scope durable.Scope, s ActionsSettings, keys durable.DataProtector, create bool) (*actions.Store, error) {
	producers := make(map[string]actions.ProducerIdentity, len(s.Producers))
	for _, p := range s.Producers {
		producers[p.Principal.Ref] = actions.ProducerIdentity{Principal: p.Principal, PublicKey: p.PublicKey}
	}
	sourceAuthority, err := actions.NewEd25519SourceAuthority(scope.Audience, producers)
	if err != nil {
		return nil, err
	}
	definitionAuthority, err := actions.NewEd25519DefinitionAuthority(s.DefinitionPublicKey, nil)
	if err != nil {
		return nil, err
	}
	config := actions.DefaultConfig(scope)
	config.Definitions = append([]actions.TriggerDefinition(nil), s.Definitions...)
	config.MaxDefinitions = s.MaxDefinitions
	config.MaxFanout = s.MaxFanout
	config.MaxProofBytes = s.MaxProofBytes
	config.MaxEnvelopeBytes = s.MaxEnvelopeBytes
	config.Queue = s.Queue
	config.SourceAuthority = sourceAuthority
	config.DefinitionAuthority = definitionAuthority
	config.Authorizer = actions.NewEnvelopeAuthorizer()
	config.Protector = keys
	if create {
		return actions.Bootstrap(ctx, dir, config)
	}
	return actions.Open(ctx, dir, config)
}

type ActionsRuntimeOpenError struct {
	cause    error
	retained *ActionsRuntime
}

func (e *ActionsRuntimeOpenError) Error() string {
	return "Actions admission could not start; original resources remain held until cleanup completes"
}
func (e *ActionsRuntimeOpenError) Unwrap() error { return e.cause }
func (e *ActionsRuntimeOpenError) CloseContext(ctx context.Context) error {
	return e.retained.CloseContext(ctx)
}

// ServeWebhookContext serves the configured webhook on an explicit listener
// until the context ends. It is started by the daemon, not by OpenInstalled.
func (r *ActionsRuntime) ServeWebhookContext(ctx context.Context, ln net.Listener) error {
	if r == nil || r.Webhook == nil {
		return localDenied()
	}
	if ln == nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Missing webhook listener")
	}
	server := &http.Server{Handler: r.Webhook, ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		select {
		case e := <-errCh:
			return e
		case <-time.After(10 * time.Second):
			return nil
		}
	case e := <-errCh:
		return e
	}
}

func (r *ActionsRuntime) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return localDenied()
	}
	r.closeMu.Lock()
	defer r.closeMu.Unlock()
	if r.closed {
		return nil
	}
	if r.Webhook != nil {
		r.Webhook.Close()
	}
	if r.Cron != nil {
		r.Cron.Close()
	}
	if r.Workers != nil {
		if err := r.Workers.Close(ctx); err != nil {
			return err
		}
	}
	if r.Store != nil {
		if err := r.Store.CloseContext(ctx); err != nil {
			return err
		}
	}
	r.closed = true
	return nil
}
func (r *ActionsRuntime) Close() error { return r.CloseContext(context.Background()) }
