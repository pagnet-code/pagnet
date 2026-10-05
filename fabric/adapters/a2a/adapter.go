package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/pagnet-code/pagnet/fabric"
)

type Adapter struct {
	config         Config
	binding        string
	card           *sdk.AgentCard
	baseClient     http.Client
	ownedTransport *http.Transport
	lifetime       context.Context
	shutdown       context.CancelFunc
}

var _ fabric.EndpointAdapter = (*Adapter)(nil)

func failure(code fabric.ErrorCode, effect fabric.EffectState) *fabric.Error {
	return &fabric.Error{Code: code, Message: "A2A selected binding operation failed", Effect: effect}
}
func New(c Config) (*Adapter, error) {
	if _, e := fabric.ParseEndpointRef(c.Ref.String()); e != nil {
		return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	if c.BindingDigest == ([32]byte{}) || c.Revision == "" || len(c.Revision) > 256 || c.BindingID == "" || len(c.BindingID) > 256 || c.Audience == "" || c.Card == nil || c.Credentials == nil || c.DisclosureGate == nil || c.Associations == nil || c.Interface.ProtocolVersion != sdk.Version || c.Interface.ProtocolBinding != sdk.TransportProtocolJSONRPC {
		return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	if c.RootIdempotency {
		store, ok := c.Associations.(RootIdempotencyStore)
		if !ok || !store.SupportsRootIdempotency() {
			return nil, failure(fabric.CodeUnsupported, fabric.EffectNotStarted)
		}
	}
	if c.Associations.Scope().Audience != c.Audience || c.Associations.Scope().Domain == "" || c.Associations.Scope().ID == "" {
		return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	u, e := url.Parse(c.Interface.URL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) && !c.AllowHTTP {
		return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	selected := false
	for _, endpoint := range c.Card.SupportedInterfaces {
		if endpoint != nil && *endpoint == c.Interface {
			selected = true
		}
	}
	if !selected {
		return nil, failure(fabric.CodeUnsupported, fabric.EffectNotStarted)
	}
	if c.Limits.MaxEventBytes == 0 {
		c.Limits.MaxEventBytes = 64 << 10
	}
	if c.Limits.MaxRequestBytes == 0 {
		c.Limits.MaxRequestBytes = 64 << 10
	}
	if c.Limits.MaxStreamBytes == 0 {
		c.Limits.MaxStreamBytes = 16 << 20
	}
	if c.Limits.Lifetime == 0 {
		c.Limits.Lifetime = time.Minute
	}
	if c.Limits.MaxEventBytes < 1024 || c.Limits.MaxEventBytes > 1<<20 || c.Limits.MaxRequestBytes < 1024 || c.Limits.MaxRequestBytes > 1<<20 || c.Limits.MaxStreamBytes < int64(c.Limits.MaxEventBytes) || c.Limits.MaxStreamBytes > 256<<20 || c.Limits.Lifetime < time.Second || c.Limits.Lifetime > 10*time.Minute {
		return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	raw, e := json.Marshal(c.Card)
	if e != nil || len(raw) > 1<<20 {
		return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	var card sdk.AgentCard
	if json.Unmarshal(raw, &card) != nil {
		return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	endpoint := c.Interface
	card.SupportedInterfaces = []*sdk.AgentInterface{&endpoint}
	c.Card = nil
	bindingRaw, _ := json.Marshal(struct {
		Ref          fabric.EndpointRef
		Revision     fabric.Revision
		ID           string
		Interface    sdk.AgentInterface
		Cancellation bool
		Profile      [32]byte
	}{c.Ref, c.Revision, c.BindingID, c.Interface, c.Cancellation, c.BindingDigest})
	base, owned, e := transportClient(c.HTTPClient, c.Limits.Lifetime)
	if e != nil {
		return nil, e
	}
	c.HTTPClient = nil
	root, shutdown := context.WithCancel(context.Background())
	return &Adapter{config: c, binding: sum(bindingRaw), card: &card, baseClient: base, ownedTransport: owned, lifetime: root, shutdown: shutdown}, nil
}
func (a *Adapter) validate(caller fabric.ExecutionContext, d fabric.EndpointDescriptor, r fabric.InvokeRequest) error {
	if caller.VerifyAuthenticated(a.config.Audience) != nil || d.Ref != a.config.Ref || d.Revision != a.config.Revision || r.Target != a.config.Ref || r.ExpectedRevision != a.config.Revision || r.InvocationID == "" || len(r.InvocationID) > 256 || len(r.IdempotencyKey) > 256 || (r.IdempotencyKey != "" && !a.config.RootIdempotency) {
		return failure(fabric.CodeStaleReference, fabric.EffectNotStarted)
	}
	for _, b := range d.Bindings {
		if b.ID == a.config.BindingID && b.Protocol == "a2a.jsonrpc" && b.Version == string(sdk.Version) && b.Streaming == a.card.Capabilities.Streaming && b.Cancellation == a.config.Cancellation && b.Idempotency == a.config.RootIdempotency {
			return nil
		}
	}
	return failure(fabric.CodeStaleReference, fabric.EffectNotStarted)
}
func messageIdentity(binding string, principal fabric.Principal, invocation string) string {
	raw, _ := json.Marshal(struct {
		Binding      string
		Principal    fabric.Principal
		InvocationID string
	}{binding, principal, invocation})
	return "pagnet-" + sum(raw)
}
func (a *Adapter) key(caller fabric.ExecutionContext, id string) AssociationKey {
	return AssociationKey{caller.PrincipalView(), a.config.Ref, a.config.Revision, a.binding, id, a.config.Audience}
}
func (a *Adapter) Invoke(ctx context.Context, caller fabric.ExecutionContext, d fabric.EndpointDescriptor, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	if ctx == nil {
		return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	if a.lifetime.Err() != nil {
		return nil, failure(fabric.CodeTargetUnavailable, fabric.EffectNotStarted)
	}
	if ctx.Err() != nil {
		return nil, failure(fabric.CodeCancelled, fabric.EffectNotStarted)
	}
	if r.Deadline != nil && !r.Deadline.After(time.Now()) {
		return nil, failure(fabric.CodeDeadlineExceeded, fabric.EffectNotStarted)
	}
	if e := a.validate(caller, d, r); e != nil {
		return nil, e
	}
	if len(r.Input) > a.config.Limits.MaxRequestBytes {
		return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	var input Input
	if fabric.DecodeJSON(r.Input, &input) != nil {
		return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	switch input.Operation {
	case "send":
		if input.AssociationInvocation != "" || (input.Mode != "unary" && input.Mode != "stream") || len(input.Parts) == 0 || len(input.Parts) > 64 {
			return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
		}
	case "subscribe", "get", "cancel":
		if input.AssociationInvocation == "" || len(input.AssociationInvocation) > 256 || len(input.Parts) > 0 || input.Mode != "" {
			return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
		}
	default:
		return nil, failure(fabric.CodeUnsupported, fabric.EffectNotStarted)
	}
	if input.Operation == "cancel" && !a.config.Cancellation {
		return nil, failure(fabric.CodeUnsupported, fabric.EffectNotStarted)
	}
	if (input.Mode == "stream" || input.Operation == "subscribe") && !a.card.Capabilities.Streaming {
		return nil, failure(fabric.CodeUnsupported, fabric.EffectNotStarted)
	}
	parts := sdk.ContentParts{}
	for _, p := range input.Parts {
		if (p.Text != nil) == (len(p.Data) > 0) {
			return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
		}
		if p.Text != nil {
			parts = append(parts, sdk.NewTextPart(*p.Text))
		} else {
			var value any
			if fabric.DecodeJSON(p.Data, &value) != nil {
				return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
			}
			parts = append(parts, sdk.NewDataPart(append(json.RawMessage(nil), p.Data...)))
		}
	}
	var association Association
	if input.Operation != "send" {
		var e error
		association, e = a.config.Associations.Lookup(ctx, a.key(caller, input.AssociationInvocation))
		if e != nil || association.TaskID == "" || association.ContextID == "" {
			return nil, failure(fabric.CodeUnauthenticated, fabric.EffectNotStarted)
		}
	}
	if e := a.config.DisclosureGate(ctx, caller, d, r); e != nil {
		return nil, failure(fabric.CodeInterceptorRejected, fabric.EffectNotStarted)
	}
	headers, e := a.config.Credentials(ctx, caller, a.config.Interface)
	if e != nil {
		return nil, failure(fabric.CodeUnauthenticated, fabric.EffectNotStarted)
	}
	canonicalHeaders := http.Header{}
	for key, values := range headers {
		canonical := http.CanonicalHeaderKey(key)
		if (canonical != "Authorization" && canonical != "X-Api-Key") || len(values) != 1 {
			return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
		}
		if _, duplicate := canonicalHeaders[canonical]; duplicate {
			return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
		}
		canonicalHeaders[canonical] = append([]string(nil), values...)
		for _, value := range values {
			if len(value) > 8192 || strings.ContainsAny(value, "\r\n\x00") {
				return nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
			}
		}
	}
	life, cancel := context.WithTimeout(ctx, a.config.Limits.Lifetime)
	if r.Deadline != nil {
		var c context.CancelFunc
		life, c = context.WithDeadline(life, *r.Deadline)
		previous := cancel
		cancel = func() { c(); previous() }
	}
	parentCancel := cancel
	stopRoot := context.AfterFunc(a.lifetime, parentCancel)
	cancel = func() { stopRoot(); parentCancel() }
	tap := &rawTap{max: a.config.Limits.MaxEventBytes}
	client, e := a.httpClient(tap, canonicalHeaders)
	if e != nil {
		cancel()
		return nil, e
	}
	selected, e := a2aclient.NewFromCard(life, a.card, a2aclient.WithDefaultsDisabled(), a2aclient.WithJSONRPCTransport(client), a2aclient.WithConfig(a2aclient.Config{DisableTenantPropagation: true}))
	if e != nil {
		cancel()
		return nil, failure(fabric.CodeTargetUnavailable, fabric.EffectNotStarted)
	}
	key := a.key(caller, r.InvocationID)
	if e = a.config.Associations.Admit(life, Association{Key: key, InputSHA: sum(r.Input), Operation: input.Operation, Mode: input.Mode}); e != nil {
		cancel()
		if errors.Is(e, ErrAttempted) {
			return nil, failure("a2a.REPLAY_REFUSED", fabric.EffectUnknown)
		}
		return nil, failure("a2a.ASSOCIATION_FAILED", fabric.EffectNotStarted)
	}
	var events iter.Seq2[sdk.Event, error]
	switch input.Operation {
	case "send":
		message := sdk.NewMessage(sdk.MessageRoleUser, parts...)
		message.ID = messageIdentity(a.binding, caller.PrincipalView(), r.InvocationID)
		zero := 0
		req := &sdk.SendMessageRequest{Message: message, Config: &sdk.SendMessageConfig{HistoryLength: &zero}}
		if input.Mode == "stream" {
			events = selected.SendStreamingMessage(life, req)
		} else {
			events = func(yield func(sdk.Event, error) bool) {
				result, e := selected.SendMessage(life, req)
				if e != nil {
					yield(nil, e)
					return
				}
				yield(result, nil)
			}
		}
	case "subscribe":
		events = selected.SubscribeToTask(life, &sdk.SubscribeToTaskRequest{ID: sdk.TaskID(association.TaskID)})
	case "get":
		events = func(yield func(sdk.Event, error) bool) {
			zero := 0
			task, e := selected.GetTask(life, &sdk.GetTaskRequest{ID: sdk.TaskID(association.TaskID), HistoryLength: &zero})
			yield(task, e)
		}
	case "cancel":
		events = func(yield func(sdk.Event, error) bool) {
			task, e := selected.CancelTask(life, &sdk.CancelTaskRequest{ID: sdk.TaskID(association.TaskID)})
			yield(task, e)
		}
	}
	next, stop := iter.Pull2(events)
	return &stream{id: r.InvocationID, ctx: life, cancel: cancel, next: next, stop: stop, tap: tap, store: a.config.Associations, key: key, operation: input.Operation, expected: association}, nil
}

type boundTransport struct {
	base     http.RoundTripper
	tap      *rawTap
	headers  http.Header
	limits   Limits
	endpoint string
}

func (t *boundTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() != t.endpoint || r.Method != http.MethodPost {
		return nil, errors.New("selected A2A transport authority mismatch")
	}
	defer r.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(r.Body, int64(t.limits.MaxRequestBytes)+4097))
	if e != nil || len(raw) > t.limits.MaxRequestBytes+4096 {
		return nil, errBound
	}
	var request struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(raw, &request) != nil || len(request.ID) == 0 {
		return nil, ErrAssociation
	}
	t.tap.id = append(json.RawMessage(nil), request.ID...)
	clone := r.Clone(r.Context())
	clone.Body = io.NopCloser(bytes.NewReader(raw))
	clone.GetBody = nil
	clone.Header = r.Header.Clone()
	for k, vs := range t.headers {
		clone.Header[k] = append([]string(nil), vs...)
	}
	response, e := t.base.RoundTrip(clone)
	if e != nil {
		return nil, e
	}
	if response.StatusCode == http.StatusOK && strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		response.Body = &boundedBody{source: response.Body, tap: t.tap, max: t.limits.MaxEventBytes, budget: t.limits.MaxStreamBytes}
	} else {
		// Validate the complete bounded unary document before the SDK decoder can
		// stop at its first value. A valid prefix never permits trailing data.
		bound := int64(t.limits.MaxEventBytes) + 1024
		if t.limits.MaxStreamBytes < bound {
			bound = t.limits.MaxStreamBytes
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, bound+1))
		closeErr := response.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if int64(len(raw)) > bound {
			return nil, errBound
		}
		if response.StatusCode == http.StatusOK {
			if e := t.tap.push(raw); e != nil {
				return nil, e
			}
		}
		response.Body = io.NopCloser(bytes.NewReader(raw))
		response.ContentLength = int64(len(raw))
	}
	return response, nil
}
func (a *Adapter) httpClient(tap *rawTap, headers http.Header) (*http.Client, error) {
	c := a.baseClient
	base := c.Transport
	c.Transport = &boundTransport{base, tap, headers.Clone(), a.config.Limits, a.config.Interface.URL}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("A2A redirects disabled") }
	return &c, nil
}

func transportClient(selected *http.Client, lifetime time.Duration) (http.Client, *http.Transport, error) {
	c := http.Client{}
	if selected != nil {
		c = *selected
	}
	if c.Timeout < 0 {
		return c, nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
	}
	if c.Timeout == 0 {
		c.Timeout = lifetime
	}
	var owned *http.Transport
	if c.Transport == nil {
		stock, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return c, nil, failure(fabric.CodeInvalidInput, fabric.EffectNotStarted)
		}
		owned = stock.Clone()
		owned.Proxy = nil
		owned.MaxIdleConns = 32
		owned.MaxIdleConnsPerHost = 8
		owned.MaxConnsPerHost = 16
		owned.MaxResponseHeaderBytes = 64 << 10
		owned.ResponseHeaderTimeout = 15 * time.Second
		owned.IdleConnTimeout = 90 * time.Second
		c.Transport = owned
	}
	return c, owned, nil
}
func (a *Adapter) Close() error {
	a.shutdown()
	if a.ownedTransport != nil {
		a.ownedTransport.CloseIdleConnections()
	}
	return nil
}
