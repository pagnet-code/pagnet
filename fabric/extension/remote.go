package extension

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// Handler is an inline extension endpoint. Context cancellation is mandatory;
// the engine's bounded executor retains capacity until even a misbehaving local
// implementation returns. An extension cannot mutate a shared request object.
const MaxInterceptBytes = 1 << 20

type Handler interface {
	Intercept(context.Context, InterceptRequest) (Decision, error)
}

// CredentialProvider runs inside the trusted adapter boundary. Its value is
// used only as this binding's HTTP Authorization header, never in an envelope.
type CredentialProvider interface {
	Authorization(context.Context, string) (string, error)
}

type HTTPHandler struct {
	endpoint    string
	binding     string
	credentials CredentialProvider
	client      *http.Client
	capacity    chan struct{}
}

// NewHTTPHandler is an explicit operator-selected plaintext destination. It does
// not install software, discover destinations, follow redirects or inherit the
// user's browser/agent credentials. Pools are private and reused per binding.
func NewHTTPHandler(endpoint, binding string, credentials CredentialProvider, maxConcurrency int) (*HTTPHandler, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.RawQuery != "" || binding == "" || len(binding) > 256 || maxConcurrency < 1 || maxConcurrency > 4096 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid remote extension binding")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Environment proxy configuration is not implicit permission to disclose a
	// customer's private extension payload to a third-party proxy.
	transport.Proxy = nil
	transport.MaxConnsPerHost = maxConcurrency
	transport.MaxIdleConns = maxConcurrency
	transport.MaxIdleConnsPerHost = maxConcurrency
	transport.ResponseHeaderTimeout = time.Minute
	transport.MaxResponseHeaderBytes = 64 << 10
	return &HTTPHandler{endpoint: u.String(), binding: binding, credentials: credentials, capacity: make(chan struct{}, maxConcurrency), client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (h *HTTPHandler) Close() { h.client.CloseIdleConnections() }
func (h *HTTPHandler) Intercept(ctx context.Context, request InterceptRequest) (Decision, error) {
	if ctx == nil {
		return Decision{}, fabric.NewError(fabric.CodeInvalidInput, "Missing interceptor context")
	}
	failure := func() (Decision, error) {
		return Decision{}, fabric.NewError(fabric.CodeProtocolError, "Remote interceptor failed")
	}
	select {
	case h.capacity <- struct{}{}:
		defer func() { <-h.capacity }()
	case <-ctx.Done():
		return Decision{}, ctx.Err()
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > MaxInterceptBytes {
		return failure()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return failure()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if h.credentials != nil {
		value, err := h.credentials.Authorization(ctx, h.binding)
		if err != nil || len(value) > 16<<10 || strings.ContainsAny(value, "\r\n") {
			return failure()
		}
		if value != "" {
			req.Header.Set("Authorization", value)
		}
	}
	resp, err := h.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Decision{}, ctx.Err()
		}
		return failure()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > int64(MaxInterceptBytes) {
		return failure()
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(MaxInterceptBytes)+1))
	if err != nil || len(raw) > MaxInterceptBytes {
		return failure()
	}
	var decision Decision
	if fabric.DecodeJSON(raw, &decision) != nil {
		return failure()
	}
	return decision, nil
}

// Executor limits outstanding inline calls, including handlers which ignore
// cancellation. No unbounded timeout goroutines or queued payloads accumulate.
type Executor struct{ capacity chan struct{} }

func NewExecutor(maxConcurrency int) (*Executor, error) {
	if maxConcurrency < 1 || maxConcurrency > 65536 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid interceptor concurrency")
	}
	return &Executor{capacity: make(chan struct{}, maxConcurrency)}, nil
}
func (x *Executor) Call(ctx context.Context, registration CompiledRegistration, handler Handler, request InterceptRequest) (Decision, error) {
	if ctx == nil || x == nil || handler == nil || registration.Registration.TimeoutMillis == 0 {
		return Decision{}, invalidRegistration()
	}
	if registration.Registration.Placement == PlacementRelay {
		return Decision{}, fabric.NewError(fabric.CodeUnsupported, "Plaintext extension protocol cannot run on relay")
	}
	if request.InterceptorID != registration.Registration.ID || request.Operation != registration.Registration.Match.Operation || request.Stage != registration.Registration.Match.Stage || !containsPhase(registration.Registration.Phases, request.Phase) {
		return Decision{}, fabric.NewError(fabric.CodeProtocolError, "Interceptor request does not match registration")
	}
	lifetime, cancel := context.WithTimeout(ctx, time.Duration(registration.Registration.TimeoutMillis)*time.Millisecond)
	defer cancel()
	select {
	case x.capacity <- struct{}{}:
	case <-lifetime.Done():
		return Decision{}, lifetime.Err()
	}
	if err := lifetime.Err(); err != nil {
		<-x.capacity
		return Decision{}, err
	}
	// Clone before entering user code; returning a late answer cannot mutate the
	// engine's envelope, even when cancellation interrupted this call.
	raw, err := json.Marshal(request)
	if err != nil {
		<-x.capacity
		return Decision{}, err
	}
	var isolated InterceptRequest
	if err = fabric.DecodeJSON(raw, &isolated); err != nil {
		<-x.capacity
		return Decision{}, err
	}
	type result struct {
		decision Decision
		err      error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-x.capacity }()
		answer := result{}
		// A local plugin panic is an extension error, never a daemon crash.
		func() {
			defer func() {
				if recover() != nil {
					answer = result{err: fabric.NewError(fabric.CodeProtocolError, "Interceptor failed")}
				}
			}()
			if err := lifetime.Err(); err != nil {
				answer.err = err
				return
			}
			answer.decision, answer.err = handler.Intercept(lifetime, isolated)
		}()
		if answer.err != nil && lifetime.Err() == nil {
			answer.err = fabric.NewError(fabric.CodeProtocolError, "Interceptor failed")
		}
		// Own the returned data before the handler can reuse its buffers. Local
		// extensions are trusted code; remote response bytes remain untrusted.
		if answer.err == nil {
			encoded, e := json.Marshal(answer.decision)
			if e != nil || len(encoded) > MaxInterceptBytes {
				answer = result{err: fabric.NewError(fabric.CodeProtocolError, "Invalid interceptor response")}
			} else {
				var owned Decision
				e = fabric.DecodeJSON(encoded, &owned)
				answer = result{decision: owned, err: e}
			}
		}
		done <- answer
	}()
	select {
	case answer := <-done:
		if lifetime.Err() != nil {
			return Decision{}, lifetime.Err()
		}
		return answer.decision, answer.err
	case <-lifetime.Done():
		return Decision{}, lifetime.Err()
	}
}
func containsPhase(phases []Phase, phase Phase) bool {
	for _, p := range phases {
		if p == phase {
			return true
		}
	}
	return false
}

// HandlerRegistry owns installed bindings separately from manifests. Secrets
// and executable implementations are not returned by discovery/describe.
type HandlerRegistry struct {
	mu       sync.RWMutex
	bindings map[string]Handler
}

func NewHandlerRegistry() *HandlerRegistry { return &HandlerRegistry{bindings: map[string]Handler{}} }
func (r *HandlerRegistry) Set(binding string, handler Handler) error {
	if binding == "" || len(binding) > 256 || handler == nil {
		return invalidRegistration()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bindings[binding] = handler
	return nil
}
func (r *HandlerRegistry) Resolve(binding string) (Handler, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	handler := r.bindings[binding]
	if handler == nil {
		return nil, fabric.NewError(fabric.CodeTargetUnavailable, "Extension binding is unavailable")
	}
	return handler, nil
}
