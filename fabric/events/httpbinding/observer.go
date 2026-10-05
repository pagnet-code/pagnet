// Package httpbinding delivers observations through the official CloudEvents
// HTTP binding. Delivery never authorizes or modifies a network invocation.
package httpbinding

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cloudevents/sdk-go/v2/binding"
	"github.com/cloudevents/sdk-go/v2/event"
	cehttp "github.com/cloudevents/sdk-go/v2/protocol/http"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
)

type CredentialProvider interface {
	Authorization(context.Context, string) (string, error)
}

type Config struct {
	Endpoint, Binding string
	// Plain HTTP requires explicit consent, including on localhost.
	AllowPlainHTTP             bool
	Concurrency, MaxEventBytes int
	Timeout                    time.Duration
	Credentials                CredentialProvider
}

type Observer struct {
	config   Config
	client   *http.Client
	capacity chan struct{}
	mu       sync.Mutex
	closed   bool
	active   sync.WaitGroup
	lifetime context.Context
	cancel   context.CancelFunc
	done     chan struct{}
}

func failure(code fabric.ErrorCode, message string) error { return fabric.NewError(code, message) }

// New configures only an explicitly selected destination. No software is
// installed and no connection or credential lookup occurs until Deliver.
func New(c Config) (*Observer, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Scheme != "https" && !(c.AllowPlainHTTP && u.Scheme == "http")) || len(c.Endpoint) > 4096 ||
		c.Binding == "" || len(c.Binding) > 256 || c.Concurrency < 1 || c.Concurrency > 4096 ||
		c.MaxEventBytes < 1 || c.MaxEventBytes > 1<<20 || c.Timeout < time.Millisecond || c.Timeout > time.Minute {
		return nil, failure(fabric.CodeInvalidInput, "Invalid event observer binding")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DisableCompression = true
	t.MaxConnsPerHost, t.MaxIdleConnsPerHost, t.MaxIdleConns = c.Concurrency, c.Concurrency, c.Concurrency
	t.MaxResponseHeaderBytes = 64 << 10
	t.ResponseHeaderTimeout = c.Timeout
	c.Endpoint = u.String()
	lifetime, cancel := context.WithCancel(context.Background())
	return &Observer{config: c, capacity: make(chan struct{}, c.Concurrency), lifetime: lifetime, cancel: cancel, done: make(chan struct{}),
		client: &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Deliver attempts exactly once. At-least-once retry and original event identity
// belong to the durable queue, never to this HTTP client. Any 2xx means the
// observer accepted the event, not that a target invocation completed.
func (o *Observer) Deliver(ctx context.Context, e event.Event) error {
	if ctx == nil {
		return failure(fabric.CodeInvalidInput, "Missing event delivery context")
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return failure(fabric.CodeTargetUnavailable, "Event observer is closed")
	}
	o.active.Add(1)
	o.mu.Unlock()
	defer o.active.Done()
	call, cancel := context.WithTimeout(ctx, o.config.Timeout)
	stop := context.AfterFunc(o.lifetime, cancel)
	defer func() { stop(); cancel() }()
	select {
	case o.capacity <- struct{}{}:
		defer func() { <-o.capacity }()
	case <-call.Done():
		return call.Err()
	}
	// Validation/clone owns all data before the SDK writes HTTP metadata/body.
	raw, err := events.Encode(e, o.config.MaxEventBytes)
	if err != nil {
		return err
	}
	owned, err := events.Decode(raw, o.config.MaxEventBytes)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(call, http.MethodPost, o.config.Endpoint, nil)
	if err != nil {
		return failure(fabric.CodeProtocolError, "Event request unavailable")
	}
	if err = cehttp.WriteRequest(binding.WithForceStructured(call), (*binding.EventMessage)(&owned), req); err != nil {
		return failure(fabric.CodeProtocolError, "Event request unavailable")
	}
	// Disable net/http replay after a stale pooled connection. Explicit queue
	// retry must retain the same event id; observer consumers are idempotent.
	req.GetBody = nil
	if o.config.Credentials != nil {
		value, err := o.config.Credentials.Authorization(call, o.config.Binding)
		if err != nil || len(value) > 16<<10 || strings.ContainsAny(value, "\r\n") {
			return failure(fabric.CodeUnauthenticated, "Event observer credential unavailable")
		}
		if value != "" {
			req.Header.Set("Authorization", value)
		}
	}
	if err = call.Err(); err != nil {
		return err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		if call.Err() != nil {
			return call.Err()
		}
		return failure(fabric.CodeTargetUnavailable, "Event observer unavailable")
	}
	defer resp.Body.Close()
	// Bound response consumption even for a malicious streaming sink.
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 4097))
	if err != nil {
		return failure(fabric.CodeProtocolError, "Event observer response unavailable")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return failure(fabric.CodeTargetUnavailable, "Event observer did not accept delivery")
	}
	return call.Err()
}

// CloseContext cancels and joins real deliveries, including credential callbacks.
// A callback ignoring cancellation retains its resources until it truly returns.
func (o *Observer) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return failure(fabric.CodeInvalidInput, "Missing event observer close context")
	}
	o.mu.Lock()
	if !o.closed {
		o.closed = true
		o.cancel()
		go func() { o.active.Wait(); o.client.CloseIdleConnections(); close(o.done) }()
	}
	o.mu.Unlock()
	select {
	case <-o.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
