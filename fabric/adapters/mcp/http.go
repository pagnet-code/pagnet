package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// RemoteFactory is an explicitly registered address, never selected from tool
// input or descriptive text. Authorization comes only from setup credentials.
type RemoteFactory struct {
	Endpoint   string
	AllowHTTP  bool
	Client     *http.Client
	Reconnects int
}

func (f RemoteFactory) Transport(_ context.Context, credentials Credentials, tap *ResultTap) (sdk.Transport, error) {
	u, err := url.Parse(f.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(f.AllowHTTP && u.Scheme == "http")) {
		return nil, errors.New("invalid configured MCP endpoint")
	}
	if f.Reconnects < 0 || f.Reconnects > 3 {
		return nil, errors.New("invalid MCP reconnect bound")
	}
	client := http.Client{}
	if f.Client != nil {
		client = *f.Client
	}
	if client.Transport == nil {
		// An unselected environment proxy must never see private input or headers.
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("explicit MCP HTTP transport required")
		}
		bounded := base.Clone()
		bounded.Proxy = nil
		bounded.MaxConnsPerHost = tap.limits.MaxPending
		bounded.MaxIdleConns = tap.limits.MaxPending
		bounded.MaxIdleConnsPerHost = tap.limits.MaxPending
		bounded.IdleConnTimeout = 30 * time.Second
		bounded.MaxResponseHeaderBytes = 64 << 10
		bounded.ResponseHeaderTimeout = 15 * time.Second
		client.Transport = bounded
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	headers := http.Header{}
	for name, value := range credentials.Headers {
		canonical := http.CanonicalHeaderKey(name)
		lower := strings.ToLower(canonical)
		switch lower {
		case "mcp-protocol-version", "mcp-session-id", "content-type", "accept", "content-length", "idempotency-key", "x-idempotency-key", "host":
			return nil, errors.New("credentials cannot override MCP transport authority")
		}
		if canonical == "" || strings.ContainsAny(canonical+value, "\r\n") {
			return nil, errors.New("invalid credential header")
		}
		headers.Set(canonical, value)
	}
	client.Transport = tap.WrapHTTP(&credentialTransport{base: client.Transport, headers: headers})
	retries := f.Reconnects
	if retries == 0 {
		retries = -1
	}
	return &sdk.StreamableClientTransport{Endpoint: u.String(), HTTPClient: &client, MaxEventSize: tap.limits.MaxResultBytes, MaxRetries: retries}, nil
}

type credentialTransport struct {
	base    http.RoundTripper
	headers http.Header
}

func (t *credentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	for name, values := range t.headers {
		copy.Header[name] = append([]string(nil), values...)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(copy)
}
