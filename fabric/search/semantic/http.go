package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// transport contains only adapter-private credentials. Errors deliberately do
// not echo response bodies, headers, selected endpoint credentials or inputs.
type transport struct {
	base    string
	client  *http.Client
	token   string
	maxBody int64
}

func newTransport(base, token string, client *http.Client, allowHTTP bool) (*transport, error) {
	u, e := url.Parse(base)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("explicit HTTP(S) endpoint without URL credentials required")
	}
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
	if u.Scheme == "http" && !local && !allowHTTP {
		return nil, errors.New("plaintext remote endpoint requires explicit AllowHTTP")
	}
	c := http.Client{Timeout: 45 * time.Second}
	if client != nil {
		c = *client
	}
	if c.Transport == nil {
		standard, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("explicit adapter transport required for nonstandard HTTP default")
		}
		baseTransport := standard.Clone()
		baseTransport.Proxy = nil
		baseTransport.MaxIdleConns = 32
		baseTransport.MaxIdleConnsPerHost = 8
		baseTransport.IdleConnTimeout = 90 * time.Second
		baseTransport.ResponseHeaderTimeout = 15 * time.Second
		baseTransport.MaxResponseHeaderBytes = 64 << 10
		c.Transport = baseTransport
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("adapter redirects are disabled") }
	if c.Timeout < 0 {
		return nil, errors.New("adapter timeout must be finite and nonnegative")
	}
	if c.Timeout == 0 {
		c.Timeout = 45 * time.Second
	}
	return &transport{base: strings.TrimRight(base, "/"), client: &c, token: token, maxBody: 16 << 20}, nil
}
func (t *transport) request(ctx context.Context, method, path string, input, output any, header string) error {
	var body io.Reader
	if input != nil {
		raw, e := json.Marshal(input)
		if e != nil {
			return e
		}
		if len(raw) > 16<<20 {
			return errors.New("adapter request exceeds finite byte budget")
		}
		body = bytes.NewReader(raw)
	}
	req, e := http.NewRequestWithContext(ctx, method, t.base+path, body)
	if e != nil {
		return errors.New("invalid adapter request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if t.token != "" {
		if header == "Authorization" {
			req.Header.Set(header, "Bearer "+t.token)
		} else {
			req.Header.Set(header, t.token)
		}
	}
	response, e := t.client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("selected adapter HTTP request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("selected adapter returned HTTP%d", response.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, t.maxBody+1))
	if e != nil {
		return errors.New("adapter response read failed")
	}
	if int64(len(raw)) > t.maxBody {
		return errors.New("adapter response exceeds finite byte budget")
	}
	if output != nil && json.Unmarshal(raw, output) != nil {
		return errors.New("selected adapter returned invalid JSON")
	}
	return ctx.Err()
}
