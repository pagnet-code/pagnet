package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
)

const resultTokenKey = "pagnet.result-token"

type tapEntry struct {
	id     jsonrpc.ID
	method string
	result json.RawMessage
}

// ResultTap preserves exact opaque application numbers independently of SDK
// typed maps. It is private to one bound connection and stores no credentials.
type ResultTap struct {
	mu      sync.Mutex
	limits  Limits
	pending map[string]*tapEntry
	ids     map[jsonrpc.ID]string
	bytes   int
	closed  bool
}

func newResultTap(l Limits) *ResultTap {
	return &ResultTap{limits: l, pending: map[string]*tapEntry{}, ids: map[jsonrpc.ID]string{}}
}
func (t *ResultTap) reserve(token, method string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || len(t.pending) >= t.limits.MaxPending {
		return errors.New("MCP pending result capacity unavailable")
	}
	if _, exists := t.pending[token]; exists {
		return errors.New("duplicate MCP result token")
	}
	t.pending[token] = &tapEntry{method: method}
	return nil
}
func (t *ResultTap) take(token string) (json.RawMessage, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.pending[token]
	if e == nil {
		return nil, errors.New("MCP result association missing")
	}
	delete(t.pending, token)
	delete(t.ids, e.id)
	t.bytes -= len(e.result)
	if len(e.result) == 0 {
		return nil, errors.New("MCP exact result unavailable")
	}
	return e.result, nil
}
func (t *ResultTap) discard(token string) { raw, _ := t.take(token); clear(raw) }
func (t *ResultTap) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	for _, e := range t.pending {
		clear(e.result)
	}
	clear(t.pending)
	clear(t.ids)
	t.bytes = 0
}
func (t *ResultTap) sent(msg jsonrpc.Message) error {
	req, ok := msg.(*jsonrpc.Request)
	if !ok || !req.ID.IsValid() {
		return nil
	}
	if req.Method != "tools/list" && req.Method != "tools/call" {
		return nil
	}
	var params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := fabric.DecodeJSON(req.Params, &params); err != nil {
		return err
	}
	var token string
	if json.Unmarshal(params.Meta[resultTokenKey], &token) != nil || token == "" {
		return errors.New("MCP result token missing")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.pending[token]
	if t.closed || e == nil || e.method != req.Method || e.id.IsValid() {
		return errors.New("MCP original request association invalid")
	}
	if _, exists := t.ids[req.ID]; exists {
		return errors.New("duplicate MCP request identity")
	}
	e.id = req.ID
	t.ids[req.ID] = token
	return nil
}
func (t *ResultTap) received(msg jsonrpc.Message) error {
	res, ok := msg.(*jsonrpc.Response)
	if !ok {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	token := t.ids[res.ID]
	if token == "" {
		return nil
	}
	e := t.pending[token]
	if e == nil || e.id != res.ID || t.closed {
		return errors.New("MCP response association invalid")
	}
	if res.Error != nil {
		return nil
	}
	if len(e.result) != 0 {
		return errors.New("duplicate MCP original response")
	}
	if len(res.Result) > t.limits.MaxResultBytes || t.bytes+len(res.Result) > t.limits.MaxResultBytes*t.limits.MaxPending {
		return errors.New("MCP response bounds exceeded")
	}
	var validate any
	if err := fabric.DecodeJSONWithLimits(res.Result, &validate, fabric.WireLimits{MaxBytes: t.limits.MaxResultBytes, MaxDepth: 64, MaxMembers: 65536}); err != nil {
		return err
	}
	e.result = bytes.Clone(res.Result)
	t.bytes += len(e.result)
	return nil
}

// WrapLocal retains SDK negotiation. It deliberately rejects Streamable/SSE
// transports: wrapping their Connection hides SDK-private state update hooks.
func (t *ResultTap) WrapLocal(transport sdk.Transport) (sdk.Transport, error) {
	switch original := transport.(type) {
	case *sdk.IOTransport:
		copy := *original
		copy.MaxLineLength = t.limits.MaxResultBytes
		transport = &copy
	case *sdk.StdioTransport:
		copy := *original
		copy.MaxLineLength = t.limits.MaxResultBytes
		transport = &copy
	case *sdk.InMemoryTransport: // Official fixture transport has SDK's finite default.
	default:
		return nil, errors.New("use HTTP result tap for remote MCP transport")
	}
	return &localTapTransport{transport, t}, nil
}

type localTapTransport struct {
	sdk.Transport
	tap *ResultTap
}

func (t *localTapTransport) Connect(ctx context.Context) (sdk.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &localTapConnection{c, t.tap}, nil
}

type localTapConnection struct {
	sdk.Connection
	tap *ResultTap
}

func (c *localTapConnection) Write(ctx context.Context, m jsonrpc.Message) error {
	if err := c.tap.sent(m); err != nil {
		return err
	}
	return c.Connection.Write(ctx, m)
}
func (c *localTapConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	m, err := c.Connection.Read(ctx)
	if err != nil {
		return nil, err
	}
	if err = c.tap.received(m); err != nil {
		return nil, err
	}
	return m, nil
}

// WrapHTTP leaves the original official SDK Connection intact, so version,
// session and cancellation updates remain SDK-owned. No request is retried.
func (t *ResultTap) WrapHTTP(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &httpResultTap{base, t}
}

type httpResultTap struct {
	base http.RoundTripper
	tap  *ResultTap
}

func (t *httpResultTap) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost && req.Body != nil {
		raw, err := io.ReadAll(io.LimitReader(req.Body, int64(t.tap.limits.MaxResultBytes+1)))
		_ = req.Body.Close()
		if err != nil || len(raw) > t.tap.limits.MaxResultBytes {
			return nil, errors.New("MCP outbound frame exceeds bound")
		}
		msg, err := jsonrpc.DecodeMessage(raw)
		if err != nil {
			return nil, err
		}
		if err = t.tap.sent(msg); err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.Body = io.NopCloser(bytes.NewReader(raw))
	}
	res, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	mode := strings.ToLower(strings.Split(res.Header.Get("Content-Type"), ";")[0])
	if res.Body != nil && (mode == "application/json" || mode == "text/event-stream") {
		res.Body = &tapBody{ReadCloser: res.Body, tap: t.tap, sse: mode == "text/event-stream"}
	}
	return res, nil
}

type tapBody struct {
	io.ReadCloser
	tap           *ResultTap
	buffer, event []byte
	sse           bool
	done          bool
}

func (b *tapBody) parse(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	var validate any
	if err := fabric.DecodeJSONWithLimits(raw, &validate, fabric.WireLimits{MaxBytes: b.tap.limits.MaxResultBytes, MaxDepth: 64, MaxMembers: 65536}); err != nil {
		return err
	}
	msg, err := jsonrpc.DecodeMessage(raw)
	if err != nil {
		return err
	}
	return b.tap.received(msg)
}
func (b *tapBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 && !b.done {
		b.buffer = append(b.buffer, p[:n]...)
		if len(b.buffer) > b.tap.limits.MaxResultBytes {
			return n, errors.New("MCP inbound frame exceeds bound")
		}
		if !b.sse {
			if json.Valid(b.buffer) {
				if parseErr := b.parse(b.buffer); parseErr != nil {
					return n, parseErr
				}
				b.done = true
				clear(b.buffer)
				b.buffer = nil
			}
		} else {
			for {
				idx := bytes.IndexByte(b.buffer, '\n')
				if idx < 0 {
					break
				}
				line := bytes.TrimSuffix(b.buffer[:idx], []byte{'\r'})
				if len(line) == 0 {
					if parseErr := b.parse(bytes.TrimSuffix(b.event, []byte{'\n'})); parseErr != nil {
						return n, parseErr
					}
					clear(b.event)
					b.event = nil
				} else if bytes.HasPrefix(line, []byte("data:")) {
					data := bytes.TrimPrefix(line, []byte("data:"))
					if len(data) > 0 && data[0] == ' ' {
						data = data[1:]
					}
					if len(b.event)+len(data)+1 > b.tap.limits.MaxResultBytes {
						return n, errors.New("MCP SSE event exceeds bound")
					}
					b.event = append(b.event, data...)
					b.event = append(b.event, '\n')
				}
				b.buffer = bytes.Clone(b.buffer[idx+1:])
			}
		}
	}
	return n, err
}
func (b *tapBody) Close() error { clear(b.buffer); clear(b.event); return b.ReadCloser.Close() }
