// Package mcpbridge exposes three MCP tools. Its stream handles are binding
// flow-control only: they cannot select a target or resume business admission.
package mcpbridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sync"
	"time"
	"unicode/utf8"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
)

type Call struct {
	Operation fabric.Operation
	Discover  *fabric.DiscoverRequest
	Describe  *fabric.DescribeRequest
	Invoke    *fabric.InvokeRequest
}

// Build receives typed routing separately from exact application input. Only
// trusted session composition supplies caller/issuer/ID/timestamps/signatures.
// Build transfers ownership of the returned byte slice; the bridge clears it.
type EnvelopeFactory interface {
	Build(context.Context, Call) ([]byte, any, error)
}
type BoundSession struct {
	Key     string
	Factory EnvelopeFactory
}
type SessionBinder interface {
	Bind(context.Context, *sdk.CallToolRequest) (BoundSession, error)
}
type Executor interface {
	Execute(context.Context, []byte, any) (node.Result, error)
}
type Limits struct {
	MaxStreams, MaxRetainedBytes, MaxResultBytes int
	TTL                                          time.Duration
}

// Reserve worst-case retained association plus frame encoding BEFORE dispatch.
const frameWindowBytes = (fabric.MaxFrameBytes+2)/3*4 + 8192 + fabric.MaxReplayAssociationBytes

var DefaultLimits = Limits{32, 4 << 20, 1 << 20, 30 * time.Second}

type Config struct {
	Service          Executor
	BindSession      SessionBinder
	Limits           Limits
	ProtocolVersions []string
}
type Bridge struct {
	server          *sdk.Server
	config          Config
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	streams         map[string]*streamEntry
	pending         map[*pendingInvocation]struct{}
	reserved, bytes int
	closed          bool
	wg              sync.WaitGroup
}
type pendingInvocation struct {
	owner  string
	cancel context.CancelFunc
	closed bool // guarded by Bridge.mu
}

type streamEntry struct {
	mu            sync.Mutex
	owner, handle string
	stream        fabric.InvocationStream
	cancel        context.CancelFunc
	expires       time.Time
	last          Page
	lastAfter     uint64
	hasAfter      bool
	terminal      bool
	replay        *fabric.ReplayAssociation
}
type Page struct {
	Handle string                    `json:"handle,omitempty"`
	Frames []fabric.InvocationFrame  `json:"frames"`
	More   bool                      `json:"more"`
	Replay *fabric.ReplayAssociation `json:"replay,omitempty"`
}
type StreamControl struct {
	Handle        string `json:"handle"`
	AfterSequence uint64 `json:"afterSequence,string"`
	Cancel        bool   `json:"cancel,omitempty"`
}
type invokeArgs struct {
	Target         fabric.EndpointRef `json:"target,omitempty"`
	Input          json.RawMessage    `json:"input,omitempty"`
	Revision       fabric.Revision    `json:"revision,omitempty"`
	Deadline       *time.Time         `json:"deadline,omitempty"`
	IdempotencyKey string             `json:"idempotencyKey,omitempty"`
	Stream         *StreamControl     `json:"stream,omitempty"`
}

func New(ctx context.Context, c Config) (*Bridge, error) {
	if ctx == nil || c.Service == nil || c.BindSession == nil {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "MCP bridge requires trusted bound session authentication")
	}
	if c.Limits == (Limits{}) {
		c.Limits = DefaultLimits
	}
	l := c.Limits
	if l.MaxStreams < 1 || l.MaxStreams > 128 || l.MaxRetainedBytes < frameWindowBytes || l.MaxRetainedBytes > 32<<20 || l.MaxResultBytes < frameWindowBytes || l.MaxResultBytes > 16<<20 || l.TTL < time.Second || l.TTL > 10*time.Minute {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid bounded MCP bridge limits")
	}
	lifetime, cancel := context.WithCancel(ctx)
	b := &Bridge{config: c, ctx: lifetime, cancel: cancel, streams: map[string]*streamEntry{}, pending: map[*pendingInvocation]struct{}{}}
	b.server = sdk.NewServer(&sdk.Implementation{Name: "pagnet", Version: "fabric-1"}, &sdk.ServerOptions{SupportedProtocolVersions: c.ProtocolVersions})
	for _, name := range []string{"discover", "describe", "invoke"} {
		operation := name
		b.server.AddTool(&sdk.Tool{Name: name, Description: descriptions[name], InputSchema: json.RawMessage(schemas[name])}, func(ctx context.Context, r *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return b.handle(ctx, r, operation)
		})
	}
	b.wg.Add(1)
	go b.expiryLoop()
	return b, nil
}
func (b *Bridge) Server() *sdk.Server { return b.server }
func decodeArgs(raw []byte, out any) error {
	if err := fabric.DecodeJSON(raw, out); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	return d.Decode(out)
}
func (b *Bridge) handle(ctx context.Context, r *sdk.CallToolRequest, name string) (*sdk.CallToolResult, error) {
	bound, err := b.config.BindSession.Bind(ctx, r)
	if err != nil || bound.Key == "" || len(bound.Key) > 4096 || bound.Factory == nil {
		return toolError(fabric.NewError(fabric.CodeUnauthenticated, "MCP session is not authenticated")), nil
	}
	call := Call{}
	switch name {
	case "discover":
		var args fabric.DiscoverRequest
		if err = decodeArgs(r.Params.Arguments, &args); err == nil {
			err = args.Validate()
		}
		call.Operation = fabric.OperationDiscover
		call.Discover = &args
	case "describe":
		var args fabric.DescribeRequest
		if err = decodeArgs(r.Params.Arguments, &args); err == nil {
			err = args.Validate()
		}
		call.Operation = fabric.OperationDescribe
		call.Describe = &args
	case "invoke":
		var args invokeArgs
		if err = decodeArgs(r.Params.Arguments, &args); err != nil {
			break
		}
		if args.Stream != nil {
			if args.Target.String() != "" || len(args.Input) != 0 || args.Revision != "" || args.Deadline != nil || args.IdempotencyKey != "" {
				return toolError(fabric.NewError(fabric.CodeInvalidInput, "Stream control cannot select or invoke a target")), nil
			}
			page, controlErr := b.control(ctx, bound.Key, *args.Stream)
			if controlErr != nil {
				return toolError(controlErr), nil
			}
			return b.result(page)
		}
		if args.Target.String() == "" || len(args.Input) == 0 || len(args.Revision) > 256 || len(args.IdempotencyKey) > 256 {
			err = fabric.NewError(fabric.CodeInvalidInput, "Invocation requires an exact target and bounded application input")
			break
		}
		var input any
		if err = fabric.DecodeJSON(args.Input, &input); err != nil {
			break
		}
		call.Operation = fabric.OperationInvoke
		call.Invoke = &fabric.InvokeRequest{Target: args.Target, Input: bytes.Clone(args.Input), ExpectedRevision: args.Revision, Deadline: args.Deadline, IdempotencyKey: args.IdempotencyKey}
	default:
		return toolError(fabric.NewError(fabric.CodeUnsupported, "Unsupported bridge operation")), nil
	}
	if err != nil {
		return toolError(err), nil
	}
	var lifetime context.Context
	var cancel context.CancelFunc
	var pending *pendingInvocation
	if call.Invoke != nil {
		lifetime, cancel = context.WithCancel(b.ctx)
		if call.Invoke.Deadline != nil {
			cancel()
			lifetime, cancel = context.WithDeadline(b.ctx, *call.Invoke.Deadline)
		}
		pending = &pendingInvocation{owner: bound.Key, cancel: cancel}
		b.mu.Lock()
		if b.closed || len(b.streams)+b.reserved >= b.config.Limits.MaxStreams || (len(b.streams)+b.reserved+1)*frameWindowBytes > b.config.Limits.MaxRetainedBytes {
			b.mu.Unlock()
			cancel()
			return toolError(fabric.NewError(fabric.CodeTargetUnavailable, "MCP stream capacity unavailable")), nil
		}
		b.reserved++
		b.pending[pending] = struct{}{}
		b.mu.Unlock()
		defer func() { b.mu.Lock(); delete(b.pending, pending); b.reserved--; b.mu.Unlock() }()
	} else {
		lifetime = ctx
	}
	if cancel != nil {
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
	}
	exact, evidence, err := bound.Factory.Build(lifetime, call)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return toolError(err), nil
	}
	result, err := b.config.Service.Execute(lifetime, exact, evidence)
	clear(exact)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return toolError(err), nil
	}
	if result.DeferredID != "" {
		if cancel != nil {
			cancel()
		}
		return b.result(struct {
			DeferredID        string        `json:"deferredId"`
			NotificationError *fabric.Error `json:"notificationError,omitempty"`
		}{result.DeferredID, result.DeferredNotificationError})
	}
	if result.Stream == nil {
		if cancel != nil {
			cancel()
		}
		if result.Discover != nil {
			return b.result(result.Discover)
		}
		if result.Describe != nil {
			return b.result(result.Describe)
		}
		return toolError(fabric.NewError(fabric.CodeProtocolError, "Canonical operation returned no result")), nil
	}
	if call.Invoke == nil || cancel == nil {
		_ = result.Stream.Close()
		return toolError(fabric.NewError(fabric.CodeProtocolError, "Read-only operation returned invocation stream")), nil
	}
	var entropy [24]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		cancel()
		_ = result.Stream.Close()
		return toolError(fabric.NewError(fabric.CodeTargetUnavailable, "Stream control entropy unavailable")), nil
	}
	handle := base64.RawURLEncoding.EncodeToString(entropy[:])
	var replay *fabric.ReplayAssociation
	if result.Replay != nil {
		if err := result.Replay.Validate(); err != nil {
			cancel()
			_ = result.Stream.Close()
			return toolError(err), nil
		}
		owned := result.Replay.Clone()
		replay = &owned
	}
	entry := &streamEntry{replay: replay, owner: bound.Key, handle: handle, stream: result.Stream, cancel: cancel, expires: time.Now().Add(b.config.Limits.TTL)}
	page, err := b.firstPage(ctx, entry)
	if err != nil {
		cancel()
		_ = result.Stream.Close()
		return toolError(err), nil
	}
	b.mu.Lock()
	if b.closed || pending.closed || lifetime.Err() != nil || b.bytes+pageSize(page) > b.config.Limits.MaxRetainedBytes {
		b.mu.Unlock()
		cancel()
		_ = result.Stream.Close()
		return toolError(fabric.NewError(fabric.CodeTargetUnavailable, "MCP retained frame capacity unavailable")), nil
	}
	b.streams[handle] = entry
	b.bytes += pageSize(page)
	b.mu.Unlock()
	return b.result(page)
}
func (b *Bridge) result(value any) (*sdk.CallToolResult, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > b.config.Limits.MaxResultBytes {
		return toolError(fabric.NewError(fabric.CodeProtocolError, "MCP result exceeds negotiated bound")), nil
	}
	result := &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: string(raw)}}}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil || len(encoded)+1024 > b.config.Limits.MaxResultBytes {
		return toolError(fabric.NewError(fabric.CodeProtocolError, "Encoded MCP result exceeds bound")), nil
	}
	return result, nil
}
func toolError(err error) *sdk.CallToolResult {
	var typed *fabric.Error
	if errors.As(err, &typed) {
		copy := fabric.NewError(typed.Code, typed.Message)
		if len(copy.Code) > 256 || !utf8.ValidString(string(copy.Code)) || copy.Code == "" {
			copy.Code = fabric.CodeProtocolError
		}
		switch typed.Effect {
		case fabric.EffectUnknown, fabric.EffectNotStarted, fabric.EffectCompleted:
			copy.Effect = typed.Effect
		}
		typed = copy
	} else {
		typed = fabric.NewError(fabric.CodeTargetUnavailable, "Operation failed; downstream outcome may be unknown")
	}
	raw, _ := json.Marshal(struct {
		Error *fabric.Error `json:"error"`
	}{typed})
	return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: string(raw)}}}
}
func pageSize(p Page) int { raw, _ := json.Marshal(p); return len(raw) }
func (b *Bridge) firstPage(ctx context.Context, e *streamEntry) (Page, error) {
	frame, err := e.stream.Next(ctx)
	if err != nil {
		return Page{}, fabric.NewError(fabric.CodeProtocolError, "Invocation ended without an original start")
	}
	if frame.Kind != fabric.FrameStart || frame.Sequence != 0 || len(frame.Data) > fabric.MaxFrameBytes {
		return Page{}, fabric.NewError(fabric.CodeProtocolError, "Invalid original stream start")
	}
	page := Page{Replay: e.replay, Handle: e.handle, Frames: []fabric.InvocationFrame{frame}, More: true}
	e.last = page
	return page, nil
}
func (b *Bridge) control(ctx context.Context, owner string, c StreamControl) (Page, error) {
	b.mu.Lock()
	e := b.streams[c.Handle]
	if e == nil || e.owner != owner || !e.expires.After(time.Now()) {
		b.mu.Unlock()
		return Page{}, fabric.NewError(fabric.CodeStaleContinuation, "MCP stream control expired or belongs to another session")
	}
	b.mu.Unlock()
	if c.Cancel {
		b.remove(e)
		return Page{Replay: e.replay, Handle: e.handle, Frames: []fabric.InvocationFrame{}, More: false}, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	b.mu.Lock()
	live := b.streams[e.handle] == e && e.expires.After(time.Now())
	b.mu.Unlock()
	if !live {
		return Page{}, fabric.NewError(fabric.CodeStaleContinuation, "MCP stream control expired or canceled")
	}
	if e.hasAfter && c.AfterSequence == e.lastAfter {
		return e.last, nil
	}
	last := e.last.Frames[len(e.last.Frames)-1]
	if e.terminal || last.Sequence == math.MaxUint64 || c.AfterSequence != last.Sequence {
		return Page{}, fabric.NewError(fabric.CodeInvalidInput, "Stream cursor is not the exact retained sequence")
	}
	frame, err := e.stream.Next(ctx)
	if err != nil {
		b.remove(e)
		if errors.Is(err, io.EOF) {
			return Page{}, fabric.NewError(fabric.CodeProtocolError, "Stream ended without genuine terminal evidence")
		}
		return Page{}, err
	}
	if frame.InvocationID != last.InvocationID || frame.Sequence != last.Sequence+1 || len(frame.Data) > fabric.MaxFrameBytes || frame.Kind == fabric.FrameStart {
		b.remove(e)
		return Page{}, fabric.NewError(fabric.CodeProtocolError, "Invalid original stream frame")
	}
	terminal := frame.Kind == fabric.FrameComplete || frame.Kind == fabric.FrameError
	page := Page{Replay: e.replay, Handle: e.handle, Frames: []fabric.InvocationFrame{frame}, More: !terminal}
	b.mu.Lock()
	if b.streams[e.handle] != e || b.bytes-pageSize(e.last)+pageSize(page) > b.config.Limits.MaxRetainedBytes {
		b.mu.Unlock()
		b.remove(e)
		return Page{}, fabric.NewError(fabric.CodeTargetUnavailable, "MCP frame window unavailable; effects are unknown")
	}
	b.bytes += pageSize(page) - pageSize(e.last)
	e.expires = time.Now().Add(b.config.Limits.TTL)
	e.lastAfter = c.AfterSequence
	e.hasAfter = true
	e.last = page
	e.terminal = terminal
	b.mu.Unlock()
	if terminal {
		e.cancel()
		_ = e.stream.Close()
	}
	return page, nil
}
func (b *Bridge) remove(e *streamEntry) {
	b.mu.Lock()
	if b.streams[e.handle] == e {
		delete(b.streams, e.handle)
		b.bytes -= pageSize(e.last)
	}
	b.mu.Unlock()
	e.cancel()
	_ = e.stream.Close()
}
func (b *Bridge) CloseSession(key string) {
	b.mu.Lock()
	var pending []context.CancelFunc
	for p := range b.pending {
		if p.owner == key {
			p.closed = true
			pending = append(pending, p.cancel)
		}
	}
	var owned []*streamEntry
	for _, e := range b.streams {
		if e.owner == key {
			owned = append(owned, e)
		}
	}
	b.mu.Unlock()
	for _, cancel := range pending {
		cancel()
	}
	for _, e := range owned {
		b.remove(e)
	}
}
func (b *Bridge) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.cancel()
	var entries []*streamEntry
	for _, e := range b.streams {
		entries = append(entries, e)
	}
	b.mu.Unlock()
	for _, e := range entries {
		b.remove(e)
	}
	b.wg.Wait()
	return nil
}
func (b *Bridge) expiryLoop() {
	defer b.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			b.expire(time.Now())
		}
	}
}

var descriptions = map[string]string{"discover": "Find relevant agents and tools. Discovery does not run them.", "describe": "Read an exact remembered endpoint or offer before invoking it.", "invoke": "Invoke one exact offer, or consume/cancel an already admitted stream using its opaque handle."}
var schemas = map[string]string{
	"discover": `{"type":"object","properties":{"query":{"type":"string"},"scope":{"type":"object"},"filters":{"type":"object"},"limit":{"type":"integer","minimum":1,"maximum":100},"cursor":{"type":"string"}},"required":["query","scope","limit"],"additionalProperties":false}`,
	"describe": `{"type":"object","properties":{"selections":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"object","properties":{"ref":{"type":"string"},"expectedRevision":{"type":"string"},"offersCursor":{"type":"string"},"offersLimit":{"type":"integer","minimum":1,"maximum":100}},"required":["ref"],"additionalProperties":false}}},"required":["selections"],"additionalProperties":false}`,
	"invoke":   `{"type":"object","oneOf":[{"properties":{"target":{"type":"string"},"input":{},"revision":{"type":"string"},"deadline":{"type":"string"},"idempotencyKey":{"type":"string"}},"required":["target","input"],"additionalProperties":false},{"properties":{"stream":{"type":"object","properties":{"handle":{"type":"string"},"afterSequence":{"type":"string","pattern":"^[0-9]+$"},"cancel":{"type":"boolean"}},"required":["handle","afterSequence"],"additionalProperties":false}},"required":["stream"],"additionalProperties":false}]}`,
}

func (b *Bridge) expire(now time.Time) {
	b.mu.Lock()
	var expired []*streamEntry
	for handle, e := range b.streams {
		if !e.expires.After(now) {
			delete(b.streams, handle)
			b.bytes -= pageSize(e.last)
			expired = append(expired, e)
		}
	}
	b.mu.Unlock()
	for _, e := range expired {
		e.cancel()
		_ = e.stream.Close()
	}
}
