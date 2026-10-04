package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
)

type Adapter struct {
	dirtyGeneration atomic.Uint64
	cleanGeneration atomic.Uint64
	config          Config
	ctx             context.Context
	cancel          context.CancelFunc
	mu, syncMu      sync.Mutex
	session         *sdk.ClientSession
	tap             *ResultTap
	dirty           chan struct{}
	wg              sync.WaitGroup
	closed          bool
}

func New(ctx context.Context, c Config) (*Adapter, error) {
	if ctx == nil || c.BindingID == "" || c.Audience == "" || len(c.Audience) > 4096 || c.Endpoint.IsOffer() || c.Endpoint.String() == "" || c.Credentials == nil || c.Transport == nil || c.Catalog == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "MCP adapter requires explicit registered authority and connection")
	}
	if c.Limits == (Limits{}) {
		c.Limits = DefaultLimits
	}
	l := c.Limits
	if l.MaxTools < 1 || l.MaxTools > 65536 || l.MaxPages < 1 || l.MaxPages > 1024 || l.MaxPending < 1 || l.MaxPending > 128 || l.MaxResultBytes < 1 || l.MaxResultBytes > 16<<20 || l.MaxCatalogBytes < 1 || l.MaxCatalogBytes > 128<<20 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid bounded MCP adapter limits")
	}
	lifetime, cancel := context.WithCancel(ctx)
	return &Adapter{config: c, ctx: lifetime, cancel: cancel, dirty: make(chan struct{}, 1)}, nil
}
func (a *Adapter) Connect(ctx context.Context) error {
	if ctx == nil {
		return fabric.NewError(fabric.CodeInvalidInput, "MCP connection requires a context")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.session != nil {
		return fabric.NewError(fabric.CodeInvalidInput, "MCP adapter connection already established or closed")
	}
	credentials, err := a.config.Credentials.Credentials(ctx, a.config.BindingID)
	if err != nil {
		return fabric.NewError(fabric.CodeUnauthenticated, "MCP binding credentials unavailable")
	}
	tap := newResultTap(a.config.Limits)
	transport, err := a.config.Transport.Transport(ctx, credentials, tap)
	if err != nil {
		tap.close()
		return fabric.NewError(fabric.CodeTargetUnavailable, "MCP binding transport unavailable")
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "pagnet-fabric", Version: "1"}, &sdk.ClientOptions{MultiRoundTrip: &sdk.MultiRoundTripOptions{Disabled: true}, ToolListChangedHandler: func(context.Context, *sdk.ToolListChangedRequest) {
		a.dirtyGeneration.Add(1)
		select {
		case a.dirty <- struct{}{}:
		default:
		}
	}})
	session, err := client.Connect(ctx, transport, &sdk.ClientSessionOptions{ProtocolVersion: a.config.ProtocolVersion})
	if err != nil {
		tap.close()
		return fabric.NewError(fabric.CodeTargetUnavailable, "MCP protocol connection failed")
	}
	a.dirtyGeneration.Add(1)
	a.session, a.tap = session, tap
	a.wg.Add(1)
	go a.syncNotifications()
	return nil
}
func (a *Adapter) syncNotifications() {
	defer a.wg.Done()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.dirty:
			ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
			_ = a.Sync(ctx)
			cancel()
		}
	}
}
func (a *Adapter) connection() (*sdk.ClientSession, *ResultTap, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.session == nil {
		return nil, nil, fabric.NewError(fabric.CodeTargetUnavailable, "MCP binding is not connected")
	}
	return a.session, a.tap, nil
}
func (a *Adapter) Close() error {
	a.cancel() // Interrupt setup before waiting for its connection lock.
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.cancel()
	session, tap := a.session, a.tap
	a.mu.Unlock()
	var err error
	if session != nil {
		err = session.Close()
	}
	if tap != nil {
		tap.close()
	}
	a.wg.Wait()
	return err
}
func (a *Adapter) ProtocolVersion() string {
	s, _, err := a.connection()
	if err != nil {
		return ""
	}
	return s.InitializeResult().ProtocolVersion
}
func (a *Adapter) Health(ctx context.Context) (fabric.Availability, error) {
	s, _, err := a.connection()
	if err == nil {
		err = s.Ping(ctx, nil)
	}
	state := "available"
	if err != nil {
		state = "unavailable"
	}
	if err != nil {
		err = fabric.NewError(fabric.CodeTargetUnavailable, "MCP binding health check failed")
	}
	return fabric.Availability{State: state, ObservedAt: time.Now().UTC()}, err
}

type wireTool struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	InputSchema  json.RawMessage `json:"inputSchema"`
	OutputSchema json.RawMessage `json:"outputSchema"`
}

func (a *Adapter) Sync(ctx context.Context) error {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	s, tap, err := a.connection()
	if err != nil {
		return err
	}
	generation := a.dirtyGeneration.Load()
	previous, err := a.config.Catalog.Current(ctx, a.config.BindingID)
	if err != nil {
		return err
	}
	if len(previous) > a.config.Limits.MaxTools {
		return fabric.NewError(fabric.CodeProtocolError, "MCP catalog exceeds configured bound")
	}
	old := make(map[string]ToolIdentity, len(previous))
	for _, b := range previous {
		if _, exists := old[b.ToolName]; exists {
			return fabric.NewError(fabric.CodeProtocolError, "Duplicate registered MCP selector")
		}
		old[b.ToolName] = b
	}
	seen := map[string]bool{}
	cursors := map[string]bool{}
	cursor := ""
	delta := CatalogDelta{}
	total := 0
	for page := 0; ; page++ {
		if page >= a.config.Limits.MaxPages || cursors[cursor] {
			return fabric.NewError(fabric.CodeProtocolError, "MCP list pagination did not terminate within bounds")
		}
		cursors[cursor] = true
		token := uuid.NewString()
		if err = tap.reserve(token, "tools/list"); err != nil {
			return err
		}
		_, err = s.ListTools(ctx, &sdk.ListToolsParams{Cursor: cursor, Meta: sdk.Meta{resultTokenKey: token}})
		if err != nil {
			tap.discard(token)
			return fabric.NewError(fabric.CodeTargetUnavailable, "MCP tool discovery failed")
		}
		raw, err := tap.take(token)
		if err != nil {
			return fabric.NewError(fabric.CodeProtocolError, "Original MCP tool list unavailable")
		}
		total += len(raw)
		if total > a.config.Limits.MaxCatalogBytes {
			clear(raw)
			return fabric.NewError(fabric.CodeProtocolError, "MCP descriptor snapshot exceeds bounds")
		}
		var result struct {
			Tools      []wireTool `json:"tools"`
			NextCursor string     `json:"nextCursor"`
		}
		err = fabric.DecodeJSONWithLimits(raw, &result, fabric.WireLimits{MaxBytes: a.config.Limits.MaxResultBytes, MaxDepth: 64, MaxMembers: 65536})
		clear(raw)
		if err != nil {
			return err
		}
		for _, tool := range result.Tools {
			if tool.Name == "" || len(tool.Name) > 256 || !utf8.ValidString(tool.Name) || len(tool.Description) > 32768 || !utf8.ValidString(tool.Description) || seen[tool.Name] || len(seen) >= a.config.Limits.MaxTools {
				return fabric.NewError(fabric.CodeProtocolError, "Invalid or duplicate MCP tool descriptor")
			}
			seen[tool.Name] = true
			var schema map[string]json.RawMessage
			if fabric.DecodeJSON(tool.InputSchema, &schema) != nil || schema == nil {
				return fabric.NewError(fabric.CodeProtocolError, "MCP input schema must be an object")
			}
			encoded, _ := json.Marshal(tool)
			sum := sha256.Sum256(encoded)
			d := ToolDescriptor{Name: tool.Name, Description: tool.Description, Fingerprint: hex.EncodeToString(sum[:]), InputSchema: bytes.Clone(tool.InputSchema), OutputSchema: bytes.Clone(tool.OutputSchema)}
			if old[tool.Name].Fingerprint != d.Fingerprint {
				delta.Upsert = append(delta.Upsert, d)
			}
		}
		cursor = result.NextCursor
		if len(cursor) > 4096 {
			return fabric.NewError(fabric.CodeProtocolError, "MCP cursor exceeds bound")
		}
		if cursor == "" {
			break
		}
	}
	for name := range old {
		if !seen[name] {
			delta.Remove = append(delta.Remove, name)
		}
	}
	sort.Strings(delta.Remove)
	sort.Slice(delta.Upsert, func(i, j int) bool { return delta.Upsert[i].Name < delta.Upsert[j].Name })
	if len(delta.Upsert) == 0 && len(delta.Remove) == 0 {
		a.cleanGeneration.Store(generation)
		return nil
	}
	_, err = a.config.Catalog.Apply(ctx, a.config.BindingID, a.config.Endpoint, delta)
	if err == nil {
		a.cleanGeneration.Store(generation)
	}
	return err
}
func (a *Adapter) Describe(ctx context.Context, ref fabric.EndpointRef, revision fabric.Revision) (fabric.OfferDescriptor, error) {
	b, err := a.config.Catalog.Resolve(ctx, a.config.BindingID, ref, revision)
	if err != nil {
		return fabric.OfferDescriptor{}, err
	}
	if b.Offer.Ref != ref || ref.Endpoint() != a.config.Endpoint || !ref.IsOffer() || b.Offer.BindingID != a.config.BindingID || b.Offer.Revision == "" || (revision != "" && b.Offer.Revision != revision) {
		return fabric.OfferDescriptor{}, fabric.NewError(fabric.CodeStaleReference, "MCP offer binding or revision changed")
	}
	return b.Offer, nil
}
func (a *Adapter) Invoke(ctx context.Context, caller fabric.ExecutionContext, endpoint fabric.EndpointDescriptor, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	if err := caller.VerifyAuthenticated(a.config.Audience); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if endpoint.Ref != a.config.Endpoint || r.Target.Endpoint() != endpoint.Ref || !r.Target.IsOffer() {
		return nil, fabric.NewError(fabric.CodeStaleReference, "MCP invocation requires the exact registered offer")
	}
	b, err := a.config.Catalog.Resolve(ctx, a.config.BindingID, r.Target, r.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	if b.Offer.Ref != r.Target || b.Offer.BindingID != a.config.BindingID || b.ToolName == "" || b.Offer.Revision == "" || (r.ExpectedRevision != "" && b.Offer.Revision != r.ExpectedRevision) {
		return nil, fabric.NewError(fabric.CodeStaleReference, "Remembered MCP offer is stale")
	}
	if a.cleanGeneration.Load() != a.dirtyGeneration.Load() {
		return nil, fabric.NewError(fabric.CodeTargetUnavailable, "MCP descriptors require synchronization")
	}
	s, tap, err := a.connection()
	if err != nil {
		return nil, err
	}
	var arguments map[string]json.RawMessage
	if err = fabric.DecodeJSON(r.Input, &arguments); err != nil || arguments == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "MCP tool arguments must be a JSON object")
	}
	lifetime, cancel := context.WithCancel(ctx)
	if r.Deadline != nil {
		cancel()
		lifetime, cancel = context.WithDeadline(ctx, *r.Deadline)
	}
	stream := &toolStream{id: r.InvocationID, cancel: cancel, result: make(chan toolReply, 1), done: make(chan struct{})}
	token := uuid.NewString()
	if err = tap.reserve(token, "tools/call"); err != nil {
		cancel()
		return nil, fabric.NewError(fabric.CodeTargetUnavailable, "MCP call capacity unavailable")
	}
	go func() {
		defer tap.discard(token)
		result, callErr := s.CallTool(lifetime, &sdk.CallToolParams{Name: b.ToolName, Arguments: json.RawMessage(bytes.Clone(r.Input)), Meta: sdk.Meta{resultTokenKey: token}})
		reply := toolReply{}
		if callErr != nil {
			reply.err = fabric.NewError(fabric.CodeTargetUnavailable, "MCP call outcome is unknown; it was not replayed")
		} else if result.NeedsInput() {
			reply.err = fabric.NewError(fabric.CodeUnsupported, "MCP provider requires explicit input/setup; call was not retried")
		} else {
			reply.raw, callErr = tap.take(token)
			if callErr != nil {
				reply.err = fabric.NewError(fabric.CodeProtocolError, "Original MCP result unavailable")
			} else if result.IsError {
				reply.err = fabric.NewError(fabric.ErrorCode("mcp.tool_error"), "MCP tool reported an execution error")
			}
		}
		stream.publishMu.Lock()
		select {
		case <-stream.done:
			clear(reply.raw)
		default:
			stream.result <- reply
		}
		stream.publishMu.Unlock()
	}()
	return stream, nil
}

type toolReply struct {
	raw []byte
	err *fabric.Error
}
type toolStream struct {
	id        string
	cancel    context.CancelFunc
	result    chan toolReply
	mu        sync.Mutex
	publishMu sync.Mutex
	closeOnce sync.Once
	done      chan struct{}
	reply     *toolReply
	offset    int
	sequence  uint64
	terminal  bool
	closed    bool
}

func (s *toolStream) Close() error {
	s.closeOnce.Do(func() { close(s.done); s.cancel() })
	s.publishMu.Lock()
	select {
	case reply := <-s.result:
		clear(reply.raw)
	default:
	}
	s.publishMu.Unlock()
	s.mu.Lock()
	s.closed = true
	if s.reply != nil {
		clear(s.reply.raw)
	}
	s.mu.Unlock()
	return nil
}
func (s *toolStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	if ctx == nil {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeInvalidInput, "MCP stream requires a context")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.terminal {
		return fabric.InvocationFrame{}, io.EOF
	}
	frame := fabric.InvocationFrame{InvocationID: s.id, Sequence: s.sequence}
	if s.sequence == 0 {
		frame.Kind = fabric.FrameStart
		s.sequence++
		return frame, nil
	}
	if s.reply == nil {
		select {
		case <-s.done:
			return frame, io.EOF
		case reply := <-s.result:
			s.reply = &reply
		case <-ctx.Done():
			s.cancel()
			return frame, ctx.Err()
		}
	}
	if s.offset < len(s.reply.raw) {
		n := min(fabric.MaxFrameBytes, len(s.reply.raw)-s.offset)
		frame.Kind = fabric.FrameChunk
		frame.ContentType = "application/vnd.modelcontextprotocol.tool-result+json"
		frame.Data = bytes.Clone(s.reply.raw[s.offset : s.offset+n])
		s.offset += n
	} else {
		if s.reply.err != nil {
			frame.Kind = fabric.FrameError
			frame.Error = s.reply.err
		} else {
			frame.Kind = fabric.FrameComplete
		}
		s.terminal = true
		clear(s.reply.raw)
	}
	s.sequence++
	return frame, nil
}

var _ fabric.EndpointAdapter = (*Adapter)(nil)
