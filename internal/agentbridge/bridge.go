// Package agentbridge is the client half of the daemon's Unix-socket agent
// bridge (PROTOCOL §6, §8–9). Both MCP surfaces — the worker bridge
// (network_* tools) and the control bridge (representative, control_*
// tools) — authenticate to the local daemon with their instance identity
// and relay fixed tool calls; the daemon validates the identity against
// the instances it launched and forwards them to the control plane.
package agentbridge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Bridge is one authenticated bridge connection to the local daemon.
//
// Concurrency: exactly ONE reader goroutine consumes the connection and
// dispatches each response to the pending call whose id it carries; writes
// are serialized. The daemon processes bridge requests strictly serially
// and echoes the client id, but runtimes may issue PARALLEL tool calls and
// may cancel a single call (MCP notifications/cancelled) — with a reader
// per Call, concurrent readers on one net.Conn are unsafe, and an
// abandoned reader consumes the next response (bytes pulled into a
// per-Call bufio.Reader are discarded). Id-correlated pending waiters are
// the daemon-side pattern (pending/deliverAgentResponse) applied here.
type Bridge struct {
	conn     net.Conn
	instance string

	// sideport is the hosted Fabric sideport the daemon's authenticated
	// bridge handshake (auth_ok) advertised for this instance, when the
	// owner administration associated one. It has no nonce, principal or
	// signing key: the bridge's own per-activation nonce and instance
	// identity supply the original-worker proof when this original MCP
	// subprocess opens the SECOND socket. A bridge whose authentication
	// failed never has one — the daemon only advertises it in auth_ok.
	sideport *HostedFabricSideport

	writeGate chan struct{}
	nextID    int

	pendingMu  sync.Mutex
	pending    map[string]chan bridgeResponse
	readErr    error // first read-loop error, reported to pending calls
	readClosed bool
}

type bridgeResponse struct {
	ok     bool
	result json.RawMessage
	err    error
}

// Dial connects to the daemon's Unix socket and authenticates with the
// instance identity + the daemon-minted per-activation nonce (security
// wave S1: identifier-only auth is gone — the daemon accepts a bridge
// only when the presented nonce matches the one it minted for the
// instance's current launch and shipped in the MCP config, the claimed
// kind matches the instance's kind, and — on Linux — the connecting
// process is inside the instance's process tree). The agent never holds
// the host credential.
func Dial(socket, instanceID, networkID, nonce, kind string) (*Bridge, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(append(mustJSON(map[string]any{
		"type":       "auth",
		"instanceId": instanceID,
		"networkId":  networkID,
		"nonce":      nonce,
		"kind":       kind,
	}), '\n')); err != nil {
		_ = conn.Close()
		return nil, err
	}
	r := bufio.NewReader(conn)
	line, err := readLine(r)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	var resp struct {
		Type     string                `json:"type"`
		Err      string                `json:"error"`
		Sideport *HostedFabricSideport `json:"sideport"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("bad auth response: %w", err)
	}
	if resp.Type != "auth_ok" {
		_ = conn.Close()
		if resp.Err == "" {
			resp.Err = "authentication rejected"
		}
		return nil, errors.New(resp.Err)
	}
	// The sideport is an additive advertisement inside the REAL auth_ok: it
	// is present only because this bridge authenticated. A present-but
	// malformed sideport is a daemon bug — refuse the sideport loudly (the
	// bridge keeps its original tools) instead of failing the bridge or
	// silently keeping an invalid credential set.
	var sp *HostedFabricSideport
	if resp.Sideport != nil {
		if err := resp.Sideport.Validate(); err != nil {
			log.Error("hosted fabric sideport invalid; ignoring it", "error", err.Error())
		} else {
			sp = resp.Sideport
		}
	}
	_ = conn.SetDeadline(time.Time{})
	b := &Bridge{
		conn:      conn,
		instance:  instanceID,
		sideport:  sp,
		pending:   map[string]chan bridgeResponse{},
		writeGate: make(chan struct{}, 1),
	}
	go b.readLoop(r)
	return b, nil
}

// Sideport returns the hosted Fabric sideport the daemon's authenticated
// bridge handshake advertised for this instance, if any. It carries the node
// private socket, the stable endpoint and the original generation only — no
// nonce, principal or signing key. The bool is false for every ordinary
// bridge (no association) and for a bridge that failed authentication (such
// a bridge has no *Bridge at all).
func (b *Bridge) Sideport() (HostedFabricSideport, bool) {
	if b == nil || b.sideport == nil {
		return HostedFabricSideport{}, false
	}
	return *b.sideport, true
}

// readLoop is the single reader of the connection. Every response line is
// routed by id to its pending waiter; ids with no waiter (their call was
// canceled or the bridge is closing) are dropped. A read error fails every
// pending call exactly once.
func (b *Bridge) readLoop(r *bufio.Reader) {
	defer b.conn.Close()
	for {
		line, err := readLine(r)
		if err != nil {
			b.failPending(err)
			return
		}
		var resp struct {
			ID     string          `json:"id"`
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
			Err    string          `json:"error"`
		}
		if err := json.Unmarshal(line, &resp); err != nil || resp.ID == "" {
			// A malformed line desyncs the stream: fail the bridge.
			b.failPending(fmt.Errorf("bad bridge response: %v", err))
			return
		}
		out := bridgeResponse{}
		if resp.OK {
			out.ok = true
			out.result = resp.Result
		} else {
			if resp.Err == "" {
				resp.Err = "bridge error (no detail)"
			}
			out.err = errors.New(resp.Err)
		}
		b.pendingMu.Lock()
		ch, ok := b.pending[resp.ID]
		if ok {
			delete(b.pending, resp.ID)
		}
		b.pendingMu.Unlock()
		if ok {
			ch <- out
		}
		// Unknown id: the call was canceled before its response arrived —
		// drop it (the daemon is still waiting for the next request line,
		// so dropping is safe and keeps the stream in sync).
	}
}

// failPending reports err to every pending call once, and to any call
// registered after the read loop died.
func (b *Bridge) failPending(err error) {
	b.pendingMu.Lock()
	defer b.pendingMu.Unlock()
	if b.readClosed {
		return
	}
	if err == nil {
		err = errors.New("bridge connection closed")
	}
	b.readErr = err
	b.readClosed = true
	for id, ch := range b.pending {
		ch <- bridgeResponse{err: err}
		delete(b.pending, id)
	}
}

// Call forwards one tool call and waits for the correlated result. Safe
// for concurrent calls. Cancellation while awaiting a response drops only that
// waiter. Cancellation during a write closes the stream because framing may
// already be partial; callers must never automatically replay a mutating tool.
func (b *Bridge) Call(ctx context.Context, tool string, args any) (json.RawMessage, error) {
	select {
	case b.writeGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	gateHeld := true
	defer func() {
		if gateHeld {
			<-b.writeGate
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.nextID++
	id := strconv.Itoa(b.nextID)
	req, err := json.Marshal(map[string]any{"id": id, "tool": tool, "args": args})
	if err != nil {
		return nil, err
	}

	if len(req) > 1<<20 {
		return nil, errors.New("bridge request exceeds 1 MiB")
	}
	ch := make(chan bridgeResponse, 1)
	// The waiter must be registered BEFORE the write: the response cannot
	// arrive before the request, and a response arriving after a failed
	// registration would be dropped by the reader.
	b.pendingMu.Lock()
	if b.readClosed {
		readErr := b.readErr
		b.pendingMu.Unlock()
		return nil, readErr
	}
	b.pending[id] = ch
	b.pendingMu.Unlock()
	err = b.writeRequest(ctx, append(req, '\n'))
	if err != nil {
		b.pendingMu.Lock()
		delete(b.pending, id)
		b.pendingMu.Unlock()
		_ = b.conn.Close()
		b.failPending(err)
		return nil, err
	}

	// Release serialized write admission before waiting for this response.
	<-b.writeGate
	gateHeld = false
	select {
	case out := <-ch:
		return out.result, out.err
	case <-ctx.Done():
		b.pendingMu.Lock()
		delete(b.pending, id)
		b.pendingMu.Unlock()
		return nil, ctx.Err()
	}
}

// writeRequest bounds local socket backpressure as well as caller cancellation.
// A failed/partial write invalidates framing; Call closes the connection rather
// than replaying a possibly executed tool. The cancellation callback is joined
// before clearing the deadline, so it cannot poison a subsequent writer.
func (b *Bridge) writeRequest(ctx context.Context, request []byte) error {
	deadline := time.Now().Add(5 * time.Second)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if err := b.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	cancelled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = b.conn.SetWriteDeadline(time.Now()); close(cancelled) })
	n, err := b.conn.Write(request)
	if !stop() {
		<-cancelled
	}
	_ = b.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if n != len(request) {
		return io.ErrShortWrite
	}
	return nil
}

// Close closes the bridge connection; pending calls fail with the close
// error and the reader goroutine exits.
func (b *Bridge) Close() {
	_ = b.conn.Close()
}

// Handle adapts one fixed tool to an MCP handler: keep only the declared
// arguments, call the bridge, render the JSON result as tool text.
func (b *Bridge) Handle(tool string, allowed map[string]any) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := map[string]any{}
		for k, v := range request.GetArguments() {
			if _, ok := allowed[k]; !ok {
				continue
			}
			args[k] = v
		}
		result, err := b.Call(ctx, tool, args)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if len(result) == 0 {
			return mcp.NewToolResultText("{}"), nil
		}
		// Pretty-print for readability inside the agent's transcript.
		var buf map[string]any
		if json.Unmarshal(result, &buf) == nil {
			if pretty, err := json.MarshalIndent(buf, "", "  "); err == nil {
				return mcp.NewToolResultText(string(pretty)), nil
			}
		}
		return mcp.NewToolResultText(string(result)), nil
	}
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func readLine(r *bufio.Reader) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '\n' {
			return buf, nil
		}
		buf = append(buf, b)
		if len(buf) > 1<<20 {
			return nil, errors.New("line too long")
		}
	}
}
