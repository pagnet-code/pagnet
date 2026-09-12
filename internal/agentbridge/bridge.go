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

	writeMu sync.Mutex
	nextID  int

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
// instance identity (the agent never holds the host credential).
func Dial(socket, instanceID, networkID string) (*Bridge, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(append(mustJSON(map[string]any{
		"type":       "auth",
		"instanceId": instanceID,
		"networkId":  networkID,
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
		Type string `json:"type"`
		Err  string `json:"error"`
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
	_ = conn.SetDeadline(time.Time{})
	b := &Bridge{
		conn:     conn,
		instance: instanceID,
		pending:  map[string]chan bridgeResponse{},
	}
	go b.readLoop(r)
	return b, nil
}

// readLoop is the single reader of the connection. Every response line is
// routed by id to its pending waiter; ids with no waiter (their call was
// canceled or the bridge is closing) are dropped. A read error fails every
// pending call exactly once.
func (b *Bridge) readLoop(r *bufio.Reader) {
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
// for concurrent calls; canceling ctx unblocks this call only — the
// response, when it arrives, is dropped by the reader (id correlation).
func (b *Bridge) Call(ctx context.Context, tool string, args any) (json.RawMessage, error) {
	b.writeMu.Lock()
	b.nextID++
	id := strconv.Itoa(b.nextID)
	req, err := json.Marshal(map[string]any{"id": id, "tool": tool, "args": args})
	if err != nil {
		b.writeMu.Unlock()
		return nil, err
	}

	ch := make(chan bridgeResponse, 1)
	// The waiter must be registered BEFORE the write: the response cannot
	// arrive before the request, and a response arriving after a failed
	// registration would be dropped by the reader.
	b.pendingMu.Lock()
	if b.readClosed {
		readErr := b.readErr
		b.pendingMu.Unlock()
		b.writeMu.Unlock()
		return nil, readErr
	}
	b.pending[id] = ch
	b.pendingMu.Unlock()
	_, err = b.conn.Write(append(req, '\n'))
	b.writeMu.Unlock()
	if err != nil {
		b.pendingMu.Lock()
		delete(b.pending, id)
		b.pendingMu.Unlock()
		b.failPending(err)
		return nil, err
	}

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
