// Package agentbridge is the client half of the daemon's Unix-socket agent
// bridge (PROTOCOL §6, §8–9). Both MCP binaries — agentnet-mcp (worker,
// network_* tools) and agentnet-control (representative, control_* tools) —
// authenticate to the local daemon with their instance identity and relay
// fixed tool calls; the daemon validates the identity against the
// instances it launched and forwards them to the control plane.
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
type Bridge struct {
	conn     net.Conn
	instance string
	mu       sync.Mutex
	nextID   int
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
	line, err := readLine(conn)
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
	return &Bridge{conn: conn, instance: instanceID}, nil
}

// Call forwards one tool call and waits for the correlated result. The read
// is armed before the write (the response cannot arrive before the server
// processes our request, so this is race-free).
func (b *Bridge) Call(ctx context.Context, tool string, args any) (json.RawMessage, error) {
	b.mu.Lock()
	b.nextID++
	id := strconv.Itoa(b.nextID)
	b.mu.Unlock()

	req, err := json.Marshal(map[string]any{"id": id, "tool": tool, "args": args})
	if err != nil {
		return nil, err
	}
	type outcome struct {
		line []byte
		err  error
	}
	out := make(chan outcome, 1)
	go func() {
		line, err := readLine(b.conn)
		out <- outcome{line, err}
	}()
	if _, err := b.conn.Write(append(req, '\n')); err != nil {
		<-out
		return nil, err
	}
	var line []byte
	select {
	case o := <-out:
		line, err = o.line, o.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	var resp struct {
		ID     string          `json:"id"`
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Err    string          `json:"error"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("bad bridge response: %w", err)
	}
	if !resp.OK {
		if resp.Err == "" {
			resp.Err = "bridge error (no detail)"
		}
		return nil, errors.New(resp.Err)
	}
	return resp.Result, nil
}

// Close closes the bridge connection.
func (b *Bridge) Close() { _ = b.conn.Close() }

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

func readLine(conn net.Conn) ([]byte, error) {
	r := bufio.NewReader(conn)
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
