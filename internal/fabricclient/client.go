// Package fabricclient connects CLI and application callers to the three
// operations on an explicitly selected, authenticated local Pagnet node.
package fabricclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

type Client struct {
	conn    *net.UnixConn
	session *sdk.ClientSession
	once    sync.Once
	err     error
}

type connectionReader struct {
	io.Reader
	conn *net.UnixConn
}

func (r connectionReader) Close() error { return r.conn.Close() }

// Dial performs the genuine kernel/owner or managed handshake, retaining its
// buffered bytes for the official MCP SDK. It never retries authentication,
// searches for another node, or substitutes cloud credentials.
func Dial(ctx context.Context, socket string, auth fabrichost.Authentication) (*Client, error) {
	conn, reader, err := fabrichost.Dial(ctx, socket, auth)
	if err != nil {
		return nil, err
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "pagnet-local-client", Version: "1"}, &sdk.ClientOptions{MultiRoundTrip: &sdk.MultiRoundTripOptions{Disabled: true}})
	session, err := client.Connect(ctx, &sdk.IOTransport{Reader: connectionReader{reader, conn}, Writer: conn, MaxLineLength: 1 << 20}, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Client{conn: conn, session: session}, nil
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		c.err = c.session.Close()
		_ = c.conn.Close()
		// SDK closes both owned directions; the second close is expected when
		// reader and writer share the authenticated Unix connection.
		if errors.Is(c.err, net.ErrClosed) {
			c.err = nil
		}
	})
	return c.err
}

// Call sends exactly one selected operation. Application arguments remain raw
// JSON so numeric values and schemas never pass through float64 conversion.
// Invoke stream-control pages use the same invoke operation, not another tool.
func (c *Client) Call(ctx context.Context, operation fabric.Operation, arguments json.RawMessage) (*sdk.CallToolResult, error) {
	if c == nil || c.session == nil || ctx == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Missing local Fabric client")
	}
	if operation != fabric.OperationDiscover && operation != fabric.OperationDescribe && operation != fabric.OperationInvoke {
		return nil, fabric.NewError(fabric.CodeUnsupported, "Unknown Fabric operation")
	}
	if len(arguments) > fabric.DefaultWireLimits.MaxBytes {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Operation arguments exceed the wire bound")
	}
	owned := bytes.Clone(arguments)
	defer clear(owned)
	var bounded any
	if fabric.DecodeJSONWithLimits(owned, &bounded, fabric.DefaultWireLimits) != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid bounded operation arguments")
	}
	if _, ok := bounded.(map[string]any); !ok {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Operation arguments must be an object")
	}
	return c.session.CallTool(ctx, &sdk.CallToolParams{Name: string(operation), Arguments: json.RawMessage(owned)})
}
