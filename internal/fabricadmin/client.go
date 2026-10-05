package fabricadmin

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

type Client struct {
	connection *net.UnixConn
	reader     *bufio.Reader
	gate       chan struct{}
	once       sync.Once
}

// Dial selects the separate administration protocol on the genuine private
// socket. Kernel owner/managed-process guards remain server authority; this
// wire mode never creates owner permission. No retries/fallback are performed.
func Dial(ctx context.Context, path string) (*Client, error) {
	conn, reader, err := fabrichost.DialProtocol(ctx, path, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"}, fabrichost.AdminProtocol)
	if err != nil {
		return nil, err
	}
	return &Client{connection: conn, reader: reader, gate: make(chan struct{}, 1)}, nil
}
func (c *Client) Close() error {
	if c == nil || c.connection == nil {
		return nil
	}
	var err error
	c.once.Do(func() { err = c.connection.Close() })
	return err
}

// Call is ordered, context-cancellable, bounded and never automatically repeats
// a mutation. A failed transport has unknown effects; typed handlers must own
// their exact CAS/setup-receipt semantics.
func (c *Client) Call(ctx context.Context, request Request) (Response, error) {
	if c == nil || c.connection == nil || c.reader == nil || c.gate == nil || ctx == nil || ctx.Err() != nil || request.Validate() != nil {
		return Response{}, fabric.NewError(fabric.CodeInvalidInput, "Invalid private administration call")
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return Response{}, ctx.Err()
	}
	raw, err := json.Marshal(request)
	if err != nil || len(raw)+1 > MaxRequestBytes {
		return Response{}, fabric.NewError(fabric.CodeInvalidInput, "Private administration request exceeds bounds")
	}
	defer clear(raw)
	deadline := time.Now().Add(time.Minute)
	if selected, ok := ctx.Deadline(); ok && selected.Before(deadline) {
		deadline = selected
	}
	_ = c.connection.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if _, err = c.connection.Write(append(raw, '\n')); err != nil {
		c.Close()
		return Response{}, fabric.NewError(fabric.CodeTargetUnavailable, "Private administration transport failed; effects may be unknown")
	}
	line, err := readLine(c.reader, MaxResponseBytes)
	if err != nil {
		c.Close()
		return Response{}, fabric.NewError(fabric.CodeTargetUnavailable, "Private administration transport failed; effects may be unknown")
	}
	defer clear(line)
	var response Response
	if err = decodeStrict(line, &response, MaxResponseBytes); err != nil || response.Version != Version || response.ID != request.ID || (response.Error == nil) == (len(response.Result) == 0) {
		c.Close()
		return Response{}, fabric.NewError(fabric.CodeProtocolError, "Invalid private administration response")
	}
	if ctx.Err() != nil {
		c.Close()
		return Response{}, ctx.Err()
	}
	_ = c.connection.SetDeadline(time.Time{})
	return response, nil
}
