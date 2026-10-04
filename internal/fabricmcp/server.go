// Package fabricmcp composes the official MCP server with a privately verified
// local connection. Peer authentication and original envelope signing are
// supplied by the actual node owner; protocol input never creates an identity.
package fabricmcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
)

type SessionFactory interface {
	mcpbridge.EnvelopeFactory
	io.Closer
}

type Config struct {
	Executor         mcpbridge.Executor
	BridgeLimits     mcpbridge.Limits
	MaxConnections   int
	MaxLineBytes     int
	ProtocolVersions []string
}
type Server struct {
	config      Config
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
	done        chan struct{}
}

func New(config Config) (*Server, error) {
	if config.Executor == nil {
		return nil, denied()
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 64
	}
	if config.MaxLineBytes == 0 {
		config.MaxLineBytes = 1 << 20
	}
	if config.MaxConnections < 1 || config.MaxConnections > 256 || config.MaxLineBytes < 1024 || config.MaxLineBytes > 2<<20 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid local MCP transport bounds")
	}
	config.ProtocolVersions = append([]string(nil), config.ProtocolVersions...)
	return &Server{config: config, connections: map[net.Conn]struct{}{}, done: make(chan struct{})}, nil
}
func denied() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Verified local MCP peer required")
}

type bound struct {
	mu      sync.Mutex
	factory mcpbridge.EnvelopeFactory
	key     string
	session *sdk.ServerSession
	closed  bool
}

func (b *bound) Bind(ctx context.Context, r *sdk.CallToolRequest) (mcpbridge.BoundSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || b.closed || r == nil || r.Session == nil {
		return mcpbridge.BoundSession{}, denied()
	}
	if b.session == nil {
		b.session = r.Session
	} else if b.session != r.Session {
		return mcpbridge.BoundSession{}, denied()
	}
	return mcpbridge.BoundSession{Key: b.key, Factory: b.factory}, nil
}

type input struct {
	reader       *bufio.Reader
	connection   net.Conn
	max          int
	pending      []byte
	closeSession func()
}

func (r *input) Read(out []byte) (int, error) {
	if len(out) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		line := make([]byte, 0, 4096)
		for {
			part, err := r.reader.ReadSlice('\n')
			if len(line)+len(part) > r.max {
				r.closeSession()
				return 0, fabric.NewError(fabric.CodeProtocolError, "Local MCP frame exceeds bound")
			}
			line = append(line, part...)
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				r.closeSession()
				if len(line) > 0 {
					return 0, fabric.NewError(fabric.CodeProtocolError, "Incomplete local MCP frame")
				}
				return 0, err
			}
			break
		}
		var raw json.RawMessage
		if err := fabric.DecodeJSONWithLimits(bytes.TrimSpace(line), &raw, fabric.WireLimits{MaxBytes: r.max, MaxDepth: 64, MaxMembers: 4096}); err != nil {
			r.closeSession()
			return 0, err
		}
		r.pending = line
	}
	n := copy(out, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
func (r *input) Close() error { r.closeSession(); return r.connection.Close() }

// ServeVerified takes ownership of a connection AFTER an actual peer authority
// has authenticated it. Factory must sign original envelopes for that exact
// peer, with current revocation checks. It is never read from protocol JSON.
// reader preserves any bytes prefetched while reading the preceding handshake.
func (s *Server) ServeVerified(ctx context.Context, connection net.Conn, reader io.Reader, factory SessionFactory) error {
	registered := false
	defer func() {
		if connection != nil {
			_ = connection.Close()
		}
		if factory != nil {
			_ = factory.Close()
		}
		if registered {
			s.mu.Lock()
			delete(s.connections, connection)
			if s.closed && len(s.connections) == 0 {
				close(s.done)
			}
			s.mu.Unlock()
		}
	}()
	if ctx == nil || connection == nil || reader == nil || factory == nil {
		return denied()
	}
	s.mu.Lock()
	if s.closed || len(s.connections) >= s.config.MaxConnections {
		s.mu.Unlock()
		return fabric.NewError(fabric.CodeTargetUnavailable, "Local MCP connection capacity unavailable")
	}
	s.connections[connection] = struct{}{}
	registered = true
	s.mu.Unlock()
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return denied()
	}
	binding := &bound{factory: factory, key: hex.EncodeToString(token[:])}
	bridge, err := mcpbridge.New(ctx, mcpbridge.Config{Service: s.config.Executor, BindSession: binding, Limits: s.config.BridgeLimits, ProtocolVersions: s.config.ProtocolVersions})
	if err != nil {
		return err
	}
	defer bridge.Close()
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			binding.mu.Lock()
			binding.closed = true
			binding.mu.Unlock()
			bridge.CloseSession(binding.key)
		})
	}
	defer cleanup()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	session, err := bridge.Server().Connect(ctx, &sdk.IOTransport{Reader: &input{reader: bufio.NewReader(reader), connection: connection, max: s.config.MaxLineBytes, closeSession: cleanup}, Writer: connection, MaxLineLength: s.config.MaxLineBytes}, nil)
	if err != nil {
		return err
	}
	defer session.Close()
	return session.Wait()
}

// Close interrupts owned SDK connections. Their ServeVerified calls join SDK
// handlers and cancel private stream handles before returning.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	connections := make([]net.Conn, 0, len(s.connections))
	for c := range s.connections {
		connections = append(connections, c)
	}
	if len(s.connections) == 0 {
		close(s.done)
	}
	s.mu.Unlock()
	var result error
	for _, c := range connections {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	return result
}

// CloseContext interrupts sockets and waits until all accepted SDK handlers,
// bridge streams and identity factories have cleaned up. Cancellation-ignoring
// providers may outlive the caller's deadline; they are never declared stopped.
func (s *Server) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Missing MCP shutdown context")
	}
	err := s.Close()
	select {
	case <-s.done:
		return err
	default:
	}
	select {
	case <-s.done:
		return err
	case <-ctx.Done():
		return errors.Join(err, ctx.Err())
	}
}
