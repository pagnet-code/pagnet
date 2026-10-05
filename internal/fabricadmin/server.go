// Package fabricadmin serves bounded private owner management operations. It
// provides transport/authentication, never runtime tools or implicit bootstrap.
package fabricadmin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
)

const Version = 1
const MaxRequestBytes = 64 << 10
const MaxResponseBytes = 1 << 20

type Request struct {
	Version          int             `json:"version"`
	ID               string          `json:"id"`
	Operation        string          `json:"operation"`
	Input            json.RawMessage `json:"input"`
	ExpectedRevision string          `json:"expectedRevision,omitempty"`
}
type Response struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *fabric.Error   `json:"error,omitempty"`
}

// Handler uses already retained installation resources. It obtains the genuine
// installation operator only inside this authenticated callback and verifies
// current capability outside SQL. It must honor context cancellation. Provider
// errors/credentials are never serialized implicitly by this package.
type Handler func(context.Context, *fabricauth.OwnerAdministration, Request) (json.RawMessage, error)
type Config struct {
	Handlers                      map[string]Handler
	MaxConnections                int
	OperationTimeout, IdleTimeout time.Duration
}
type Server struct {
	config      Config
	mu          sync.Mutex
	connections map[net.Conn]context.CancelFunc
	closed      bool
	done        chan struct{}
}

func failure() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Current private owner administration session required")
}
func validText(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func (r Request) Validate() error {
	if r.Version != Version || !validText(r.ID, 128) || !fabric.ValidNamespacedName(r.Operation) || len(r.Operation) > 128 || len(r.ExpectedRevision) > 256 || r.ExpectedRevision != "" && !validText(r.ExpectedRevision, 256) || len(r.Input) == 0 {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid private administration request")
	}
	var input any
	return fabric.DecodeJSONWithLimits(r.Input, &input, fabric.WireLimits{MaxBytes: MaxRequestBytes, MaxDepth: 32, MaxMembers: 2048})
}
func New(c Config) (*Server, error) {
	if len(c.Handlers) == 0 || len(c.Handlers) > 128 {
		return nil, failure()
	}
	copyHandlers := make(map[string]Handler, len(c.Handlers))
	for operation, handler := range c.Handlers {
		if !fabric.ValidNamespacedName(operation) || len(operation) > 128 || handler == nil {
			return nil, failure()
		}
		copyHandlers[operation] = handler
	}
	c.Handlers = copyHandlers
	if c.MaxConnections == 0 {
		c.MaxConnections = 64
	}
	if c.OperationTimeout == 0 {
		c.OperationTimeout = 30 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = time.Minute
	}
	if c.MaxConnections < 1 || c.MaxConnections > 256 || c.OperationTimeout < time.Millisecond || c.OperationTimeout > time.Minute || c.IdleTimeout < time.Millisecond || c.IdleTimeout > 5*time.Minute {
		return nil, failure()
	}
	return &Server{config: c, connections: map[net.Conn]context.CancelFunc{}, done: make(chan struct{})}, nil
}
func (s *Server) ServeVerified(ctx context.Context, connection net.Conn, input io.Reader, factory fabricmcp.SessionFactory) error {
	if factory != nil {
		defer factory.Close()
	}
	if connection != nil {
		defer connection.Close()
	}
	session, ok := factory.(*fabricauth.Session)
	if s == nil || ctx == nil || ctx.Err() != nil || connection == nil || input == nil || !ok || session == nil {
		return failure()
	}
	lifetime, cancel := context.WithCancel(ctx)
	defer cancel()
	s.mu.Lock()
	if s.closed || len(s.connections) >= s.config.MaxConnections {
		s.mu.Unlock()
		return failure()
	}
	s.connections[connection] = cancel
	s.mu.Unlock()
	defer func() {
		session.Close()
		connection.Close()
		s.mu.Lock()
		delete(s.connections, connection)
		if s.closed && len(s.connections) == 0 {
			select {
			case <-s.done:
			default:
				close(s.done)
			}
		}
		s.mu.Unlock()
	}()
	stop := context.AfterFunc(lifetime, func() { session.Close(); connection.Close() })
	defer stop()
	packets := make(chan []byte, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		defer cancel()
		defer session.Close()
		defer connection.Close()
		reader := bufio.NewReader(input)
		for {
			_ = connection.SetReadDeadline(time.Now().Add(s.config.IdleTimeout))
			line, err := readLine(reader, MaxRequestBytes)
			if err != nil {
				return
			}
			select {
			case packets <- line:
			case <-lifetime.Done():
				clear(line)
				return
			default:
				clear(line)
				return
			}
		}
	}()
	defer func() {
		cancel()
		connection.Close()
		<-readDone
		for {
			select {
			case pending := <-packets:
				clear(pending)
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-lifetime.Done():
			return lifetime.Err()
		case line := <-packets:
			var request Request
			err := decodeStrict(line, &request, MaxRequestBytes)
			if err == nil {
				err = request.Validate()
			}
			if err != nil {
				clear(line)
				return fabric.NewError(fabric.CodeProtocolError, "Malformed private administration request")
			}
			handler := s.config.Handlers[request.Operation]
			if handler == nil {
				handler = func(context.Context, *fabricauth.OwnerAdministration, Request) (json.RawMessage, error) {
					return nil, fabric.NewError(fabric.CodeUnsupported, "Private administration operation is not registered")
				}
			}
			call, callCancel := context.WithTimeout(lifetime, s.config.OperationTimeout)
			var result json.RawMessage
			err = session.WithOwnerAdministration(call, line, func(current context.Context, owner *fabricauth.OwnerAdministration) (err error) {
				defer func() {
					if recover() != nil {
						err = fabric.NewError(fabric.CodeProtocolError, "Private administration handler failed")
					}
				}()
				owned := request
				owned.Input = bytes.Clone(request.Input)
				defer clear(owned.Input)
				result, err = handler(current, owner, owned)
				if err != nil {
					result = nil
					return err
				}
				if err == nil {
					var decoded any
					if len(result) == 0 || len(result) > MaxResponseBytes-2048 || fabric.DecodeJSONWithLimits(result, &decoded, fabric.WireLimits{MaxBytes: MaxResponseBytes - 2048, MaxDepth: 62, MaxMembers: 4080}) != nil {
						result = nil
						return fabric.NewError(fabric.CodeProtocolError, "Private administration result exceeds bounds")
					}
					result = bytes.Clone(result)
				}
				return err
			})
			clear(line)
			callCancel()
			response := Response{Version: Version, ID: request.ID, Result: result}
			if err != nil {
				clear(result)
				response.Result = nil
				response.Error = publicError(err)
			}
			encoded, encodeErr := json.Marshal(response)
			clear(result)
			if encodeErr != nil || len(encoded) > MaxResponseBytes {
				return fabric.NewError(fabric.CodeProtocolError, "Private administration response exceeds bounds")
			}
			_ = connection.SetWriteDeadline(time.Now().Add(s.config.OperationTimeout))
			_, writeErr := connection.Write(append(encoded, '\n'))
			clear(encoded)
			if writeErr != nil {
				return writeErr
			}
			if lifetime.Err() != nil {
				return lifetime.Err()
			}
		}
	}
}
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	line := make([]byte, 0, 4096)
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > max {
			clear(line)
			return nil, fabric.NewError(fabric.CodeProtocolError, "Private administration frame exceeds bounds")
		}
		line = append(line, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			clear(line)
			return nil, err
		}
		return line, nil
	}
}
func decodeStrict(raw []byte, out any, max int) error {
	if err := fabric.DecodeJSONWithLimits(raw, out, fabric.WireLimits{MaxBytes: max, MaxDepth: 64, MaxMembers: 4096}); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}
func publicError(err error) *fabric.Error {
	out := fabric.NewError(fabric.CodeProtocolError, "Private administration failed; effects may be unknown")
	var typed *fabric.Error
	if errors.As(err, &typed) && typed != nil && validText(string(typed.Code), 128) {
		for _, r := range typed.Code {
			if r > 127 || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
				return out
			}
		}
		out.Code = typed.Code
		switch typed.Effect {
		case fabric.EffectNotStarted, fabric.EffectCompleted, fabric.EffectUnknown:
			out.Effect = typed.Effect
		}
	}
	return out
}
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	connections := make(map[net.Conn]context.CancelFunc, len(s.connections))
	for c, cancel := range s.connections {
		connections[c] = cancel
	}
	if len(connections) == 0 {
		close(s.done)
	}
	s.mu.Unlock()
	for c, cancel := range connections {
		cancel()
		c.Close()
	}
	return nil
}
func (s *Server) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return failure()
	}
	if s == nil {
		return nil
	}
	s.Close()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
