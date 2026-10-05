// Package fabrichost serves original MCP sessions on an explicitly configured
// private local socket. It never bootstraps identity or contacts a cloud.
package fabrichost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
)

const Protocol = "fabric.mcp"
const AdminProtocol = "fabric.admin.v1"
const (
	EndpointEnvironment   = "PAGNET_FABRIC_ENDPOINT"
	WorkerEnvironment     = "PAGNET_FABRIC_WORKER_ID"
	GenerationEnvironment = "PAGNET_FABRIC_GENERATION"
	NonceEnvironment      = "PAGNET_FABRIC_NONCE"
)

type ManagedSelector struct {
	Endpoint             fabric.EndpointRef
	WorkerID, Generation string
}

// ResolveManaged consults actual current signed binding and authenticated worker
// facts. Selection fields are untrusted selectors, never authentication.
type ManagedResolver func(context.Context, ManagedSelector) (fabricauth.Activation, error)

// VerifiedSessionServer owns a kernel-verified private connection and session.
// Protocol selection never creates authority or changes runtime MCP tools.
type VerifiedSessionServer interface {
	ServeVerified(context.Context, net.Conn, io.Reader, fabricmcp.SessionFactory) error
	CloseContext(context.Context) error
}
type Config struct {
	SocketPath                   string
	Authority                    *fabricauth.Authority
	Server                       VerifiedSessionServer
	Protocols                    map[string]VerifiedSessionServer
	ResolveManaged               ManagedResolver
	MaxConnections, MaxAuthBytes int
	AuthTimeout                  time.Duration
}
type Host struct {
	shutdownErr                       error
	config                            Config
	listener                          *net.UnixListener
	release                           func()
	ctx                               context.Context
	cancel                            context.CancelFunc
	mu                                sync.Mutex
	connections                       map[*net.UnixConn]struct{}
	closed, acceptEnded, serverJoined bool
	done                              chan struct{}
	finish                            sync.Once
}
type Authentication struct {
	Type       string             `json:"type"`
	Protocol   string             `json:"protocol,omitempty"`
	Mode       string             `json:"mode"`
	Endpoint   fabric.EndpointRef `json:"endpoint,omitempty"`
	WorkerID   string             `json:"workerId,omitempty"`
	Generation string             `json:"generation,omitempty"`
	Nonce      string             `json:"nonce,omitempty"`
}

func failure() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Local Fabric peer authentication failed")
}
func bounded(v string, max int) bool {
	return v != "" && len(v) <= max && utf8.ValidString(v) && !strings.ContainsAny(v, "\x00\r\n")
}
func (a Authentication) Validate() error {
	if a.Type != "fabric.auth" || a.Protocol != "" && a.Protocol != Protocol && a.Protocol != AdminProtocol {
		return failure()
	}
	switch a.Mode {
	case "owner":
		if a.Endpoint.String() != "" || a.WorkerID != "" || a.Generation != "" || a.Nonce != "" {
			return failure()
		}
	case "managed":
		if a.Endpoint.IsOffer() || a.Endpoint.String() == "" || !bounded(a.WorkerID, 256) || !bounded(a.Generation, 256) || !bounded(a.Nonce, 512) {
			return failure()
		}
	default:
		return failure()
	}
	return nil
}
func Start(ctx context.Context, config Config) (*Host, error) {
	if err := ValidateSocketPath(config.SocketPath); err != nil {
		return nil, err
	}
	if ctx == nil || ctx.Err() != nil || config.Authority == nil || config.ResolveManaged != nil && !config.Authority.SupportsManaged() || !filepath.IsAbs(config.SocketPath) || filepath.Clean(config.SocketPath) != config.SocketPath {
		return nil, failure()
	}
	protocols := make(map[string]VerifiedSessionServer, 2)
	if config.Server != nil {
		protocols[Protocol] = config.Server
	}
	if len(config.Protocols) > 2 {
		return nil, failure()
	}
	for name, server := range config.Protocols {
		if name != Protocol && name != AdminProtocol || server == nil || protocols[name] != nil {
			return nil, failure()
		}
		protocols[name] = server
	}
	if len(protocols) == 0 {
		return nil, failure()
	}
	seen := make(map[VerifiedSessionServer]bool, 2)
	for _, server := range protocols {
		value := reflect.ValueOf(server)
		if !value.IsValid() || !value.Type().Comparable() || (value.Kind() == reflect.Pointer && value.IsNil()) || seen[server] {
			return nil, failure()
		}
		seen[server] = true
	}
	config.Protocols = protocols
	if config.MaxConnections == 0 {
		config.MaxConnections = 64
	}
	if config.MaxAuthBytes == 0 {
		config.MaxAuthBytes = 8192
	}
	if config.AuthTimeout == 0 {
		config.AuthTimeout = 5 * time.Second
	}
	if config.MaxConnections < 1 || config.MaxConnections > 256 || config.MaxAuthBytes < 1024 || config.MaxAuthBytes > 16384 || config.AuthTimeout < time.Millisecond || config.AuthTimeout > 30*time.Second {
		return nil, failure()
	}
	listener, release, err := listenPrivate(config.SocketPath)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	host := &Host{config: config, listener: listener, release: release, ctx: lifetime, cancel: cancel, connections: map[*net.UnixConn]struct{}{}, done: make(chan struct{})}
	go host.accept()
	go func() {
		<-lifetime.Done()
		host.Close()
		var joined sync.WaitGroup
		var errorsMu sync.Mutex
		var shutdownErr error
		for _, server := range config.Protocols {
			joined.Add(1)
			go func(server VerifiedSessionServer) {
				defer joined.Done()
				err := server.CloseContext(context.Background())
				errorsMu.Lock()
				shutdownErr = errors.Join(shutdownErr, err)
				errorsMu.Unlock()
			}(server)
		}
		joined.Wait()
		host.mu.Lock()
		host.shutdownErr = shutdownErr
		host.serverJoined = true
		host.finishLocked()
		host.mu.Unlock()
	}()
	return host, nil
}
func (h *Host) accept() {
	defer func() { h.mu.Lock(); h.acceptEnded = true; h.finishLocked(); h.mu.Unlock() }()
	for {
		c, err := h.listener.AcceptUnix()
		if err != nil {
			return
		}
		h.mu.Lock()
		if h.closed || len(h.connections) >= h.config.MaxConnections {
			h.mu.Unlock()
			c.Close()
			continue
		}
		h.connections[c] = struct{}{}
		h.mu.Unlock()
		go h.serve(c)
	}
}
func (h *Host) finishLocked() {
	if h.closed && h.acceptEnded && h.serverJoined && len(h.connections) == 0 {
		h.finish.Do(func() { h.release(); close(h.done) })
	}
}
func authLine(reader *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(line)+len(part) > max {
			return nil, failure()
		}
		line = append(line, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, failure()
		}
		return line, nil
	}
}
func parseAuth(raw []byte, max int) (Authentication, error) {
	var a Authentication
	if fabric.DecodeJSONWithLimits(raw, &a, fabric.WireLimits{MaxBytes: max, MaxDepth: 8, MaxMembers: 32}) != nil {
		return a, failure()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&a) != nil || a.Validate() != nil {
		return a, failure()
	}
	return a, nil
}
func (h *Host) serve(c *net.UnixConn) {
	defer func() { c.Close(); h.mu.Lock(); delete(h.connections, c); h.finishLocked(); h.mu.Unlock() }()
	authenticated, cancel := context.WithTimeout(h.ctx, h.config.AuthTimeout)
	defer cancel()
	c.SetDeadline(time.Now().Add(h.config.AuthTimeout))
	reader := bufio.NewReader(c)
	raw, err := authLine(reader, h.config.MaxAuthBytes)
	if err != nil {
		return
	}
	request, err := parseAuth(raw, h.config.MaxAuthBytes)
	clear(raw)
	if err != nil {
		return
	}
	protocol := request.Protocol
	if protocol == "" {
		protocol = Protocol
	}
	server := h.config.Protocols[protocol]
	if server == nil || protocol == AdminProtocol && request.Mode != "owner" {
		return
	}
	var session *fabricauth.Session
	if request.Mode == "owner" {
		session, err = h.config.Authority.BindOwner(authenticated, c)
	} else {
		if h.config.ResolveManaged == nil {
			return
		}
		activation, resolveErr := h.config.ResolveManaged(authenticated, ManagedSelector{request.Endpoint, request.WorkerID, request.Generation})
		local, ok := activation.Scope.Local()
		if resolveErr != nil || !ok || local.Endpoint != request.Endpoint || local.WorkerID != request.WorkerID || activation.NativeGeneration != request.Generation || !bounded(activation.Nonce, 512) || !hmac.Equal([]byte(request.Nonce), []byte(activation.Nonce)) {
			return
		}
		session, err = h.config.Authority.BindManaged(authenticated, c, activation)
	}
	request.Nonce = ""
	if err != nil || session == nil {
		if session != nil {
			session.Close()
		}
		return
	}
	transferred := false
	defer func() {
		if !transferred {
			session.Close()
		}
	}()
	if _, err = io.WriteString(c, "{\"type\":\"fabric.ready\",\"protocol\":\""+protocol+"\"}\n"); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	transferred = true
	_ = server.ServeVerified(h.ctx, c, reader, session)
}
func (h *Host) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	connections := make([]*net.UnixConn, 0, len(h.connections))
	for c := range h.connections {
		connections = append(connections, c)
	}
	h.mu.Unlock()
	h.cancel()
	h.listener.Close()
	for _, c := range connections {
		c.Close()
	}
	return nil
}

// CloseContext waits for all authenticated/unauthenticated handlers, actual SDK
// callbacks and factory cleanup before releasing the socket's lifetime lock.
func (h *Host) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return failure()
	}
	h.Close()
	select {
	case <-h.done:
		return h.shutdownErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
