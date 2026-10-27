// Package senderipc exposes only the current proved sender controller to the
// same OS user. It carries text operations, never credentials or provider policy.
package senderipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/localipc"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
)

// Supported reports whether kernel-authenticated same-owner Unix peers are
// available. Other daemon features do not depend on this optional local endpoint.
func Supported() bool              { return supportedOS(runtime.GOOS) }
func supportedOS(goos string) bool { return goos == "linux" || goos == "darwin" }

const Version = 1
const MaxFrame = 128 << 10
const MaxWait = 5 * time.Minute
const frameTimeout = 5 * time.Second

var ErrUnavailable = errors.New("managed sender is unavailable; reconnect its enrolled daemon")
var ErrWaitEnded = errors.New("sender wait ended; resume or inspect the same saved ASK")

type Binding struct {
	Server         string `json:"server"`
	TenantID       string `json:"tenantId"`
	OwnerUserID    string `json:"ownerUserId"`
	HostID         string `json:"hostId"`
	InstallationID string `json:"installationId"`
	ServiceID      string `json:"serviceId"`
}
type Request struct {
	Version     int     `json:"version"`
	Binding     Binding `json:"binding"`
	Action      string  `json:"action"`
	ProjectID   string  `json:"projectId"`
	AskID       string  `json:"askId"`
	RecipientID string  `json:"recipientId,omitempty"`
	Prompt      string  `json:"prompt,omitempty"`
	WaitMillis  int64   `json:"waitMillis,omitempty"`
}
type response struct {
	Version   int               `json:"version"`
	Binding   Binding           `json:"binding"`
	Operation *sender.Operation `json:"operation,omitempty"`
	Error     string            `json:"error,omitempty"`
}

func canonicalID(s string, v7 bool) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && id.String() == s && id.Variant() == uuid.RFC4122 && (!v7 || id.Version() == 7)
}
func (b Binding) valid() bool {
	if b.Server == "" || len(b.Server) > 4096 {
		return false
	}
	for _, id := range []string{b.TenantID, b.OwnerUserID, b.HostID, b.InstallationID, b.ServiceID} {
		if !canonicalID(id, false) {
			return false
		}
	}
	return true
}
func (r Request) valid() bool {
	if r.Version != Version || !r.Binding.valid() || !canonicalID(r.ProjectID, false) || !canonicalID(r.AskID, true) || r.WaitMillis < 0 || r.WaitMillis > MaxWait.Milliseconds() {
		return false
	}
	switch r.Action {
	case "ask":
		return canonicalID(r.RecipientID, false) && r.Prompt != "" && r.WaitMillis > 0
	case "resume":
		return r.RecipientID == "" && r.Prompt == "" && r.WaitMillis > 0
	case "result":
		return r.RecipientID == "" && r.Prompt == "" && r.WaitMillis == 0
	}
	return false
}
func readFrame(conn net.Conn, value any) error {
	raw, err := bufio.NewReaderSize(conn, MaxFrame+1).ReadSlice('\n')
	if err != nil || len(raw) > MaxFrame {
		return errors.New("invalid sender IPC frame")
	}
	if err := fabric.DecodeJSONWithLimits(raw, value, fabric.WireLimits{MaxBytes: MaxFrame, MaxDepth: 12, MaxMembers: 128}); err != nil {
		return errors.New("invalid sender IPC JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid sender IPC JSON")
	}
	return nil
}
func writeFrame(conn net.Conn, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > MaxFrame {
		return errors.New("sender IPC frame too large")
	}
	raw = append(raw, '\n')
	for len(raw) > 0 {
		n, err := conn.Write(raw)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}
func socketPath(state string) (string, error) {
	if !Supported() {
		return "", ErrUnavailable
	}
	if err := textbridge.PrivateDir(state); err != nil {
		return "", ErrUnavailable
	}
	path, err := localipc.TextSenderSocketPath(state)
	if err != nil {
		return "", ErrUnavailable
	}
	if err := textbridge.PrivateDir(filepath.Dir(path)); err != nil {
		return "", ErrUnavailable
	}
	return path, nil
}

type publication struct {
	binding    Binding
	controller *sender.Controller
	ctx        context.Context
	cancel     context.CancelFunc
	handlers   sync.WaitGroup
}
type Server struct {
	listener    net.Listener
	path        string
	info        os.FileInfo
	mu          sync.Mutex
	entries     map[string]*publication
	connections map[net.Conn]bool
	closed      bool
	slots       chan struct{}
	acceptDone  chan struct{}
	handlers    sync.WaitGroup
}

func Listen(state string) (*Server, error) {
	path, err := socketPath(state)
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		checked, err := localipc.CheckTextSenderSocket(path)
		if err != nil {
			return nil, ErrUnavailable
		}
		probe, err := net.DialTimeout("unix", path, frameTimeout)
		if err == nil {
			probe.Close()
			return nil, ErrUnavailable
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, ErrUnavailable
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(info, current) || !os.SameFile(checked, current) {
			return nil, ErrUnavailable
		}
		if err := os.Remove(path); err != nil {
			return nil, ErrUnavailable
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, ErrUnavailable
	}
	if unix, ok := l.(*net.UnixListener); ok {
		unix.SetUnlinkOnClose(false)
	}
	if err := os.Chmod(path, 0600); err != nil {
		l.Close()
		os.Remove(path)
		return nil, ErrUnavailable
	}
	info, err := localipc.CheckTextSenderSocket(path)
	if err != nil {
		l.Close()
		return nil, ErrUnavailable
	}
	s := &Server{listener: l, path: path, info: info, entries: map[string]*publication{}, connections: map[net.Conn]bool{}, slots: make(chan struct{}, 32), acceptDone: make(chan struct{})}
	go s.accept()
	return s, nil
}
func (s *Server) accept() {
	defer close(s.acceptDone)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		select {
		case s.slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			<-s.slots
			return
		}
		s.connections[conn] = true
		s.handlers.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.handlers.Done()
			defer func() { conn.Close(); s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock(); <-s.slots }()
			s.serve(conn)
		}()
	}
}

// Publish is called only after installation proof and controller startup. The
// returned function unpublishes, cancels and joins handlers before store unlock.
func (s *Server) Publish(binding Binding, controller *sender.Controller) (func(), error) {
	if !binding.valid() || controller == nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &publication{binding: binding, controller: controller, ctx: ctx, cancel: cancel}
	s.mu.Lock()
	if s.closed || s.entries[binding.ServiceID] != nil {
		s.mu.Unlock()
		cancel()
		return nil, ErrUnavailable
	}
	s.entries[binding.ServiceID] = p
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		if s.entries[binding.ServiceID] == p {
			delete(s.entries, binding.ServiceID)
		}
		cancel()
		s.mu.Unlock()
		p.handlers.Wait()
	}, nil
}
func (s *Server) serve(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(frameTimeout))
	if _, _, err := localpeer.Owner(conn); err != nil {
		return
	}
	var req Request
	if readFrame(conn, &req) != nil || !req.valid() {
		return
	}
	rsp := response{Version: Version, Binding: req.Binding}
	s.mu.Lock()
	p := s.entries[req.Binding.ServiceID]
	if p == nil || p.binding != req.Binding || p.ctx.Err() != nil {
		s.mu.Unlock()
		rsp.Error = "unavailable"
		writeFrame(conn, rsp)
		return
	}
	p.handlers.Add(1)
	s.mu.Unlock()
	defer p.handlers.Done()
	ctx, cancel := context.WithTimeout(p.ctx, time.Duration(req.WaitMillis)*time.Millisecond+frameTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	conn.SetDeadline(time.Now().Add(time.Duration(req.WaitMillis)*time.Millisecond + frameTimeout))
	// A client leaving its wait must release its bounded handler slot. Only one
	// request is allowed per connection; EOF or extra input cancels this request.
	readExited := make(chan struct{})
	go func() { var extra [1]byte; _, _ = conn.Read(extra[:]); cancel(); close(readExited) }()
	defer func() { conn.SetReadDeadline(time.Now()); <-readExited }()
	var op sender.Operation
	var err error
	switch req.Action {
	case "ask":
		op, err = p.controller.ReserveWithID(ctx, req.ProjectID, req.RecipientID, req.AskID, req.Prompt)
	case "resume":
		op, err = p.controller.Resume(ctx, req.ProjectID, req.AskID)
	case "result":
		op, err = p.controller.Get(ctx, req.ProjectID, req.AskID)
	}
	if err == nil && req.Action != "result" {
		waitCtx, done := context.WithTimeout(ctx, time.Duration(req.WaitMillis)*time.Millisecond)
		op, err = p.controller.Wait(waitCtx, req.ProjectID, req.AskID)
		done()
	}
	if err != nil {
		switch {
		case errors.Is(err, sender.ErrConflict):
			rsp.Error = "conflict"
		case errors.Is(err, sender.ErrInvalid):
			rsp.Error = "invalid"
		case errors.Is(err, sender.ErrNotFound):
			rsp.Error = "not_found"
		case errors.Is(err, context.DeadlineExceeded):
			rsp.Error = "wait_ended"
		default:
			rsp.Error = "unavailable"
		}
	} else {
		rsp.Operation = &op
	}
	if p.ctx.Err() == nil {
		writeFrame(conn, rsp)
	}
}
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for _, p := range s.entries {
		p.cancel()
	}
	s.entries = map[string]*publication{}
	for conn := range s.connections {
		conn.Close()
	}
	s.mu.Unlock()
	s.listener.Close()
	<-s.acceptDone
	s.handlers.Wait()
	if info, err := os.Lstat(s.path); err == nil && os.SameFile(s.info, info) {
		return os.Remove(s.path)
	}
	return nil
}
func Call(ctx context.Context, state string, req Request) (sender.Operation, error) {
	if !req.valid() {
		return sender.Operation{}, sender.ErrInvalid
	}
	path, err := socketPath(state)
	if err != nil {
		return sender.Operation{}, err
	}
	before, err := localipc.CheckTextSenderSocket(path)
	if err != nil {
		return sender.Operation{}, ErrUnavailable
	}
	d := net.Dialer{Timeout: frameTimeout}
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return sender.Operation{}, ErrUnavailable
	}
	defer conn.Close()
	after, err := localipc.CheckTextSenderSocket(path)
	if err != nil || !os.SameFile(before, after) {
		return sender.Operation{}, ErrUnavailable
	}
	if _, _, err := localpeer.Owner(conn); err != nil {
		return sender.Operation{}, ErrUnavailable
	}
	deadline := time.Now().Add(time.Duration(req.WaitMillis)*time.Millisecond + frameTimeout)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	if writeFrame(conn, req) != nil {
		return sender.Operation{}, ErrUnavailable
	}
	var rsp response
	if readFrame(conn, &rsp) != nil || rsp.Version != Version || rsp.Binding != req.Binding {
		return sender.Operation{}, ErrUnavailable
	}
	if rsp.Error != "" {
		switch rsp.Error {
		case "conflict":
			return sender.Operation{}, sender.ErrConflict
		case "invalid":
			return sender.Operation{}, sender.ErrInvalid
		case "not_found":
			return sender.Operation{}, sender.ErrNotFound
		case "wait_ended":
			return sender.Operation{}, ErrWaitEnded
		default:
			return sender.Operation{}, ErrUnavailable
		}
	}
	if rsp.Operation == nil || rsp.Operation.ProjectID != req.ProjectID || rsp.Operation.AskID != req.AskID || (req.Action == "ask" && rsp.Operation.RecipientID != req.RecipientID) {
		return sender.Operation{}, ErrUnavailable
	}
	return *rsp.Operation, nil
}
