package sessionworker

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/internal/localpeer"
)

const maxTerminalQueueBytes = 256 << 10
const maxTerminalInputBytes = 4096

type terminalFrame struct {
	NativeGeneration string `json:"nativeGeneration"`
	Data             []byte `json:"data,omitempty"`
	Rows             uint16 `json:"rows,omitempty"`
	Cols             uint16 `json:"cols,omitempty"`
}

// TerminalStream is an ephemeral, bounded input lane under an already-current
// controller. Queueing is not delivery acknowledgment. EOF discards pending
// bytes; reconnect must never replay uncertain keystrokes or paste.
type TerminalStream struct {
	conn       net.Conn
	generation string
	mu         sync.Mutex
	queue      [][]byte
	queued     int
	resize     *terminalFrame
	err        error
	wake       chan struct{}
	done       chan struct{}
	once       sync.Once
}

func (c *Controller) OpenTerminalStream(ctx context.Context, dir string, scope Scope, key []byte, generation string) (*TerminalStream, error) {
	if c.Ownership != NativeOwnershipProtocol || c.identity == "" || c.Lease <= 0 || len(key) != 32 || generation == "" {
		return nil, errors.New("whole native terminal authority missing")
	}
	path, err := SocketPath(dir)
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*TerminalStream, error) { _ = conn.Close(); return nil, err }
	if _, _, err = localpeer.Owner(conn); err != nil {
		return fail(err)
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	var hello handshake
	if err = readFrame(conn, &hello); err != nil {
		return fail(err)
	}
	if hello.NativeGeneration != "" || hello.Error != "" || hello.Protocol != Protocol || hello.Scope != scope || hello.Ownership != c.Ownership || hello.WorkerBuild != c.WorkerBuild || hello.Mode != "" || !validNonce(hello.ServerNonce) || hello.ClientNonce != "" || hello.ControllerID != "" || hello.Lease != 0 || hello.Proof != "" {
		return fail(errors.New("terminal worker authority differs"))
	}
	hello.Mode = "terminal"
	hello.NativeGeneration = generation
	hello.Lease = c.Lease
	hello.ControllerID = c.identity
	hello.ClientNonce, err = freshNonce()
	if err != nil {
		return fail(err)
	}
	hello.Proof = authenticationProof(key, "controller", hello)
	if err = writeFrame(conn, hello); err != nil {
		return fail(err)
	}
	var reply handshake
	if err = readFrame(conn, &reply); err != nil {
		return fail(err)
	}
	if reply.NativeGeneration != hello.NativeGeneration || reply.Mode != hello.Mode || reply.Lease != hello.Lease || reply.Protocol != hello.Protocol || reply.Scope != hello.Scope || reply.Ownership != hello.Ownership || reply.WorkerBuild != hello.WorkerBuild || reply.ControllerID != hello.ControllerID || reply.ServerNonce != hello.ServerNonce || reply.ClientNonce != hello.ClientNonce || !equalProof(reply.Proof, authenticationProof(key, "worker", reply)) {
		return fail(errors.New("terminal mutual authentication failed"))
	}
	if reply.Error != "" {
		return fail(errors.New(reply.Error))
	}
	_ = conn.SetDeadline(time.Time{})
	return newTerminalStream(conn, generation), nil
}
func newTerminalStream(conn net.Conn, generation string) *TerminalStream {
	stream := &TerminalStream{conn: conn, generation: generation, wake: make(chan struct{}, 1), done: make(chan struct{})}
	go stream.writeLoop()
	go func() {
		var response Response
		err := readBoundedFrame(conn, &response, 16<<10)
		if err == nil {
			err = errors.New(response.Error)
		}
		stream.finish(errors.Join(errors.New("terminal connection ended; queued input will not be replayed"), err))
	}()
	return stream

}

func (s *TerminalStream) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *TerminalStream) SendInput(data []byte) error {
	if len(data) == 0 || len(data) > maxTerminalInputBytes {
		return errors.New("invalid terminal input batch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.queued+len(data) > maxTerminalQueueBytes || len(s.queue) >= 4096 {
		return ErrFull
	}
	s.queue = append(s.queue, append([]byte(nil), data...))
	s.queued += len(data)
	s.signal()
	return nil
}
func (s *TerminalStream) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 || rows > 1000 || cols > 1000 {
		return errors.New("invalid terminal dimensions")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.resize = &terminalFrame{NativeGeneration: s.generation, Rows: rows, Cols: cols}
	s.signal()
	return nil
}
func (s *TerminalStream) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *TerminalStream) Close() error {
	s.finish(errors.New("terminal closed; queued input will not be replayed"))
	return nil
}
func (s *TerminalStream) finish(err error) {
	s.once.Do(func() {
		s.mu.Lock()
		s.err = err
		for _, data := range s.queue {
			clear(data)
		}
		s.queue = nil
		s.queued = 0
		s.resize = nil
		s.mu.Unlock()
		close(s.done)
		_ = s.conn.Close()
	})
}
func (s *TerminalStream) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case <-s.wake:
		}
		// A tiny bounded window batches keys and coalesces resize without an ACK.
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-s.done:
			timer.Stop()
			return
		case <-timer.C:
		}
		for {
			s.mu.Lock()
			if s.err != nil {
				s.mu.Unlock()
				return
			}
			frame := terminalFrame{NativeGeneration: s.generation}
			for len(s.queue) > 0 && len(frame.Data)+len(s.queue[0]) <= maxTerminalInputBytes {
				data := s.queue[0]
				frame.Data = append(frame.Data, data...)
				s.queued -= len(data)
				clear(data)
				s.queue[0] = nil
				s.queue = s.queue[1:]
			}
			if s.resize != nil {
				frame.Rows = s.resize.Rows
				frame.Cols = s.resize.Cols
				s.resize = nil
			}
			more := len(s.queue) > 0
			s.mu.Unlock()
			if len(frame.Data) == 0 && frame.Rows == 0 {
				break
			}
			_ = s.conn.SetWriteDeadline(time.Now().Add(time.Second))
			err := writeFrame(s.conn, frame)
			clear(frame.Data)
			if err != nil {
				s.finish(errors.Join(errors.New("terminal input delivery uncertain; never replay it"), err))
				return
			}
			if !more {
				break
			}
		}
	}
}

func serveTerminalStream(ctx context.Context, conn *net.UnixConn, owner *SessionOwner, current *currentController, lease int64) {
	for {
		var frame terminalFrame
		if err := readBoundedFrame(conn, &frame, 16<<10); err != nil {
			return
		}
		if len(frame.Data) > maxTerminalInputBytes || len(frame.Data) == 0 && frame.Rows == 0 {
			return
		}
		err := current.terminalEffect(lease, conn, func() error {
			owner.relay.mu.Lock()
			admitted := !owner.relay.closed && owner.relay.lease == lease && owner.relay.admission != nil
			owner.relay.mu.Unlock()
			if !admitted {
				return errors.New("fresh control-plane admission required for terminal input")
			}
			if len(frame.Data) > 0 {
				if err := owner.writeInput(Operation{NativeGeneration: frame.NativeGeneration, Data: frame.Data}); err != nil {
					return err
				}
			}
			if frame.Rows > 0 {
				return owner.resize(Operation{NativeGeneration: frame.NativeGeneration, Rows: frame.Rows, Cols: frame.Cols})
			}
			return nil
		})
		clear(frame.Data)
		if err != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_ = writeFrame(conn, Response{Error: err.Error()})
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func (o *SessionOwner) hasLiveTerminal(generation string) bool {
	o.mu.Lock()
	available := o.terminal != nil && generation != "" && generation == o.generation && o.fatal == nil
	o.mu.Unlock()
	return available && o.driver != nil && o.driver.Live(o.journal.scope.InstanceID)
}
