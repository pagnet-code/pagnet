package federation

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// PacketStream owns one explicitly selected connection. Implementations must
// synchronously backpressure each bounded record; Close unblocks both directions.
// EOF and successful writes never imply native invocation completion/admission.
type PacketStream interface {
	Read(context.Context) (Packet, error)
	Write(context.Context, Packet) error
	Close() error
}

type ConnStream struct {
	conn            net.Conn
	timeout         time.Duration
	readMu, writeMu sync.Mutex
	closeOnce       sync.Once
	closeErr        error
}

// NewConnStream transfers exclusive connection/deadline ownership. A finite
// operator-selected timeout is mandatory even if the caller has no deadline.
func NewConnStream(conn net.Conn, timeout time.Duration) (*ConnStream, error) {
	if conn == nil || timeout <= 0 || timeout > 5*time.Minute {
		return nil, protocolError()
	}
	return &ConnStream{conn: conn, timeout: timeout}, nil
}
func (s *ConnStream) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.conn.Close() })
	return s.closeErr
}

func (s *ConnStream) deadline(ctx context.Context, read bool) (func(), error) {
	if ctx == nil {
		return nil, protocolError()
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	limit := time.Now().Add(s.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(limit) {
		limit = d
	}
	set := s.conn.SetWriteDeadline
	if read {
		set = s.conn.SetReadDeadline
	}
	if e := set(limit); e != nil {
		return nil, e
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = set(time.Now()); close(done) })
	return func() {
		if !stop() {
			<-done
		}
	}, nil
}
func (s *ConnStream) Read(ctx context.Context) (Packet, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	finish, e := s.deadline(ctx, true)
	if e != nil {
		return Packet{}, e
	}
	defer finish()
	var header [4]byte
	if _, e = io.ReadFull(s.conn, header[:]); e != nil {
		_ = s.Close()
		if ctx.Err() != nil {
			return Packet{}, ctx.Err()
		}
		return Packet{}, e
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxRecordWire {
		_ = s.Close()
		return Packet{}, protocolError()
	}
	raw := make([]byte, int(size))
	defer clear(raw)
	if _, e = io.ReadFull(s.conn, raw); e != nil {
		_ = s.Close()
		if ctx.Err() != nil {
			return Packet{}, ctx.Err()
		}
		return Packet{}, e
	}
	packet, e := DecodePacket(raw)
	if e != nil {
		_ = s.Close()
		return Packet{}, e
	}
	return packet, nil
}
func (s *ConnStream) Write(ctx context.Context, p Packet) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	raw, e := EncodePacket(p)
	if e != nil {
		return e
	}
	defer clear(raw)
	finish, e := s.deadline(ctx, false)
	if e != nil {
		return e
	}
	defer finish()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	for _, part := range [][]byte{header[:], raw} {
		for len(part) > 0 {
			n, err := s.conn.Write(part)
			if err != nil || n <= 0 {
				_ = s.Close()
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if err != nil {
					return err
				}
				return io.ErrNoProgress
			}
			part = part[n:]
		}
	}
	return nil
}

// Duplex is an encrypted record transport, not an invocation/proof validator.
// Trust is checked by HPKE on every record. The actual node verifies signed
// original/finalized forward provenance before interpreting plaintext.
type Duplex struct {
	stream            PacketStream
	sender            *Sender
	receiver          *Receiver
	sendMu, receiveMu sync.Mutex
	budgetMu          sync.Mutex
	bytes             uint64
	maxBytes          uint64
	closed            bool
}

func NewDuplex(ctx context.Context, c Config, stream PacketStream, maxBytes uint64) (*Duplex, error) {
	if stream == nil || maxBytes == 0 || maxBytes > 128<<20 {
		return nil, protocolError()
	}
	sender, e := NewSender(ctx, c)
	if e != nil {
		return nil, e
	}
	receiver, e := NewReceiver(c)
	if e != nil {
		return nil, e
	}
	return &Duplex{stream: stream, sender: sender, receiver: receiver, maxBytes: maxBytes}, nil
}
func (d *Duplex) Close() error {
	d.budgetMu.Lock()
	d.closed = true
	d.budgetMu.Unlock()
	return d.stream.Close()
}
func (d *Duplex) reserve(n int) error {
	d.budgetMu.Lock()
	defer d.budgetMu.Unlock()
	if d.closed || n <= 0 || uint64(n) > d.maxBytes-d.bytes {
		return protocolError()
	}
	d.bytes += uint64(n)
	return nil
}
func (d *Duplex) Send(ctx context.Context, plaintext []byte) error {
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	if e := d.reserve(len(plaintext)); e != nil {
		_ = d.Close()
		return e
	}
	p, e := d.sender.Seal(ctx, plaintext)
	if e != nil {
		_ = d.Close()
		return e
	}
	if e = d.stream.Write(ctx, p); e != nil {
		_ = d.Close()
		return e
	}
	return nil
}
func (d *Duplex) Receive(ctx context.Context) ([]byte, error) {
	d.receiveMu.Lock()
	defer d.receiveMu.Unlock()
	p, e := d.stream.Read(ctx)
	if e != nil {
		_ = d.Close()
		return nil, e
	}
	plain, e := d.receiver.Open(ctx, p)
	if e != nil {
		_ = d.Close()
		return nil, e
	}
	if e = d.reserve(len(plain)); e != nil {
		clear(plain)
		_ = d.Close()
		return nil, e
	}
	return plain, nil
}
