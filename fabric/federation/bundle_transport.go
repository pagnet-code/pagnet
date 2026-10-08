package federation

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

const bundleStart = byte(1)
const bundleChunk = byte(2)
const bundleEnd = byte(3)

// UnitKind identifies the first plaintext record of one relay connection. The
// blind relay dispatches on it before any unit-specific handling: UnitBundle
// leads to ReceiveBundle (records 1..3), UnitControl to ReceiveControl
// (record 4, reply record 5, pull frames record 6).
type UnitKind int

const (
	UnitBundle  UnitKind = 1 // bundleStart: one bounded forward bundle
	UnitControl UnitKind = 4 // controlRequestRecord: one committed control unit
)

// ForwardChannel owns its Duplex and serializes complete bounded request
// documents. It never buffers an invocation response: subsequent result/event
// frames require the actual node protocol's one-record pull boundary.
// Receiving a document is NOT authentication/admission; VerifyForwardBundle
// must run before any node execution or destination admission acknowledgement.
type ForwardChannel struct {
	transport         *Duplex
	sendMu, receiveMu sync.Mutex
	pending           []byte
}

func NewForwardChannel(transport *Duplex) (*ForwardChannel, error) {
	if transport == nil {
		return nil, protocolError()
	}
	return &ForwardChannel{transport: transport}, nil
}
func (c *ForwardChannel) Close() error { return c.transport.Close() }

// DispatchFirst reads the first plaintext record and retains it for the
// subsequent typed receive. Any other first record is a protocol error that
// closes the channel. The caller must follow with the matching typed receive
// (ReceiveBundle or ReceiveControl), which consumes and clears the retained
// record.
func (c *ForwardChannel) DispatchFirst(ctx context.Context) (UnitKind, error) {
	c.receiveMu.Lock()
	defer c.receiveMu.Unlock()
	if c.pending != nil {
		return 0, protocolError()
	}
	raw, e := c.transport.Receive(ctx)
	if e != nil {
		return 0, e
	}
	var kind UnitKind
	switch {
	case len(raw) == 37 && raw[0] == bundleStart:
		kind = UnitBundle
	case len(raw) >= 2 && raw[0] == controlRequestRecord:
		kind = UnitControl
	default:
		clear(raw)
		_ = c.transport.Close()
		return 0, protocolError()
	}
	c.pending = raw
	return kind, nil
}

// takePending returns the first record retained by DispatchFirst when one was
// retained, otherwise reads the next record. Callers hold receiveMu and clear
// the returned slice.
func (c *ForwardChannel) takePending(ctx context.Context) ([]byte, error) {
	if c.pending != nil {
		p := c.pending
		c.pending = nil
		return p, nil
	}
	return c.transport.Receive(ctx)
}
func (c *ForwardChannel) SendBundle(ctx context.Context, b ForwardBundle) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	raw, e := EncodeForwardBundle(b)
	if e != nil {
		return e
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	header := make([]byte, 37)
	header[0] = bundleStart
	binary.BigEndian.PutUint32(header[1:5], uint32(len(raw)))
	copy(header[5:], digest[:])
	if e = c.transport.Send(ctx, header); e != nil {
		return e
	}
	for offset := 0; offset < len(raw); {
		end := min(offset+MaxRecordPlaintext-1, len(raw))
		chunk := make([]byte, 1+end-offset)
		chunk[0] = bundleChunk
		copy(chunk[1:], raw[offset:end])
		e = c.transport.Send(ctx, chunk)
		clear(chunk)
		if e != nil {
			return e
		}
		offset = end
	}
	end := make([]byte, 33)
	end[0] = bundleEnd
	copy(end[1:], digest[:])
	return c.transport.Send(ctx, end)
}
func (c *ForwardChannel) ReceiveBundle(ctx context.Context) (ForwardBundle, error) {
	c.receiveMu.Lock()
	defer c.receiveMu.Unlock()
	fail := func(e error) (ForwardBundle, error) { _ = c.Close(); return ForwardBundle{}, e }
	header, e := c.takePending(ctx)
	if e != nil {
		return fail(e)
	}
	defer clear(header)
	if len(header) != 37 || header[0] != bundleStart {
		return fail(protocolError())
	}
	size := binary.BigEndian.Uint32(header[1:5])
	if size == 0 || size > MaxForwardBundleBytes {
		return fail(protocolError())
	}
	var wanted [32]byte
	copy(wanted[:], header[5:])
	raw := make([]byte, int(size))
	defer clear(raw)
	offset := 0
	for offset < len(raw) {
		chunk, e := c.transport.Receive(ctx)
		if e != nil {
			return fail(e)
		}
		if len(chunk) <= 1 || chunk[0] != bundleChunk || len(chunk)-1 > len(raw)-offset {
			clear(chunk)
			return fail(protocolError())
		}
		offset += copy(raw[offset:], chunk[1:])
		clear(chunk)
	}
	final, e := c.transport.Receive(ctx)
	if e != nil {
		return fail(e)
	}
	defer clear(final)
	var tail [32]byte
	if len(final) == 33 {
		copy(tail[:], final[1:])
	}
	if len(final) != 33 || final[0] != bundleEnd || tail != wanted || sha256.Sum256(raw) != wanted {
		return fail(protocolError())
	}
	b, e := DecodeForwardBundle(raw)
	if e != nil {
		return fail(e)
	}
	return b, nil
}
