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

// ForwardChannel owns its Duplex and serializes complete bounded request
// documents. It never buffers an invocation response: subsequent result/event
// frames require the actual node protocol's one-record pull boundary.
// Receiving a document is NOT authentication/admission; VerifyForwardBundle
// must run before any node execution or destination admission acknowledgement.
type ForwardChannel struct {
	transport         *Duplex
	sendMu, receiveMu sync.Mutex
}

func NewForwardChannel(transport *Duplex) (*ForwardChannel, error) {
	if transport == nil {
		return nil, protocolError()
	}
	return &ForwardChannel{transport: transport}, nil
}
func (c *ForwardChannel) Close() error { return c.transport.Close() }
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
	header, e := c.transport.Receive(ctx)
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
