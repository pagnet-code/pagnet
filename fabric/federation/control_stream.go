package federation

import (
	"context"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric"
	"io"
	"math"
	"sync"
	"sync/atomic"
)

const originalPullFrameRecord = byte(6)

type originalPullFrame struct {
	RequestDigest [32]byte               `json:"requestDigest"`
	Frame         fabric.InvocationFrame `json:"frame"`
}

// PullPage is only a bounded transport page, NOT an InvocationStream or an
// invocation/cancellation capability. NewPullPage does not authenticate/admit
// its request: source composition must first commit ControlLedger.Begin and
// verify the genuine original source. It never reads an endpoint/provider.
// Page exhaustion is io.EOF even if the original invocation is still running;
// only an actual received terminal frame expresses terminal native evidence.
type PullPage struct {
	channel  *ForwardChannel
	id       string
	digest   [32]byte
	credit   uint8
	next     uint64
	count    uint8
	terminal bool
	mode     uint8
	mu       sync.Mutex
	closed   atomic.Bool
}

func NewPullPage(c *ForwardChannel, request ControlRequest) (*PullPage, error) {
	if c == nil {
		return nil, protocolError()
	}
	r, digest, e := ownedControl(request)
	if e != nil {
		return nil, e
	}
	p, e := controlPayload(r)
	if e != nil || r.Proof.Frame.Action != "pull" || p.Cursor.Ordinal == math.MaxInt64 {
		return nil, protocolError()
	}
	return &PullPage{channel: c, id: r.Proof.Frame.InvocationID, digest: digest, credit: p.Credit, next: uint64(p.Cursor.Ordinal + 1)}, nil
}

// Close unblocks only this owned encrypted transport. It is not a signed
// original-source stop request and never reports completion or stop ACK.
func (p *PullPage) Close() error { p.closed.Store(true); return p.channel.Close() }
func (p *PullPage) validFrame(f fabric.InvocationFrame) bool {
	if f.InvocationID != p.id || f.Sequence != p.next || len(f.Data) > fabric.MaxFrameBytes || p.count >= p.credit || p.terminal || p.next >= math.MaxInt64 {
		return false
	}
	if p.next == 0 && f.Kind != fabric.FrameStart || p.next > 0 && f.Kind == fabric.FrameStart {
		return false
	}
	switch f.Kind {
	case fabric.FrameStart:
		return len(f.Data) == 0 && f.Error == nil
	case fabric.FrameChunk, fabric.FrameProgress, fabric.FrameComplete:
		return f.Error == nil
	case fabric.FrameError:
		return f.Error != nil && len(f.Data) == 0
	default:
		return false
	}
}
func (p *PullPage) advance(f fabric.InvocationFrame) {
	p.next++
	p.count++
	p.terminal = f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError
}
func (p *PullPage) Send(ctx context.Context, f fabric.InvocationFrame) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx == nil || p.closed.Load() || p.mode == 2 || !p.validFrame(f) {
		p.Close()
		return protocolError()
	}
	p.mode = 1
	raw, e := json.Marshal(originalPullFrame{p.digest, f})
	if e != nil || len(raw) > MaxRecordPlaintext-1 {
		p.Close()
		return protocolError()
	}
	defer clear(raw)
	p.channel.sendMu.Lock()
	defer p.channel.sendMu.Unlock()
	record := append([]byte{originalPullFrameRecord}, raw...)
	defer clear(record)
	if e = p.channel.transport.Send(ctx, record); e != nil {
		p.Close()
		return e
	}
	p.advance(f)
	return nil
}
func (p *PullPage) Receive(ctx context.Context) (fabric.InvocationFrame, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx == nil || p.closed.Load() {
		return fabric.InvocationFrame{}, protocolError()
	}
	if p.mode == 1 {
		p.Close()
		return fabric.InvocationFrame{}, protocolError()
	}
	p.mode = 2
	if p.count == p.credit || p.terminal {
		return fabric.InvocationFrame{}, io.EOF
	}
	p.channel.receiveMu.Lock()
	defer p.channel.receiveMu.Unlock()
	raw, e := p.channel.transport.Receive(ctx)
	if e != nil {
		p.Close()
		return fabric.InvocationFrame{}, e
	}
	defer clear(raw)
	var record originalPullFrame
	if len(raw) < 2 || raw[0] != originalPullFrameRecord || fabric.DecodeJSONWithLimits(raw[1:], &record, fabric.WireLimits{MaxBytes: MaxRecordPlaintext - 1, MaxDepth: 16, MaxMembers: 256}) != nil || record.RequestDigest != p.digest || !p.validFrame(record.Frame) {
		p.Close()
		return fabric.InvocationFrame{}, protocolError()
	}
	p.advance(record.Frame)
	return record.Frame, nil
}
