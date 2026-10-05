package fabricservices

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"io"
	"sync"
)

type retainedStream struct {
	fabric.InvocationStream
	ledger   *Invocations
	caller   fabric.ExecutionContext
	receipt  Receipt
	ctx      context.Context
	mu       sync.Mutex
	terminal bool
}

func (s *retainedStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal {
		return fabric.InvocationFrame{}, io.EOF
	}
	f, e := s.InvocationStream.Next(ctx)
	if e != nil {
		s.terminal = true
		s.InvocationStream.Close()
		return fabric.InvocationFrame{}, e
	}
	if e = s.ledger.Append(s.ctx, s.caller, s.receipt, f); e != nil {
		s.terminal = true
		s.InvocationStream.Close()
		return fabric.InvocationFrame{}, e
	}
	s.terminal = f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError
	return f, nil
}

type replayStream struct {
	ledger  *Invocations
	caller  fabric.ExecutionContext
	receipt Receipt
	ctx     context.Context
	mu      sync.Mutex
	ordinal uint64
	closed  bool
	cancel  context.CancelFunc
}

func (s *replayStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ordinal >= s.receipt.Frames {
		return fabric.InvocationFrame{}, io.EOF
	}
	call, cancel := context.WithCancel(s.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	f, e := s.ledger.Frame(call, s.caller, s.receipt, s.ordinal)
	if e != nil {
		s.closed = true
		return fabric.InvocationFrame{}, e
	}
	s.ordinal++
	return f, nil
}
func (s *replayStream) Close() error {
	s.cancel()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func newReplayStream(ctx context.Context, i *Invocations, caller fabric.ExecutionContext, r Receipt) *replayStream {
	life, cancel := context.WithCancel(ctx)
	return &replayStream{ledger: i, caller: caller, receipt: r, ctx: life, cancel: cancel}
}

// ReplayAssociation returns only an actual retained fresh-ID association.
// Original-ID retries need no alias and retain their original stream identity.
func (s *replayStream) ReplayAssociation() *fabric.ReplayAssociation {
	if s.receipt.Replay == nil {
		return nil
	}
	a := s.receipt.Replay.Clone()
	return &a
}
