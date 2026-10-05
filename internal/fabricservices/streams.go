package fabricservices

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"io"
	"sync"
)

type retainedStream struct {
	capture *sourceCapture
	fabric.InvocationStream
	ledger    *Invocations
	caller    fabric.ExecutionContext
	receipt   Receipt
	ctx       context.Context
	mu        sync.Mutex
	terminal  bool
	detached  bool
	closed    bool
	drainDone chan struct{}
}

func (s *retainedStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.detached || s.closed {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeTargetUnavailable, "Original source delivery is detached")
	}
	if s.terminal {
		return fabric.InvocationFrame{}, io.EOF
	}
	f, e := s.InvocationStream.Next(ctx)
	if e != nil {
		s.terminal = true
		s.InvocationStream.Close()
		if s.capture != nil {
			s.capture.close()
		}
		return fabric.InvocationFrame{}, e
	}
	appendFrame := func() error { return s.ledger.Append(s.ctx, s.caller, s.receipt, f) }
	if s.capture != nil {
		appendFrame = func() error { return s.capture.append(f) }
	}
	if e = appendFrame(); e != nil {
		s.terminal = true
		s.InvocationStream.Close()
		if s.capture != nil {
			s.capture.close()
		}
		return fabric.InvocationFrame{}, e
	}
	if s.capture != nil {
		if _, e = s.ledger.Frame(s.ctx, s.caller, s.receipt, f.Sequence); e != nil {
			return fabric.InvocationFrame{}, e
		}
	}
	s.terminal = f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError
	if s.terminal && s.capture != nil {
		s.capture.close()
	}
	return f, nil
}

// DetachOriginalDelivery transfers only consumption to the already accepted
// bounded source. It never repeats a tools/call. The original SDK output is
// FULL-retained before any separately authenticated consumer can publish it.
func (s *retainedStream) DetachOriginalDelivery() (SourceReference, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.capture == nil || s.closed {
		return SourceReference{}, denied()
	}
	ref := serviceReference(s.receipt)
	if s.detached || s.terminal {
		return ref, nil
	}
	if s.capture.beginDrain == nil {
		return SourceReference{}, denied()
	}
	done, err := s.capture.beginDrain()
	if err != nil {
		return SourceReference{}, err
	}
	s.detached = true
	s.drainDone = make(chan struct{})
	go func() {
		defer done()
		defer close(s.drainDone)
		defer s.capture.close()
		defer s.InvocationStream.Close()
		for {
			f, e := s.InvocationStream.Next(s.capture.ctx)
			if e != nil {
				return
			}
			if e = s.capture.append(f); e != nil {
				return
			}
			if f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError {
				return
			}
		}
	}()
	return ref, nil
}

// Close detaches delivery after explicit source ownership transfer. Otherwise
// it closes this original stream and its capture lifetime; genuine cancellation
// is distinct from any original completion frame.
func (s *retainedStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.detached {
		return nil
	}
	if s.closed {
		return nil
	}
	s.closed = true
	if s.capture != nil {
		s.capture.close()
	}
	return s.InvocationStream.Close()
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
