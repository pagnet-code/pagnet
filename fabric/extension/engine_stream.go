package extension

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type interceptedStream struct {
	engine    *Engine
	envelope  fabric.Envelope
	stage     string
	stack     []CompiledRegistration
	upstream  fabric.InvocationStream
	lifetime  context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	terminal  bool
	closeOnce sync.Once
	closeErr  error
}

func newInterceptedStream(ctx context.Context, e *Engine, envelope fabric.Envelope, stage string, stack []CompiledRegistration, upstream fabric.InvocationStream) *interceptedStream {
	lifetime, cancel := context.WithCancel(ctx)
	return &interceptedStream{engine: e, envelope: envelope, stage: stage, stack: append([]CompiledRegistration(nil), stack...), upstream: upstream, lifetime: lifetime, cancel: cancel}
}
func (s *interceptedStream) Close() error {
	s.cancel()
	s.closeOnce.Do(func() { s.closeErr = s.upstream.Close() })
	return s.closeErr
}
func (s *interceptedStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal {
		return fabric.InvocationFrame{}, io.EOF
	}
	if ctx == nil {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeInvalidInput, "Missing stream context")
	}
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	defer func() { stop(); cancel() }()
	if s.lifetime.Err() != nil {
		return fabric.InvocationFrame{}, s.lifetime.Err()
	}
	frame, err := s.upstream.Next(call)
	if err != nil {
		s.terminal = true
		if !errors.Is(err, io.EOF) {
			_ = s.observe(call, PhaseError, nil, err)
		}
		_ = s.Close()
		return fabric.InvocationFrame{}, err
	}
	phase := PhaseChunk
	switch frame.Kind {
	case fabric.FrameStart:
		phase = PhaseResponse
	case fabric.FrameComplete:
		phase = PhaseCompletion
	case fabric.FrameError:
		phase = PhaseError
	}
	if err := s.observe(call, phase, &frame, nil); err != nil {
		s.terminal = true
		_ = s.Close()
		return fabric.InvocationFrame{}, err
	}
	if frame.Kind == fabric.FrameComplete || frame.Kind == fabric.FrameError {
		s.terminal = true
		_ = s.Close()
	}
	return frame, nil
}
func (s *interceptedStream) observe(ctx context.Context, phase Phase, frame *fabric.InvocationFrame, failure error) error {
	if ctx.Err() != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		ctx = cleanup
	}
	currentFailure := failure
	for i := len(s.stack) - 1; i >= 0; i-- {
		registration := s.stack[i]
		currentPhase := phase
		if currentFailure != nil {
			currentPhase = PhaseError
		}
		if !containsPhase(registration.Registration.Phases, currentPhase) {
			continue
		}
		request := s.engine.request(s.envelope, registration.Registration.Match.Stage, registration, currentPhase)
		request.Frame = frame
		if frame != nil && frame.Error != nil {
			request.Failure = frame.Error
		}
		if currentFailure != nil {
			var e *fabric.Error
			if errors.As(currentFailure, &e) {
				request.Failure = e
			} else {
				request.Failure = fabric.NewError(fabric.CodeProtocolError, "Stream failed")
			}
		}
		decision, err := s.engine.call(ctx, registration, request, true)
		if err != nil {
			currentFailure = err
			continue
		}
		if decision.Action == Reject {
			currentFailure = decision.Failure
		}
	}
	return currentFailure
}

// The operation deadline belongs to the stream, not the method returning it.
type lifetimeStream struct {
	upstream fabric.InvocationStream
	cancel   context.CancelFunc
	once     sync.Once
}

func (s *lifetimeStream) Close() error { s.once.Do(s.cancel); return s.upstream.Close() }
func (s *lifetimeStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	frame, err := s.upstream.Next(ctx)
	if err != nil || frame.Kind == fabric.FrameComplete || frame.Kind == fabric.FrameError {
		_ = s.Close()
	}
	return frame, err
}
