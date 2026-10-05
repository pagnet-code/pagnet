package fabric

import (
	"context"
	"errors"
	"io"
	"sync"
)

type FrameKind string

const (
	FrameStart    FrameKind = "start"
	FrameChunk    FrameKind = "chunk"
	FrameProgress FrameKind = "progress"
	FrameComplete FrameKind = "complete"
	FrameError    FrameKind = "error"
)

const MaxFrameBytes = 64 << 10

type InvocationFrame struct {
	InvocationID string `json:"invocationId"`
	// Decimal string on JSON transports: browser Number cannot exactly carry
	// every uint64. In-process adapters retain the native integer.
	Sequence    uint64    `json:"sequence,string"`
	Kind        FrameKind `json:"kind"`
	ContentType string    `json:"contentType,omitempty"`
	Data        []byte    `json:"data,omitempty"`
	Error       *Error    `json:"error,omitempty"`
}

// InvocationStream is pull-driven: Next provides backpressure. Close must be
// safe concurrently with a blocked Next and cancel downstream resources.
// A completion/error frame is terminal; subsequent Next returns io.EOF.
type InvocationStream interface {
	Next(context.Context) (InvocationFrame, error)
	Close() error
}

// CheckedStream verifies stream framing without buffering the whole response.
// A caller must Close if it stops consuming; cancellation is propagated to the
// producer, and malformed or premature EOF streams are terminated immediately.
type CheckedStream struct {
	upstream  InvocationStream
	id        string
	lifetime  context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	next      uint64
	terminal  bool
	closeOnce sync.Once
	closeErr  error
}

func NewCheckedStream(parent context.Context, id string, upstream InvocationStream) (*CheckedStream, error) {
	if parent == nil || upstream == nil || !validText(id, 256) {
		return nil, NewError(CodeInvalidInput, "Invalid stream")
	}
	lifetime, cancel := context.WithCancel(parent)
	return &CheckedStream{upstream: upstream, id: id, lifetime: lifetime, cancel: cancel}, nil
}

// NewCheckedReplayStream accepts original identity only through a verified
// current-request association; it never rewrites original frames.
func NewCheckedReplayStream(parent context.Context, requestID string, upstream InvocationStream, correlation *VerifiedReplayCorrelation) (*CheckedStream, error) {
	if correlation == nil || correlation.association.Validate() != nil || correlation.association.RequestID != requestID {
		return nil, NewError(CodeUnauthenticated, "Missing verified replay correlation")
	}
	return NewCheckedStream(parent, correlation.association.ExecutionID, upstream)
}

func (s *CheckedStream) Close() error {
	s.cancel()
	s.closeOnce.Do(func() { s.closeErr = s.upstream.Close() })
	return s.closeErr
}

func (s *CheckedStream) Next(ctx context.Context) (InvocationFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal {
		return InvocationFrame{}, io.EOF
	}
	if ctx == nil {
		return InvocationFrame{}, NewError(CodeInvalidInput, "Missing stream context")
	}
	callCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	defer func() { stop(); cancel() }()
	if s.lifetime.Err() != nil {
		s.terminal = true
		_ = s.Close()
		return InvocationFrame{}, s.lifetime.Err()
	}
	f, err := s.upstream.Next(callCtx)
	if err != nil {
		s.terminal = true
		_ = s.Close()
		if errors.Is(err, io.EOF) {
			return InvocationFrame{}, NewError(CodeProtocolError, "Stream ended before terminal frame")
		}
		return InvocationFrame{}, err
	}
	if err = callCtx.Err(); err != nil {
		s.terminal = true
		_ = s.Close()
		return InvocationFrame{}, err
	}
	if f.InvocationID != s.id || f.Sequence != s.next || len(f.Data) > MaxFrameBytes {
		return s.fail("Invalid stream identity, sequence or frame size")
	}
	if s.next == 0 && f.Kind != FrameStart {
		return s.fail("Stream must begin with start")
	}
	if s.next > 0 && f.Kind == FrameStart {
		return s.fail("Duplicate stream start")
	}
	switch f.Kind {
	case FrameStart:
		if len(f.Data) != 0 || f.Error != nil {
			return s.fail("Start contains application content")
		}
	case FrameChunk, FrameProgress:
		if f.Error != nil {
			return s.fail("Content frame contains an error")
		}
	case FrameComplete:
		if f.Error != nil {
			return s.fail("Completion contains an error")
		}
		s.terminal = true
	case FrameError:
		if f.Error == nil || len(f.Data) != 0 {
			return s.fail("Invalid terminal error")
		}
		s.terminal = true
	default:
		return s.fail("Unknown required stream frame kind")
	}
	if s.next == ^uint64(0) {
		return s.fail("Stream sequence overflow")
	}
	s.next++
	if s.terminal {
		_ = s.Close()
	}
	return f, nil
}

func (s *CheckedStream) fail(message string) (InvocationFrame, error) {
	s.terminal = true
	_ = s.Close()
	return InvocationFrame{}, NewError(CodeProtocolError, message)
}

func (s *CheckedStream) WithOriginalCapture(ctx context.Context, next func(context.Context) error) error {
	return WithOriginalSourceCapture(ctx, s.upstream, next)
}
func (s *CheckedStream) OriginalSourceOwnership(ctx context.Context) (OriginalSourceOwnership, error) {
	return OriginalStreamOwnership(ctx, s.upstream)
}
