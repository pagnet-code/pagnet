package continuations

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
)

// targetStream sees checked genuine target terminal evidence before extension
// hooks can reject or transform output. Settlement is not inferred from chunks.
type targetStream struct {
	fabric.InvocationStream
	mu         sync.Mutex
	settlement *settler
}

func (s *targetStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, e := s.InvocationStream.Next(ctx)
	if e != nil {
		if !errors.Is(e, io.EOF) {
			if se := s.settlement.recordRetained(Evidence{Kind: TargetFailure, InvocationID: s.settlement.invocationID, Failure: e}); se != nil {
				return fabric.InvocationFrame{}, se
			}
		}
		return f, e
	}
	if f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError {
		kind := TargetTerminal
		var failure error
		if f.Kind == fabric.FrameError {
			failure = f.Error
		}
		copy := f
		copy.Data = append([]byte(nil), f.Data...)
		if se := s.settlement.recordRetained(Evidence{Kind: kind, InvocationID: f.InvocationID, Frame: &copy, Failure: failure}); se != nil {
			return fabric.InvocationFrame{}, se
		}
	}
	return f, nil
}

// resultStream coordinates consumer abandonment with in-flight Next. Close first
// cancels the actual upstream, then waits for accepted terminal evidence before
// settling unknown. It does not buffer or replay the invocation's output.
type resultStream struct {
	fabric.InvocationStream
	nextMu     sync.Mutex
	closeOnce  sync.Once
	closeErr   error
	settlement *settler
}

func (s *resultStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.nextMu.Lock()
	defer s.nextMu.Unlock()
	f, e := s.InvocationStream.Next(ctx)
	if e != nil || f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError {
		defer s.settlement.releaseBinding()
	}
	if e != nil && !s.settlement.done() {
		if se := s.settlement.record(Evidence{Kind: Abandoned, InvocationID: s.settlement.invocationID, Failure: e}); se != nil {
			return fabric.InvocationFrame{}, se
		}
	}
	return f, e
}
func (s *resultStream) Close() error {
	s.closeOnce.Do(func() {
		defer s.settlement.releaseBinding()
		e := s.InvocationStream.Close()
		s.nextMu.Lock()
		defer s.nextMu.Unlock()
		se := s.settlement.record(Evidence{Kind: Abandoned, InvocationID: s.settlement.invocationID})
		s.closeErr = errors.Join(e, se)
	})
	return s.closeErr
}
