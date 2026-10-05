package node

import (
	"context"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
	"github.com/pagnet-code/pagnet/fabric/telemetry"
)

// EventLoss reports observation admission loss independently of operation
// success. No observer failure is converted into an invocation failure.
func (s *Service) EventLoss() uint64 { return s.eventLoss.Load() }

func (s *Service) publishLifecycle(ctx context.Context, envelope fabric.Envelope, disposition string) {
	if s.config.Events == nil {
		return
	}
	subject := ""
	if envelope.Target != nil {
		subject = envelope.Target.String()
	}
	e, err := events.Lifecycle(s.config.EventSource, subject, events.LifecycleMetadata{InvocationID: envelope.ID, Operation: envelope.Operation, Disposition: disposition}, time.Now().UTC())
	if err != nil {
		s.eventLoss.Add(1)
		return
	}
	// TryPublish's nonblocking contract is required of the selected EventBus.
	// Caller cancellation does not turn a metadata observation into an error.
	if err := s.config.Events.TryPublish(context.WithoutCancel(ctx), e); err != nil {
		s.eventLoss.Add(1)
	}
}

// Lifecycle dispositions describe the caller operation/stream, not proof of
// target effects. Native durable receipts remain the authority for effects.
type observedStream struct {
	fabric.InvocationStream
	node     *Service
	envelope fabric.Envelope
	lifetime context.Context
	once     sync.Once
	span     telemetry.Span
}

func (s *observedStream) finish(disposition string) {
	s.once.Do(func() {
		s.node.publishLifecycle(s.lifetime, s.envelope, disposition)
		if s.span != nil {
			s.span.End(disposition)
		}
	})
}

func (s *observedStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	f, err := s.InvocationStream.Next(ctx)
	if err != nil {
		s.finish("failed")
	} else if f.Kind == fabric.FrameComplete {
		s.finish("completed")
	} else if f.Kind == fabric.FrameError {
		s.finish("failed")
	}
	return f, err
}

func (s *observedStream) Close() error {
	s.finish("cancelled")
	return s.InvocationStream.Close()
}

func (s *observedStream) WithOriginalCapture(ctx context.Context, next func(context.Context) error) error {
	return fabric.WithOriginalSourceCapture(ctx, s.InvocationStream, next)
}
func (s *observedStream) OriginalSourceOwnership(ctx context.Context) (fabric.OriginalSourceOwnership, error) {
	return fabric.OriginalStreamOwnership(ctx, s.InvocationStream)
}
