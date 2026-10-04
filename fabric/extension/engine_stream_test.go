package extension

import (
	"context"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type testFrames struct {
	mu     sync.Mutex
	frames []fabric.InvocationFrame
	reads  int
	closed bool
}

func (s *testFrames) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return fabric.InvocationFrame{}, ctx.Err()
	}
	s.reads++
	if len(s.frames) == 0 {
		return fabric.InvocationFrame{}, io.EOF
	}
	frame := s.frames[0]
	s.frames = s.frames[1:]
	return frame, nil
}
func (s *testFrames) Close() error { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true; return nil }
func TestEngineStreamingPullAndReverseHooks(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	m := manifestWith("a", "b")
	for i := range m.Interceptors {
		m.Interceptors[i].Phases = append(m.Interceptors[i].Phases, PhaseChunk, PhaseCompletion)
	}
	var calls []string
	engine := makeEngine(t, m, handlerFunc(func(_ context.Context, r InterceptRequest) (Decision, error) {
		calls = append(calls, r.InterceptorID+":"+string(r.Phase))
		return Decision{Action: Continue}, nil
	}), nil, nil)
	var env fabric.Envelope
	fabric.DecodeJSON(raw, &env)
	upstream := &testFrames{frames: []fabric.InvocationFrame{{InvocationID: env.ID, Sequence: 0, Kind: fabric.FrameStart}, {InvocationID: env.ID, Sequence: 1, Kind: fabric.FrameChunk, Data: []byte("hello")}, {InvocationID: env.ID, Sequence: 2, Kind: fabric.FrameComplete}}}
	out, err := engine.ExecuteStage(context.Background(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		return Outcome{Stream: upstream}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if upstream.reads != 0 {
		t.Fatal("stream was eagerly drained")
	}
	for i := 0; i < 3; i++ {
		frame, err := out.Stream.Next(context.Background())
		if err != nil || frame.Sequence != uint64(i) {
			t.Fatal(frame, err)
		}
		if upstream.reads != i+1 {
			t.Fatal("read ahead")
		}
	}
	if _, err := out.Stream.Next(context.Background()); err != io.EOF {
		t.Fatal(err)
	}
	want := []string{"acme.security.a:request", "acme.security.b:request", "acme.security.b:response", "acme.security.a:response", "acme.security.b:chunk", "acme.security.a:chunk", "acme.security.b:completion", "acme.security.a:completion"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatal(calls)
	}
	if !upstream.closed {
		t.Fatal("terminal stream retained resources")
	}
}
func TestChunkRejectionUnwindsPriorErrorAndNeverDefers(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	m := manifestWith("a", "b")
	for i := range m.Interceptors {
		m.Interceptors[i].Phases = append(m.Interceptors[i].Phases, PhaseChunk)
	}
	var calls []string
	engine := makeEngine(t, m, handlerFunc(func(_ context.Context, r InterceptRequest) (Decision, error) {
		calls = append(calls, r.InterceptorID+":"+string(r.Phase))
		if r.InterceptorID == "acme.security.b" && r.Phase == PhaseChunk {
			return Decision{Action: Reject, Failure: fabric.NewError(fabric.CodeInterceptorRejected, "Chunk denied")}, nil
		}
		return Decision{Action: Continue}, nil
	}), nil, nil)
	var env fabric.Envelope
	fabric.DecodeJSON(raw, &env)
	upstream := &testFrames{frames: []fabric.InvocationFrame{{InvocationID: env.ID, Sequence: 0, Kind: fabric.FrameStart}, {InvocationID: env.ID, Sequence: 1, Kind: fabric.FrameChunk, Data: []byte("private")}, {InvocationID: env.ID, Sequence: 2, Kind: fabric.FrameComplete}}}
	out, err := engine.ExecuteStage(context.Background(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		return Outcome{Stream: upstream}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	out.Stream.Next(context.Background())
	frame, err := out.Stream.Next(context.Background())
	if err == nil || len(frame.Data) != 0 {
		t.Fatal("denied chunk leaked", frame, err)
	}
	if !reflect.DeepEqual(calls[len(calls)-2:], []string{"acme.security.b:chunk", "acme.security.a:error"}) {
		t.Fatal(calls)
	}
	if !upstream.closed || upstream.reads != 2 {
		t.Fatal("rejection drained downstream")
	}
}

type blockingFrames struct {
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (s *blockingFrames) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	close(s.entered)
	<-ctx.Done()
	return fabric.InvocationFrame{}, ctx.Err()
}
func (s *blockingFrames) Close() error { s.once.Do(func() { close(s.closed) }); return nil }
func TestStreamCloseCancelsBlockedNativeRead(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	engine := makeEngine(t, manifestWith("a"), handlerFunc(func(context.Context, InterceptRequest) (Decision, error) { return Decision{Action: Continue}, nil }), nil, nil)
	upstream := &blockingFrames{entered: make(chan struct{}), closed: make(chan struct{})}
	out, err := engine.ExecuteStage(context.Background(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		return Outcome{Stream: upstream}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, e := out.Stream.Next(context.Background()); done <- e }()
	<-upstream.entered
	if err := out.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled read succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel blocked upstream")
	}
	select {
	case <-upstream.closed:
	default:
		t.Fatal("upstream not closed")
	}
}
