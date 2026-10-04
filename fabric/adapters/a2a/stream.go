package a2a

import (
	"context"
	"encoding/json"
	"errors"
	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/pagnet-code/pagnet/fabric"
	"io"
	"sync"
)

type stream struct {
	mu                        sync.Mutex
	id                        string
	ctx                       context.Context
	cancel                    context.CancelFunc
	next                      func() (sdk.Event, error, bool)
	stop                      func()
	tap                       *rawTap
	store                     AssociationStore
	key                       AssociationKey
	expected                  Association
	operation                 string
	seq                       uint64
	started, closed, finished bool
	pending                   []byte
	terminal                  *fabric.Error
	complete                  bool
}

func (s *stream) Close() error {
	s.cancel() // Interrupt HTTP before joining Next; iter next/stop never race.
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.stop()
		clear(s.pending)
		s.pending = nil
	}
	return nil
}
func (s *stream) frame(kind fabric.FrameKind, data []byte, err *fabric.Error) fabric.InvocationFrame {
	f := fabric.InvocationFrame{InvocationID: s.id, Sequence: s.seq, Kind: kind, Data: data, Error: err}
	if kind == fabric.FrameChunk {
		f.ContentType = "application/x-ndjson"
	}
	s.seq++
	return f
}
func (s *stream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	if ctx == nil {
		return fabric.InvocationFrame{}, failure(fabric.CodeInvalidInput, fabric.EffectUnknown)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.finished {
		return fabric.InvocationFrame{}, io.EOF
	}
	if !s.started {
		s.started = true
		return s.frame(fabric.FrameStart, nil, nil), nil
	}
	if len(s.pending) > 0 {
		return s.chunk(), nil
	}
	if s.terminal != nil || s.complete {
		s.finished = true
		s.stop()
		s.cancel()
		if s.terminal != nil {
			return s.frame(fabric.FrameError, nil, s.terminal), nil
		}
		return s.frame(fabric.FrameComplete, nil, nil), nil
	}
	if ctx.Err() != nil {
		s.terminal = failure(fabric.CodeCancelled, fabric.EffectUnknown)
		return s.endError(), nil
	}
	interrupt := context.AfterFunc(ctx, s.cancel)
	defer interrupt()
	event, err, ok := s.next()
	if err != nil || !ok {
		code := fabric.ErrorCode("a2a.INTERRUPTED")
		if s.ctx.Err() != nil {
			code = fabric.CodeCancelled
		}
		if errors.Is(err, sdk.ErrUnsupportedOperation) {
			code = fabric.CodeUnsupported
		}
		if errors.Is(err, sdk.ErrTaskNotFound) {
			code = fabric.CodeNotFound
		}
		if errors.Is(err, sdk.ErrTaskNotCancelable) {
			code = "a2a.CANCEL_REJECTED"
		}
		if errors.Is(err, errBound) {
			code = "a2a.OUTPUT_LIMIT"
		}
		s.terminal = failure(code, fabric.EffectUnknown)
		return s.endError(), nil
	}
	raw, err := s.tap.take()
	if err != nil {
		s.terminal = failure(fabric.CodeProtocolError, fabric.EffectUnknown)
		return s.endError(), nil
	}
	if s.operation == "get" || s.operation == "cancel" {
		raw = append(append(json.RawMessage(`{"task":`), raw...), '}')
	}
	var exact sdk.StreamResponse
	if json.Unmarshal(raw, &exact) != nil || !sameControl(event, exact.Event) {
		s.terminal = failure(fabric.CodeProtocolError, fabric.EffectUnknown)
		return s.endError(), nil
	}
	task, conversation, state, standalone, valid := controls(event)
	if !valid {
		s.terminal = failure(fabric.CodeProtocolError, fabric.EffectUnknown)
		return s.endError(), nil
	}
	if task != "" {
		if s.expected.TaskID != "" && (task != s.expected.TaskID || conversation != s.expected.ContextID) {
			s.terminal = failure(fabric.CodeProtocolError, fabric.EffectUnknown)
			return s.endError(), nil
		}
		if e := s.store.Associate(s.ctx, s.key, task, conversation); e != nil {
			s.terminal = failure("a2a.ASSOCIATION_FAILED", fabric.EffectUnknown)
			return s.endError(), nil
		}
		s.expected.TaskID, s.expected.ContextID = task, conversation
	}
	// Preserve exact JSON numbers/fields from the response matched to SDK event.
	s.pending = append(append([]byte(nil), raw...), '\n')
	switch state {
	case sdk.TaskStateCompleted:
		s.complete = true
	case sdk.TaskStateRejected:
		s.terminal = failure("a2a.REJECTED", fabric.EffectNotStarted)
	case sdk.TaskStateFailed:
		s.terminal = failure("a2a.FAILED", fabric.EffectUnknown)
	case sdk.TaskStateCanceled:
		s.terminal = failure("a2a.STOPPED", fabric.EffectUnknown)
	case sdk.TaskStateAuthRequired:
		s.terminal = failure("a2a.AUTH_REQUIRED", fabric.EffectUnknown)
	case sdk.TaskStateInputRequired:
		s.terminal = failure("a2a.INPUT_REQUIRED", fabric.EffectUnknown)
	case sdk.TaskStateSubmitted, sdk.TaskStateWorking, sdk.TaskStateUnspecified:
	default:
		s.terminal = failure("a2a.UNKNOWN_STATUS", fabric.EffectUnknown)
	}
	if standalone {
		s.complete = true
	}
	return s.chunk(), nil
}
func (s *stream) chunk() fabric.InvocationFrame {
	n := len(s.pending)
	if n > fabric.MaxFrameBytes {
		n = fabric.MaxFrameBytes
	}
	part := append([]byte(nil), s.pending[:n]...)
	s.pending = s.pending[n:]
	return s.frame(fabric.FrameChunk, part, nil)
}
func (s *stream) endError() fabric.InvocationFrame {
	s.finished = true
	s.stop()
	s.cancel()
	return s.frame(fabric.FrameError, nil, s.terminal)
}
func controls(event sdk.Event) (task, conversation string, state sdk.TaskState, standalone, valid bool) {
	valid = true
	switch e := event.(type) {
	case *sdk.Task:
		if e == nil {
			return "", "", "", false, false
		}
		task, conversation, state = string(e.ID), e.ContextID, e.Status.State
	case *sdk.TaskStatusUpdateEvent:
		if e == nil {
			return "", "", "", false, false
		}
		task, conversation, state = string(e.TaskID), e.ContextID, e.Status.State
	case *sdk.TaskArtifactUpdateEvent:
		if e == nil || e.Artifact == nil || e.Artifact.ID == "" {
			return "", "", "", false, false
		}
		task, conversation = string(e.TaskID), e.ContextID
	case *sdk.Message:
		if e == nil || e.ID == "" {
			return "", "", "", false, false
		}
		task, conversation = string(e.TaskID), e.ContextID
		standalone = task == ""
	default:
		return "", "", "", false, false
	}
	if !standalone && (task == "" || conversation == "") {
		valid = false
	}
	return
}
func sameControl(a, b sdk.Event) bool {
	at, ac, as, am, av := controls(a)
	bt, bc, bs, bm, bv := controls(b)
	if !av || !bv || at != bt || ac != bc || as != bs || am != bm {
		return false
	}
	switch x := a.(type) {
	case *sdk.Task:
		_, ok := b.(*sdk.Task)
		return ok
	case *sdk.TaskStatusUpdateEvent:
		_, ok := b.(*sdk.TaskStatusUpdateEvent)
		return ok
	case *sdk.Message:
		y, ok := b.(*sdk.Message)
		return ok && x.ID == y.ID
	case *sdk.TaskArtifactUpdateEvent:
		y, ok := b.(*sdk.TaskArtifactUpdateEvent)
		return ok && x.Artifact.ID == y.Artifact.ID && x.Append == y.Append && x.LastChunk == y.LastChunk
	}
	return false
}
