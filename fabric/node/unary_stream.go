package node

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
)

// A bounded cached/virtual response follows ordinary stream framing without
// inventing endpoint effects or collecting an unbounded downstream stream.
type unaryStream struct {
	mu       sync.Mutex
	id       string
	payload  []byte
	offset   int
	sequence uint64
	terminal bool
}

func newUnaryStream(id string, payload json.RawMessage) *unaryStream {
	return &unaryStream{id: id, payload: append([]byte(nil), payload...)}
}
func (s *unaryStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminal = true
	s.payload = nil
	return nil
}
func (s *unaryStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal {
		return fabric.InvocationFrame{}, io.EOF
	}
	if ctx == nil {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeInvalidInput, "Missing stream context")
	}
	if ctx.Err() != nil {
		return fabric.InvocationFrame{}, ctx.Err()
	}
	frame := fabric.InvocationFrame{InvocationID: s.id, Sequence: s.sequence, ContentType: "application/json"}
	switch {
	case s.sequence == 0:
		frame.Kind = fabric.FrameStart
	case s.offset < len(s.payload):
		frame.Kind = fabric.FrameChunk
		end := s.offset + fabric.MaxFrameBytes
		if end > len(s.payload) {
			end = len(s.payload)
		}
		frame.Data = append([]byte(nil), s.payload[s.offset:end]...)
		s.offset = end
	default:
		frame.Kind = fabric.FrameComplete
		s.terminal = true
		s.payload = nil
	}
	s.sequence++
	return frame, nil
}
