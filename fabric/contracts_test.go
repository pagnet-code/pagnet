package fabric

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testEnvelope(t *testing.T) (Envelope, []byte) {
	t.Helper()
	e := Envelope{ProtocolVersion: CurrentProtocolVersion, ID: "request-1", Operation: OperationDiscover,
		Principal: Principal{Ref: "local:alice", Kind: "actor.human", Issuer: "local:owner"}, Source: "local:alice",
		CreatedAt: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), Payload: json.RawMessage(`{"query":"sales","number":9007199254740993}`),
		Context: EnvelopeContext{Origin: "local:alice"}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return e, b
}

func TestAuthenticatedEnvelopeBoundary(t *testing.T) {
	e, b := testEnvelope(t)
	verified, err := NewAuthenticatedContext(e.Principal, "local:domain", b)
	if err != nil {
		t.Fatal(err)
	}
	if err = verified.VerifyBinding(e, b, "local:domain"); err != nil {
		t.Fatal(err)
	}
	if _, err = json.Marshal(verified); err == nil {
		t.Fatal("Trusted capability serialized to wire")
	}
	if err = json.Unmarshal([]byte(`{"verified":true}`), &verified); err == nil {
		t.Fatal("Wire populated an existing trusted capability")
	}
	tests := []struct {
		name     string
		ctx      ExecutionContext
		original Envelope
		bytes    []byte
		audience string
	}{
		{"zero context", ExecutionContext{}, e, b, "local:domain"},
		{"foreign audience", verified, e, b, "foreign:domain"},
		{"substituted bytes", verified, e, append(append([]byte(nil), b...), byte(' ')), "local:domain"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.ctx.VerifyBinding(tc.original, tc.bytes, tc.audience) == nil {
				t.Fatal("Unauthenticated binding accepted")
			}
		})
	}
	changed := e
	changed.Operation = OperationInvoke
	if verified.VerifyBinding(changed, b, "local:domain") == nil {
		t.Fatal("Different interpreted operation accepted")
	}
	forged := e
	forged.Principal.Ref = "local:mallory"
	forgedBytes, _ := json.Marshal(forged)
	forgedContext, _ := NewAuthenticatedContext(e.Principal, "local:domain", forgedBytes)
	if _, err = forgedContext.DecodeVerifiedEnvelope(forgedBytes, "local:domain"); err == nil {
		t.Fatal("Forged wire principal accepted")
	}
	decoded, err := verified.DecodeVerifiedEnvelope(b, "local:domain")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(decoded.Payload), "9007199254740993") {
		t.Fatal("Application number lost precision")
	}
}

func TestVersionAndRequiredSemantics(t *testing.T) {
	for _, v := range []ProtocolVersion{"1.0", "1.27"} {
		if err := v.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []ProtocolVersion{"2.0", "01.0", "1.00", "1", "1.-1", "1.0.0", "1.9999999999"} {
		if v.Validate() == nil {
			t.Fatalf("Accepted %q", v)
		}
	}
	e, _ := testEnvelope(t)
	e.RequiredFeatures = []string{"future.required-feature"}
	if e.Validate() == nil {
		t.Fatal("Required future semantics silently ignored")
	}
	e.RequiredFeatures = nil
	e.Principal.Kind = "future.custom-actor"
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
}

type fixtureStream struct {
	frames []InvocationFrame
	reads  atomic.Int32
	closes atomic.Int32
	wait   bool
}

func (s *fixtureStream) Next(ctx context.Context) (InvocationFrame, error) {
	s.reads.Add(1)
	if s.wait {
		<-ctx.Done()
		return InvocationFrame{}, ctx.Err()
	}
	if len(s.frames) == 0 {
		return InvocationFrame{}, io.EOF
	}
	f := s.frames[0]
	s.frames = s.frames[1:]
	return f, nil
}
func (s *fixtureStream) Close() error { s.closes.Add(1); return nil }

func TestPullStreamAndTerminalDisposition(t *testing.T) {
	up := &fixtureStream{frames: []InvocationFrame{
		{InvocationID: "invocation", Kind: FrameStart},
		{InvocationID: "invocation", Sequence: 1, Kind: FrameChunk, Data: []byte("original content")},
		{InvocationID: "invocation", Sequence: 2, Kind: FrameComplete},
	}}
	s, err := NewCheckedStream(context.Background(), "invocation", up)
	if err != nil {
		t.Fatal(err)
	}
	if up.reads.Load() != 0 {
		t.Fatal("Producer pulled before demand")
	}
	for i := 0; i < 3; i++ {
		f, err := s.Next(context.Background())
		if err != nil || f.Sequence != uint64(i) {
			t.Fatalf("Frame%d: %+v %v", i, f, err)
		}
		if up.reads.Load() != int32(i+1) {
			t.Fatal("Read-ahead bypassed pull backpressure")
		}
	}
	if _, err = s.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("After terminal: %v", err)
	}
	if up.reads.Load() != 3 || up.closes.Load() != 1 {
		t.Fatal("Terminal did not release producer once")
	}
	_ = s.Close()
	if up.closes.Load() != 1 {
		t.Fatal("Duplicate close")
	}
}

func TestMalformedStreamsCloseWithoutDelivery(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames []InvocationFrame
	}{
		{"missing start", []InvocationFrame{{InvocationID: "invocation", Kind: FrameChunk}}},
		{"wrong invocation", []InvocationFrame{{InvocationID: "foreign", Kind: FrameStart}}},
		{"wrong sequence", []InvocationFrame{{InvocationID: "invocation", Sequence: 1, Kind: FrameStart}}},
		{"premature EOF", nil},
		{"oversized content", []InvocationFrame{{InvocationID: "invocation", Kind: FrameStart}, {InvocationID: "invocation", Sequence: 1, Kind: FrameChunk, Data: make([]byte, MaxFrameBytes+1)}}},
		{"duplicate start", []InvocationFrame{{InvocationID: "invocation", Kind: FrameStart}, {InvocationID: "invocation", Sequence: 1, Kind: FrameStart}}},
		{"empty error", []InvocationFrame{{InvocationID: "invocation", Kind: FrameStart}, {InvocationID: "invocation", Sequence: 1, Kind: FrameError}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := &fixtureStream{frames: tc.frames}
			s, _ := NewCheckedStream(context.Background(), "invocation", up)
			for i := 0; i <= len(tc.frames); i++ {
				_, err := s.Next(context.Background())
				if err != nil {
					if errors.Is(err, io.EOF) {
						t.Fatal("Malformed stream accepted")
					}
					if up.closes.Load() != 1 {
						t.Fatal("Failed producer not closed")
					}
					return
				}
			}
			t.Fatal("Invalid frames accepted")
		})
	}
}

func TestStreamCancellationWhileNextBlocked(t *testing.T) {
	up := &fixtureStream{wait: true}
	s, _ := NewCheckedStream(context.Background(), "invocation", up)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := s.Next(ctx); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Cancellation did not reach producer")
	}
	if up.closes.Load() != 1 {
		t.Fatal("Cancelled producer not closed")
	}
}

func TestStreamCloseCancelsBlockedNext(t *testing.T) {
	up := &fixtureStream{wait: true}
	s, _ := NewCheckedStream(context.Background(), "invocation", up)
	done := make(chan error, 1)
	go func() { _, err := s.Next(context.Background()); done <- err }()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked with Next")
	}
}

func TestUnknownErrorEffectIsNotReplayPermission(t *testing.T) {
	e := NewError(CodeTargetUnavailable, strings.Repeat("á", 1025))
	if e.Effect != EffectUnknown || len(e.Message) > 1024 {
		t.Fatal("Unsafe error default or unbounded error")
	}
}

func TestFrameSequenceNeverRoundsThroughJSON(t *testing.T) {
	f := InvocationFrame{InvocationID: "invocation", Sequence: ^uint64(0), Kind: FrameChunk, Data: []byte("x")}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"sequence":"18446744073709551615"`) {
		t.Fatal("Sequence is not encoded as exact decimal text")
	}
	var reopened InvocationFrame
	if err = DecodeJSON(b, &reopened); err != nil || reopened.Sequence != f.Sequence {
		t.Fatalf("Sequence changed: %+v %v", reopened, err)
	}
}

func TestCallerCannotForgeInterceptorExclusionOrOrigin(t *testing.T) {
	e, _ := testEnvelope(t)
	for _, mutate := range []func(*Envelope){
		func(e *Envelope) { e.Context.ExtensionChain = []string{"acme.authorization"} },
		func(e *Envelope) { e.Context.Origin = "local:administrator" },
		func(e *Envelope) {
			e.Context.ParentID = "foreign-parent"
			e.Context.Ancestry = []string{"foreign-parent"}
			e.Context.Hops = 1
		},
	} {
		changed := e
		mutate(&changed)
		b, _ := json.Marshal(changed)
		c, err := NewAuthenticatedContext(e.Principal, "local:domain", b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.DecodeVerifiedEnvelope(b, "local:domain"); err == nil {
			t.Fatal("Caller-signed assertion forged engine ancestry")
		}
	}
}

func TestAuthenticatedForwardLineageIsPinnedAndImmutable(t *testing.T) {
	e, _ := testEnvelope(t)
	e.Context.ParentID = "parent"
	e.Context.Ancestry = []string{"parent"}
	e.Context.Hops = 1
	e.Context.ExtensionChain = []string{"acme.audit"}
	b, _ := json.Marshal(e)
	p := Provenance{Origin: e.Principal.Ref, ParentID: "parent", Ancestry: []string{"parent"}, Hops: 1, ExtensionChain: []string{"acme.audit"}}
	c, err := NewAuthenticatedForwardContext(e.Principal, "local:domain", b, p)
	if err != nil {
		t.Fatal(err)
	}
	p.ExtensionChain[0] = "acme.authorization"
	view := c.ProvenanceView()
	view.ExtensionChain[0] = "acme.authorization"
	if _, err = c.DecodeVerifiedEnvelope(b, "local:domain"); err != nil {
		t.Fatal("Caller mutated copied provenance", err)
	}
}
