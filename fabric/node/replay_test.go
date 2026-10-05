package node

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

type replayFixtureStream struct {
	fixtureFrames
	association   fabric.ReplayAssociation
	pulls, closed int
}

func (s *replayFixtureStream) ReplayAssociation() *fabric.ReplayAssociation {
	a := s.association.Clone()
	return &a
}
func (s *replayFixtureStream) Next(c context.Context) (fabric.InvocationFrame, error) {
	s.pulls++
	return s.fixtureFrames.Next(c)
}
func (s *replayFixtureStream) Close() error { s.closed++; return nil }

type replayFixtureDispatcher struct {
	stream *replayFixtureStream
	mutate func(*fabric.ReplayAssociation)
}

func (d *replayFixtureDispatcher) Invoke(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	_, o, f, ok := FinalizedRequestFromContext(ctx)
	if !ok {
		panic("no actual finalized boundary")
	}
	h := sha256.Sum256([]byte("original receipt"))
	a := fabric.ReplayAssociation{Version: 1, AuthorityNamespace: r.Target.Domain(), AuthorityStoreID: "retained-root", AuthorityKeyRevision: 1, Principal: c.PrincipalView(), RequestID: r.InvocationID, ExecutionID: "original-paid-execution", Target: r.Target, ExpectedRevision: r.ExpectedRevision, OriginalRequestSHA: sha256.Sum256(o), FinalizedRequestSHA: sha256.Sum256(f), InputSHA: sha256.Sum256(r.Input), IdempotencySHA: sha256.Sum256([]byte(r.IdempotencyKey)), BindingFingerprint: h, OriginalReceiptSHA: h, Proof: []byte("retained signed alias")}
	if d.mutate != nil {
		d.mutate(&a)
	}
	d.stream = &replayFixtureStream{association: a, fixtureFrames: fixtureFrames{frames: []fabric.InvocationFrame{{InvocationID: a.ExecutionID, Kind: fabric.FrameStart}, {InvocationID: a.ExecutionID, Sequence: 1, Kind: fabric.FrameChunk, ContentType: "application/json", Data: []byte(`{"n":9007199254740993}`)}, {InvocationID: a.ExecutionID, Sequence: 2, Kind: fabric.FrameComplete}}}}
	return d.stream, nil
}

type replayFixtureVerifier struct {
	calls int
	deny  bool
}

func (v *replayFixtureVerifier) VerifyReplay(_ context.Context, c fabric.ExecutionContext, r fabric.ReplayRequest, a fabric.ReplayAssociation) error {
	v.calls++
	if v.deny {
		return errors.New("current account retired")
	}
	if c.PrincipalView() != a.Principal || r.RequestID != a.RequestID {
		return errors.New("bad fresh identity")
	}
	return nil
}
func TestNodeReplayDefaultDenyBeforePullAndPreservesOriginalExecution(t *testing.T) {
	for _, name := range []string{"missing-verifier", "current-retired", "altered-input", "altered-principal", "verified"} {
		t.Run(name, func(t *testing.T) {
			s, e, _, _, _ := setup(t)
			e.Operation = fabric.OperationInvoke
			ref, _ := fabric.NewEndpointRef(make([]byte, 32))
			e.Target = &ref
			e.ExpectedRevision = "r1"
			e.Context.IdempotencyKey = "same-business-attempt"
			e.Payload = json.RawMessage(`{"n":9007199254740993}`)
			d := &replayFixtureDispatcher{}
			v := &replayFixtureVerifier{}
			s.config.Dispatcher = d
			if name != "missing-verifier" {
				s.config.ReplayVerifier = v
			}
			v.deny = name == "current-retired"
			if name == "altered-input" {
				d.mutate = func(a *fabric.ReplayAssociation) { a.InputSHA[0] ^= 1 }
			}
			if name == "altered-principal" {
				d.mutate = func(a *fabric.ReplayAssociation) { a.Principal.Ref = "local:other" }
			}
			raw, _ := json.Marshal(e)
			result, err := s.Execute(t.Context(), raw, "verified-local-peer")
			if name != "verified" {
				if err == nil || d.stream.pulls != 0 || d.stream.closed != 1 {
					t.Fatal("unverified source consumed", err, d.stream.pulls, d.stream.closed)
				}
				return
			}
			if err != nil || result.Replay == nil || result.Replay.RequestID != e.ID || result.Replay.ExecutionID == e.ID {
				t.Fatal(result, err)
			}
			if d.stream.pulls != 0 {
				t.Fatal("eager replay pull")
			}
			for ordinal := 0; ordinal < 3; ordinal++ {
				f, err := result.Stream.Next(t.Context())
				if err != nil || f.InvocationID != "original-paid-execution" || f.Sequence != uint64(ordinal) {
					t.Fatal(f, err)
				}
			}
			if v.calls != 1 {
				t.Fatal("missing current replay verification")
			}
		})
	}
}
