package continuations

import (
	"context"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

type captureForwardFixture struct {
	reads, closes, captures int
	owner                   *captureForwardOwner
}
type captureForwardOwner struct{ closed bool }

func (*captureForwardOwner) OriginalSourceProtocol() string { return "test.exact-source" }
func (o *captureForwardOwner) Close() error                 { o.closed = true; return nil }
func (s *captureForwardFixture) Next(context.Context) (fabric.InvocationFrame, error) {
	s.reads++
	return fabric.InvocationFrame{}, nil
}
func (s *captureForwardFixture) Close() error { s.closes++; return nil }
func (s *captureForwardFixture) OriginalSourceOwnership(context.Context) (fabric.OriginalSourceOwnership, error) {
	return s.owner, nil
}

type captureForwardKey struct{}

func (s *captureForwardFixture) WithOriginalCapture(ctx context.Context, next func(context.Context) error) error {
	s.captures++
	return next(context.WithValue(ctx, captureForwardKey{}, s.owner))
}

func TestContinuationCaptureForwardsOnlyExactUpstreamWithoutSettlement(t *testing.T) {
	upstream := &captureForwardFixture{owner: &captureForwardOwner{}}
	// Nil settlement is intentional: forwarding must not settle or read work.
	stream := &resultStream{InvocationStream: &targetStream{InvocationStream: upstream}}
	owner, e := stream.OriginalSourceOwnership(t.Context())
	if e != nil || owner != upstream.owner {
		t.Fatal("ownership replaced", e)
	}
	want := errors.New("exact callback result")
	e = stream.WithOriginalCapture(t.Context(), func(ctx context.Context) error {
		if ctx.Value(captureForwardKey{}) != owner {
			t.Fatal("capture context replaced")
		}
		return want
	})
	if e != want || upstream.captures != 1 || upstream.reads != 0 || upstream.closes != 0 || upstream.owner.closed {
		t.Fatal("forwarding altered original lifecycle", e)
	}
	unsupported := &resultStream{InvocationStream: &frames{}}
	if _, e = unsupported.OriginalSourceOwnership(t.Context()); e == nil {
		t.Fatal("unsupported source ownership fabricated")
	}
	if e = unsupported.WithOriginalCapture(t.Context(), func(context.Context) error { t.Fatal("unsupported capture callback"); return nil }); e == nil {
		t.Fatal("unsupported source accepted")
	}
}
