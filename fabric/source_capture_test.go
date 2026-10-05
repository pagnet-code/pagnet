package fabric

import (
	"context"
	"errors"
	"io"
	"testing"
)

type captureFixtureOwnership struct{}

func (*captureFixtureOwnership) OriginalSourceProtocol() string { return "fixture.original" }
func (*captureFixtureOwnership) Close() error                   { return nil }

type captureFixtureStream struct {
	owner                *captureFixtureOwnership
	next, close, capture int
	callback             context.Context
}

func (s *captureFixtureStream) Next(context.Context) (InvocationFrame, error) {
	s.next++
	return InvocationFrame{}, io.EOF
}
func (s *captureFixtureStream) Close() error { s.close++; return nil }
func (s *captureFixtureStream) OriginalSourceOwnership(context.Context) (OriginalSourceOwnership, error) {
	return s.owner, nil
}
func (s *captureFixtureStream) WithOriginalCapture(ctx context.Context, next func(context.Context) error) error {
	s.capture++
	return next(s.callback)
}

type plainCaptureFixture struct{ captureFixtureStream }

// Explicit plain wrapper retains only the InvocationStream interface.
type noCaptureStream struct{ inner *captureFixtureStream }

func (s noCaptureStream) Next(ctx context.Context) (InvocationFrame, error) { return s.inner.Next(ctx) }
func (s noCaptureStream) Close() error                                      { return s.inner.Close() }
func TestOriginalCaptureCheckedForwardingHasNoConsumptionOrSyntheticAuthority(t *testing.T) {
	ctx := context.WithValue(t.Context(), struct{}{}, "owned callback")
	upstream := &captureFixtureStream{owner: &captureFixtureOwnership{}, callback: ctx}
	checked, err := NewCheckedStream(t.Context(), "original", upstream)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := OriginalStreamOwnership(t.Context(), checked)
	if err != nil || owner != upstream.owner {
		t.Fatal("changed original ownership", err)
	}
	sentinel := errors.New("original callback failure")
	if err = WithOriginalSourceCapture(t.Context(), checked, func(got context.Context) error {
		if got != ctx {
			t.Fatal("reconstructed capture context")
		}
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatal("lost callback failure", err)
	}
	if upstream.next != 0 || upstream.close != 0 || upstream.capture != 1 {
		t.Fatal("forwarding consumed/closed source", upstream)
	}
	plain := noCaptureStream{upstream}
	if _, err = OriginalStreamOwnership(t.Context(), plain); err == nil {
		t.Fatal("unsupported source gained ownership")
	}
	if err = WithOriginalSourceCapture(t.Context(), plain, func(context.Context) error { t.Fatal("unsupported source ran capture"); return nil }); err == nil {
		t.Fatal("unsupported source gained capture")
	}
}
