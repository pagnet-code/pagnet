package fabricnative

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestClosedNativeStreamPreservesDeadlineAndCancellationWithoutInventedFrames(t *testing.T) {
	// Actual Close sets closed under mu before cancel outside the lock. Keep
	// the lifetime active to reproduce that interval deterministically.
	early := &nativeStream{closed: true, lifetime: t.Context()}
	if frame, err := early.Next(t.Context()); frame.Kind != "" {
		t.Fatal("stop fabricated frame", frame, err)
	} else {
		var typed *fabric.Error
		if !errors.As(err, &typed) || typed.Code != fabric.CodeCancelled {
			t.Fatal("stop/cancel publication race became EOF", err)
		}
	}

	for _, v := range []struct {
		deadline bool
		code     fabric.ErrorCode
	}{{true, fabric.CodeDeadlineExceeded}, {false, fabric.CodeCancelled}} {
		var ctx context.Context
		var cancel context.CancelFunc
		if v.deadline {
			ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		} else {
			ctx, cancel = context.WithCancel(t.Context())
			cancel()
		}
		defer cancel()
		s := &nativeStream{closed: true, lifetime: ctx}
		frame, e := s.Next(t.Context())
		var f *fabric.Error
		if !errors.As(e, &f) || f.Code != v.code || frame.Kind != "" {
			t.Fatal("closed source forged/obscured failure", frame, e)
		}
		s.terminal = true
		if _, e = s.Next(t.Context()); !errors.Is(e, io.EOF) {
			t.Fatal("genuine terminal EOF changed", e)
		}
	}
}
