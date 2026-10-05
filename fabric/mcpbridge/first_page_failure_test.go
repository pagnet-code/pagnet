package mcpbridge

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

type initialFailureStream struct{ err error }

func (s initialFailureStream) Next(context.Context) (fabric.InvocationFrame, error) {
	return fabric.InvocationFrame{}, s.err
}
func (initialFailureStream) Close() error { return nil }
func TestFirstPagePreservesActualFailureBeforeOriginalStart(t *testing.T) {
	typed := fabric.NewError(fabric.CodeTargetUnavailable, "original source unknown")
	for _, v := range []struct {
		err  error
		code fabric.ErrorCode
	}{{context.DeadlineExceeded, fabric.CodeDeadlineExceeded}, {context.Canceled, fabric.CodeCancelled}, {typed, fabric.CodeTargetUnavailable}, {io.EOF, fabric.CodeProtocolError}} {
		_, e := (&Bridge{}).firstPage(t.Context(), &streamEntry{stream: initialFailureStream{v.err}})
		var f *fabric.Error
		if !errors.As(e, &f) || f.Code != v.code {
			t.Fatalf("%v became %v", v.err, e)
		}
		if v.err == typed && e != typed {
			t.Fatal("original typed effect attribution replaced")
		}
	}
}
