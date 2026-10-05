package continuations

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
)

// Forward only the actual accepted upstream source. These ports do not read a
// frame, settle/release a claim, close a native effect or promote a resumer.
func (s *targetStream) OriginalSourceOwnership(ctx context.Context) (fabric.OriginalSourceOwnership, error) {
	if s == nil {
		return nil, fabric.NewError(fabric.CodeUnsupported, "Original continuation source unavailable")
	}
	return fabric.OriginalStreamOwnership(ctx, s.InvocationStream)
}
func (s *targetStream) WithOriginalCapture(ctx context.Context, next func(context.Context) error) error {
	if s == nil {
		return fabric.NewError(fabric.CodeUnsupported, "Original continuation source unavailable")
	}
	return fabric.WithOriginalSourceCapture(ctx, s.InvocationStream, next)
}
func (s *resultStream) OriginalSourceOwnership(ctx context.Context) (fabric.OriginalSourceOwnership, error) {
	if s == nil {
		return nil, fabric.NewError(fabric.CodeUnsupported, "Original continuation source unavailable")
	}
	return fabric.OriginalStreamOwnership(ctx, s.InvocationStream)
}
func (s *resultStream) WithOriginalCapture(ctx context.Context, next func(context.Context) error) error {
	if s == nil {
		return fabric.NewError(fabric.CodeUnsupported, "Original continuation source unavailable")
	}
	return fabric.WithOriginalSourceCapture(ctx, s.InvocationStream, next)
}
