package fabric

import "context"

// OriginalSourceOwnership is adapter-owned infrastructure evidence, not a wire
// credential or caller grant. Consumers must verify the concrete original
// receipt against their selected binding before publishing an association.
type OriginalSourceOwnership interface {
	OriginalSourceProtocol() string
	Close() error
}

// OriginalPipelineSource permits only one already accepted source's output to
// pass through its ORIGINAL outer stream pipeline independently of viewer
// disclosure. The callback must invoke that same outer Next; this port never
// skips framing/interceptors/unwind, creates work, or renews paid authority.
// Implementations keep the capability private, exact-stream and callback-lived.
type OriginalPipelineSource interface {
	OriginalSourceOwnership(context.Context) (OriginalSourceOwnership, error)
	WithOriginalCapture(context.Context, func(context.Context) error) error
}

// WithOriginalSourceCapture forwards only an actual upstream capability. An
// unsupported stream cannot be reclassified as an original source.
func WithOriginalSourceCapture(ctx context.Context, s InvocationStream, next func(context.Context) error) error {
	if ctx == nil || next == nil {
		return NewError(CodeInvalidInput, "Missing original pipeline capture")
	}
	p, ok := s.(OriginalPipelineSource)
	if !ok {
		return NewError(CodeUnsupported, "Original pipeline capture unavailable")
	}
	return p.WithOriginalCapture(ctx, next)
}
func OriginalStreamOwnership(ctx context.Context, s InvocationStream) (OriginalSourceOwnership, error) {
	if ctx == nil {
		return nil, NewError(CodeInvalidInput, "Missing original source context")
	}
	p, ok := s.(OriginalPipelineSource)
	if !ok {
		return nil, NewError(CodeUnsupported, "Original source ownership unavailable")
	}
	return p.OriginalSourceOwnership(ctx)
}
