package fabricnode

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
)

// Infrastructure worker ownership remains the actual protected local operator.
// A remote caller cannot become that operator; historical source recovery uses
// only the exact signed source under existing local original-origin checks.
func (b *RemoteBoundary) WithNativeControl(ctx context.Context, f identity.NativeControlFacts, next func() error) error {
	return b.local.WithNativeControl(ctx, f, next)
}
func (b *RemoteBoundary) WithCurrentOwner(ctx context.Context, c fabric.ExecutionContext, next func(context.Context) error) error {
	return b.local.WithCurrentOwner(ctx, c, next)
}
func (b *RemoteBoundary) WithHistoricalNativeOrigin(ctx context.Context, f identity.HistoricalNativeOriginFacts, next func(identity.Witness) error) error {
	return b.local.WithHistoricalNativeOrigin(ctx, f, next)
}
