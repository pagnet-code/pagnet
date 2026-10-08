//go:build !linux && !darwin

package fabricnode

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
)

// start is explicitly unavailable off unix: the relay transport is a unix
// domain socket. Enabling the federation surface on this platform is a
// startup failure, never a silent skip.
func (r *federationRelay) start(ctx context.Context) error {
	if r == nil {
		return localDenied()
	}
	return fabric.NewError(fabric.CodeUnsupported, "Federation serving requires a unix domain relay transport")
}
