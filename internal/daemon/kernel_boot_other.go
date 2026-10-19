//go:build !linux && !darwin

package daemon

import (
	"errors"

	"github.com/pagnet-code/pagnet/transport"
)

// CollectKernelBootEvidence reads kernel evidence without deriving it from a daemon boot.
func CollectKernelBootEvidence() (transport.KernelBootEvidence, error) {
	return transport.KernelBootEvidence{}, errors.New("kernel boot evidence unavailable on this platform")
}
