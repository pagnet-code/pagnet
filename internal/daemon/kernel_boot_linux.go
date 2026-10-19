package daemon

import (
	"os"

	"github.com/pagnet-code/pagnet/transport"
)

// CollectKernelBootEvidence reads kernel evidence without deriving it from a daemon boot.
func CollectKernelBootEvidence() (transport.KernelBootEvidence, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return transport.KernelBootEvidence{}, err
	}
	return kernelBootUUID(string(raw), "linux_boot_id")
}
