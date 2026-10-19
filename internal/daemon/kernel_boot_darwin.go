package daemon

import (
	"errors"
	"fmt"

	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

// CollectKernelBootEvidence reads kernel evidence without deriving it from a daemon boot.
func CollectKernelBootEvidence() (transport.KernelBootEvidence, error) {
	if raw, err := unix.Sysctl("kern.bootsessionuuid"); err == nil {
		if evidence, err := kernelBootUUID(raw, "darwin_bootsessionuuid"); err == nil {
			return evidence, nil
		}
	}
	// Older kernels expose only a boot time. Report its actual weaker quality;
	// callers must never treat it as UUID evidence authorizing worker recovery.
	boot, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return transport.KernelBootEvidence{}, err
	}
	evidence := transport.KernelBootEvidence{Identity: fmt.Sprintf("%d.%06d", boot.Sec, boot.Usec), Source: "darwin_boottime", Quality: "boot_time"}
	if !evidence.Valid() {
		return transport.KernelBootEvidence{}, errors.New("kernel boot time unavailable")
	}
	return evidence, nil
}
