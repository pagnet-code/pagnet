package daemon

import (
	"errors"
	"strings"

	"github.com/pagnet-code/pagnet/transport"
)

func kernelBootUUID(identity, source string) (transport.KernelBootEvidence, error) {
	evidence := transport.KernelBootEvidence{Identity: strings.ToLower(strings.TrimSpace(identity)), Source: source, Quality: "boot_uuid"}
	if !evidence.Valid() {
		return transport.KernelBootEvidence{}, errors.New("kernel boot UUID unavailable")
	}
	return evidence, nil
}
