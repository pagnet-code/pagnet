package transport

import (
	"errors"

	"github.com/pagnet-code/pagnet/domain"
)

const NativeWorkerAvailabilityProtocol = "native-worker-availability-v1"
const MsgNativeWorkerAvailability = "host.native_worker_availability"

// NativeWorkerAvailabilityPayload is ephemeral controller connectivity evidence,
// never runtime liveness, dispatch authority, or a stopped receipt.
type NativeWorkerAvailabilityPayload struct {
	InstanceID          string `json:"instanceId"`
	OwnershipGeneration string `json:"ownershipGeneration"`
	Sequence            int64  `json:"sequence"`
	State               string `json:"state"`
}

func (p NativeWorkerAvailabilityPayload) Validate() error {
	id, err := domain.ParseID(p.InstanceID)
	if err != nil || id.String() != p.InstanceID || len(p.OwnershipGeneration) == 0 || len(p.OwnershipGeneration) > 256 {
		return errors.New("invalid native worker availability identity")
	}
	if p.Sequence <= 0 || (p.State != "connected" && p.State != "unavailable" && p.State != "unknown") {
		return errors.New("invalid native worker availability observation")
	}
	return nil
}
