package transport

const NativeWorkerRecoveryProtocol = "native-worker-recovery-v1"
const MsgNativeWorkerRecoveryState = "native.worker.recovery.state"
const MsgNativeWorkerRecoveryAck = "native.worker.recovery.ack"

// NativeWorkerRecoveryState is authoritative only on the admitted host socket.
// It records loss, never an original command result or stopped receipt.
type NativeWorkerRecoveryState struct {
	RecoveryID           string              `json:"recoveryId"`
	InstanceID           string              `json:"instanceId"`
	DefinitionID         string              `json:"definitionId"`
	HostID               string              `json:"hostId"`
	TenantID             string              `json:"tenantId"`
	AccountID            string              `json:"accountId"`
	OwnershipID          string              `json:"ownershipId,omitempty"`
	OwnershipGeneration  string              `json:"ownershipGeneration,omitempty"`
	Action               string              `json:"action"`
	State                string              `json:"state"`
	OriginalBoot         *KernelBootEvidence `json:"originalBoot,omitempty"`
	PrepareBoot          KernelBootEvidence  `json:"prepareBoot"`
	LastDispatchSequence int64               `json:"lastDispatchSequence"`
	RetiredFloor         int64               `json:"retiredFloor"`
}

type NativeWorkerRecoveryAck struct {
	RecoveryID          string             `json:"recoveryId"`
	InstanceID          string             `json:"instanceId"`
	OwnershipGeneration string             `json:"ownershipGeneration,omitempty"`
	Action              string             `json:"action"`
	LocalPhase          string             `json:"localPhase"`
	LocalFenceBoot      KernelBootEvidence `json:"localFenceBoot"`
}
