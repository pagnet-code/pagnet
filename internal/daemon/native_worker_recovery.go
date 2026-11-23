package daemon

import (
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// NativeWorkerRecovery is an immutable durable fence. Empty OriginalGeneration
// fences the whole legacy instance; LocalGeneration records only the generation
// actually found locally, for later cleanup. Collection never removes the fence.
type NativeWorkerRecovery struct {
	LaunchProof          NativeWorkerLaunchRecoveryProof
	RecoveryID           string
	DefinitionID         string
	HostID               string
	TenantID             string
	AccountID            string
	OwnershipID          string
	LastDispatchSequence int64
	RetiredFloor         int64
	ServerCleaned        bool
	InstanceID           string
	OriginalGeneration   string
	Action               string
	OriginalBoot         transport.KernelBootEvidence
	PrepareBoot          transport.KernelBootEvidence
	FenceBoot            transport.KernelBootEvidence
	LocalGeneration      string
	Phase                string
}

// ProvesNewBoot requires a real UUID boot after both the server preparation and
// the local durable fence. Even an owned generation may not have launched until
// after its original ownership boot, so original evidence alone is insufficient.
func (r NativeWorkerRecovery) ProvesNewBoot(current transport.KernelBootEvidence) bool {
	if !current.ProvesNewBoot(r.PrepareBoot) || !current.ProvesNewBoot(r.FenceBoot) {
		return false
	}
	return r.OriginalBoot == (transport.KernelBootEvidence{}) || current.ProvesNewBoot(r.OriginalBoot)
}

// NativeWorkerLaunchRecoveryProof freezes the consumed claim behind the fence.
// It is local authority only; only DeathProof crosses the host socket.
type NativeWorkerLaunchRecoveryProof struct {
	Scope               sessionworker.Scope
	Profile             string
	ProfileFingerprint  string
	OriginalOwnershipID string
	LaunchBoot          transport.KernelBootEvidence
	DeathProof          transport.NativeWorkerRecoveryDeathProof
}

func (r NativeWorkerRecovery) provesPriorLaunchBoot(current transport.KernelBootEvidence) bool {
	p := r.LaunchProof
	return p.DeathProof.Kind == "prior_launch_boot" && p.DeathProof.LaunchBoot == p.LaunchBoot && current.ProvesNewBoot(p.LaunchBoot) && (r.OriginalBoot == (transport.KernelBootEvidence{}) || current.ProvesNewBoot(r.OriginalBoot))
}
