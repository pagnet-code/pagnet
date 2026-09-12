package domain

import "time"

// RunnerStatus is the lifecycle state of a runner.
type RunnerStatus string

const (
	// RunnerStatusOnline: the runner's WSS is connected and it may be
	// leased new commands.
	RunnerStatusOnline RunnerStatus = "online"
	// RunnerStatusOffline: no live connection.
	RunnerStatusOffline RunnerStatus = "offline"
	// RunnerStatusDraining: an operator asked the runner to stop taking
	// new work (existing work finishes); the scheduler excludes it from
	// selection until it reconnects or is undrained.
	RunnerStatusDraining RunnerStatus = "draining"
)

func (s RunnerStatus) Valid() bool {
	switch s {
	case RunnerStatusOnline, RunnerStatusOffline, RunnerStatusDraining:
		return true
	}
	return false
}

// Runner is one daemon process under a host. A host may run several
// runners (daemons) in parallel; each is identified by the (host_id,
// boot_id) pair — boot_id is minted by the daemon at every startup and
// carried in the WSS connect handshake. A reconnect of the same boot
// identity reuses the runner row; a second daemon under the same host
// gets its own row and coexists with the first.
//
// Runners are additive to hosts: the host keeps its identity, credential
// and host-level settings (roots, workspaces, instances); the runner is
// the execution unit commands are leased to. No secrets live here.
type Runner struct {
	ID           ID
	TenantID     ID
	HostID       ID
	BootID       string
	Hostname     string
	Version      string
	Capabilities []string          // runtimes this runner can drive
	Labels       map[string]string // operator metadata
	Capacity     map[string]any    // structured capacity hints (JSON)
	Status       RunnerStatus
	ConnectedAt  *time.Time
	LastSeenAt   *time.Time
	DrainingAt   *time.Time
	CreatedAt    time.Time
}

// DefaultBootID is the boot identity of the synthetic runner every host
// gets at migration time (and that legacy daemons — no connect handshake —
// register under), so single-daemon installs keep working.
const DefaultBootID = "default"
