package domain

import "time"

// Host is a physical or virtual machine running the pagnet daemon. A host
// is NOT a network: it may run agents belonging to different networks.
type Host struct {
	ID            ID
	TenantID      ID
	Name          string
	Status        HostStatus
	OS            string
	Arch          string
	DaemonVersion string

	CPUCount      int
	CPULoad       float64
	MemTotalBytes int64
	MemUsedBytes  int64
	DiskFreeBytes int64

	// RootsMode selects how the host's allowed roots are enforced
	// (allow_all by default: any absolute, existing path; allow_list:
	// only paths under one of the host's allowed roots).
	RootsMode string

	LastHeartbeatAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Host roots modes (hosts.roots_mode).
const (
	// RootsModeAllowAll is the default: the host allows any absolute,
	// existing path (the allowed-roots list is ignored).
	RootsModeAllowAll = "allow_all"
	// RootsModeAllowList confines the host to its allowed roots (the
	// existing enforcement: a path must sit under one of them).
	RootsModeAllowList = "allow_list"
)

// ValidRootsMode reports whether m is a known host roots mode (an empty
// mode is treated as the default, allow_all).
func ValidRootsMode(m string) bool {
	return m == "" || m == RootsModeAllowAll || m == RootsModeAllowList
}

// Online reports whether the host should be considered reachable based on its
// last heartbeat (threshold supplied by the server).
func (h Host) Online(offlineThreshold time.Duration) bool {
	if h.Status == HostStatusOnline && h.LastHeartbeatAt != nil {
		return time.Since(*h.LastHeartbeatAt) < offlineThreshold
	}
	return false
}

// HostAllowedRoot confines what filesystem paths a host may expose to the
// control plane. Canonicalized, symlink-resolved paths only.
type HostAllowedRoot struct {
	ID        ID
	HostID    ID
	Path      string
	CreatedAt time.Time
}

// RuntimeInstallation is a runtime detected on a host.
type RuntimeInstallation struct {
	ID         ID
	HostID     ID
	Runtime    RuntimeName
	Version    string
	Path       string
	DetectedAt time.Time
}

// EnrollmentToken is a one-time, short-lived token that enrolls a host.
// Stored hashed server-side.
type EnrollmentToken struct {
	ID           ID
	TenantID     ID
	TokenName    string // display name, e.g. "enroll owl"
	AllowedRoots []string
	ExpiresAt    time.Time
	UsedAt       *time.Time
}

// HostMetrics is the per-heartbeat machine telemetry reported by the daemon.
type HostMetrics struct {
	CPUCount      int
	CPULoad       float64
	MemTotalBytes int64
	MemUsedBytes  int64
	DiskFreeBytes int64
}
