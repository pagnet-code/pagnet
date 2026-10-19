package transport

import (
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// KernelBootEvidence identifies an OS boot independently of the daemon process.
// A boot time is inventory evidence only; recovery requires a boot UUID.
type KernelBootEvidence struct {
	Identity string `json:"identity"`
	Source   string `json:"source"`
	Quality  string `json:"quality"`
}

func (b KernelBootEvidence) Valid() bool {
	if b.Identity == "" || len(b.Identity) > 256 || strings.TrimSpace(b.Identity) != b.Identity {
		return false
	}
	switch b.Source {
	case "linux_boot_id", "darwin_bootsessionuuid":
		id, err := uuid.Parse(b.Identity)
		return b.Quality == "boot_uuid" && err == nil && id != uuid.Nil && id.String() == b.Identity
	case "darwin_boottime":
		parts := strings.Split(b.Identity, ".")
		if b.Quality != "boot_time" || len(parts) != 2 || len(parts[1]) != 6 {
			return false
		}
		sec, err := strconv.ParseInt(parts[0], 10, 64)
		usec, microErr := strconv.ParseUint(parts[1], 10, 32)
		return err == nil && sec > 0 && microErr == nil && usec < 1000000
	}
	return false
}

// ProvesNewBoot requires comparable kernel UUIDs. A daemon restart, missing
// evidence, source change, or coarse boot time cannot prove worker death.
func (b KernelBootEvidence) ProvesNewBoot(original KernelBootEvidence) bool {
	return b.Valid() && original.Valid() && b.Source == original.Source && b.Quality == "boot_uuid" && original.Quality == "boot_uuid" && b.Identity != original.Identity
}
