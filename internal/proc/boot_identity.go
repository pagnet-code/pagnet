package proc

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// BootIdentity identifies one kernel boot. Source names the kernel interface;
// Quality is boot_uuid for a kernel UUID or boot_time for the weaker Darwin
// fallback, whose wall-clock timestamp may change after clock corrections.
// ID includes the source family so unlike sources cannot compare equal.
// Successful reads always return a nonempty ID shorter than 128 bytes.
type BootIdentity struct {
	ID      string
	Source  string
	Quality string
}

const linuxBootIDPath = "/proc/sys/kernel/random/boot_id"

func parseBootUUID(raw, prefix, source string) (BootIdentity, error) {
	if len(raw) > 64 {
		return BootIdentity{}, fmt.Errorf("proc: %s boot UUID exceeds limit", source)
	}
	value := strings.TrimSpace(raw)
	id, err := uuid.Parse(value)
	if err != nil || len(value) != 36 || id == uuid.Nil || id.String() != strings.ToLower(value) {
		return BootIdentity{}, fmt.Errorf("proc: %s returned an invalid boot UUID", source)
	}
	return BootIdentity{ID: prefix + id.String(), Source: source, Quality: "boot_uuid"}, nil
}

func readLinuxBootIdentity(readFile func(string) ([]byte, error)) (BootIdentity, error) {
	raw, err := readFile(linuxBootIDPath)
	if err != nil {
		return BootIdentity{}, fmt.Errorf("proc: read kernel boot ID: %w", err)
	}
	return parseBootUUID(string(raw), "linux-boot-id:", linuxBootIDPath)
}

func readDarwinBootIdentity(readString func(string) (string, error), readTime func(string) (int64, int64, error)) (BootIdentity, error) {
	raw, uuidErr := readString("kern.bootsessionuuid")
	if uuidErr == nil {
		var identity BootIdentity
		identity, uuidErr = parseBootUUID(raw, "darwin-boot-session:", "kern.bootsessionuuid")
		if uuidErr == nil {
			return identity, nil
		}
	}
	sec, usec, timeErr := readTime("kern.boottime")
	if timeErr == nil {
		// Positive, representable civil time and a normalized timeval are required.
		if sec <= 0 || sec > 253402300799 || usec < 0 || usec >= 1000000 {
			timeErr = errors.New("invalid kernel boot timeval")
		} else {
			return BootIdentity{ID: fmt.Sprintf("darwin-boot-time:%d:%d", sec, usec), Source: "kern.boottime", Quality: "boot_time"}, nil
		}
	}
	return BootIdentity{}, fmt.Errorf("proc: kernel boot identity unavailable: %w", errors.Join(uuidErr, timeErr))
}
