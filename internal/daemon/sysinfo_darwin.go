//go:build darwin

package daemon

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// readLoadAvg returns the 1-minute load average from sysctl vm.loadavg
// (three int32 values, 1/5/15 min, scaled by 100).
func readLoadAvg() (float64, error) {
	raw, err := unix.SysctlRaw("vm.loadavg")
	if err != nil {
		return 0, err
	}
	if len(raw) < 4 {
		return 0, fmt.Errorf("short vm.loadavg sysctl reply")
	}
	load := int32(binary.LittleEndian.Uint32(raw))
	return float64(load) / 100.0, nil
}

// readMemInfo reports host memory via sysctl. "Used" is total minus
// (free + inactive) pages: inactive pages are reclaimable file cache, the
// darwin analogue of Linux's MemAvailable, so the semantics match the
// linux implementation.
func readMemInfo() (total, used int64, ok bool) {
	totalU, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0, 0, false
	}
	pageU, err := unix.SysctlUint64("hw.pagesize")
	if err != nil {
		return 0, 0, false
	}
	freeRaw, err := unix.SysctlRaw("vm.stats.page.pagesfree")
	if err != nil || len(freeRaw) < 8 {
		return 0, 0, false
	}
	availPages := binary.LittleEndian.Uint64(freeRaw)
	if inactRaw, err := unix.SysctlRaw("vm.stats.page.inactcount"); err == nil && len(inactRaw) >= 8 {
		availPages += binary.LittleEndian.Uint64(inactRaw)
	}
	total = int64(totalU)
	used = total - int64(availPages)*int64(pageU)
	if used < 0 {
		used = 0
	}
	return total, used, true
}
