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
	free, okFree := darwinPageCount("vm.page_free_count", "vm.stats.page.pagesfree")
	if !okFree {
		return 0, 0, false
	}
	availPages := free
	if inact, okInact := darwinPageCount("vm.page_inactive_count", "vm.stats.page.inactcount"); okInact {
		availPages += inact
	}
	total = int64(totalU)
	used = total - int64(availPages)*int64(pageU)
	if used < 0 {
		used = 0
	}
	return total, used, true
}

// darwinPageCount reads the first sysctl that exists. macOS renamed the
// vm_statistics64 page counters between releases (vm.stats.page.* is the
// pre-10.7 spelling; modern systems expose vm.page_*_count), so try the
// current name first and fall back to the legacy one.
func darwinPageCount(names ...string) (uint64, bool) {
	for _, n := range names {
		if raw, err := unix.SysctlRaw(n); err == nil && len(raw) >= 8 {
			return binary.LittleEndian.Uint64(raw), true
		}
	}
	return 0, false
}
