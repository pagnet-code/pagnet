//go:build linux

package daemon

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readLoadAvg reads the 1-minute load average from /proc/loadavg.
func readLoadAvg() (float64, error) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty loadavg")
	}
	return strconv.ParseFloat(fields[0], 64)
}

// readMemInfo reads host memory from /proc/meminfo (NOT the daemon's Go
// heap). ok=false when the file is unavailable so the caller leaves the
// fields zero.
func readMemInfo() (total, used int64, ok bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	var memTotal, memAvail uint64
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			memTotal = meminfoKB(rest)
		} else if rest, ok := strings.CutPrefix(line, "MemAvailable:"); ok {
			memAvail = meminfoKB(rest)
		}
	}
	if memTotal == 0 {
		return 0, 0, false
	}
	used = int64(memTotal) - int64(memAvail)
	if used < 0 {
		used = 0
	}
	return int64(memTotal), used, true
}

// meminfoKB parses the "12345 kB" value of one /proc/meminfo line.
func meminfoKB(rest string) uint64 {
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return 0
	}
	n, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return n * 1024
}
