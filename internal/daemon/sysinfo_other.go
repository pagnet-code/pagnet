//go:build !linux && !darwin

package daemon

import "errors"

var errSysinfoUnsupported = errors.New("system stats not supported on this platform")

// readLoadAvg is unimplemented on this platform: the heartbeat leaves
// cpu_load zero and the UI renders "—".
func readLoadAvg() (float64, error) {
	return 0, errSysinfoUnsupported
}

// readMemInfo is unimplemented on this platform (ok=false).
func readMemInfo() (total, used int64, ok bool) {
	return 0, 0, false
}
