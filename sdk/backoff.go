package sdk

import (
	"math"
	"time"
)

// Reconnect backoff bounds (north-star: exponential backoff + jitter,
// 1s..30s cap). The first retry waits ~1s; each consecutive failure doubles
// the cap up to 30s; full jitter (uniform in (0, cap]) keeps a fleet of
// endpoints from thundering the control plane on a shared outage.
const (
	backoffBase = 1 * time.Second
	backoffCap  = 30 * time.Second
)

// nextBackoff computes the reconnect delay after attempt failures
// (attempt is 0-based: the first retry is attempt 0). rnd draws the jitter
// in [0,1); production passes rand.Float64, tests pass a fixed source.
func nextBackoff(attempt int, rnd func() float64) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	shift := math.Pow(2, float64(attempt))
	cap := float64(backoffBase) * shift
	if cap > float64(backoffCap) {
		cap = float64(backoffCap)
	}
	// Full jitter: uniform in (0, cap]. (0 is excluded so a retry always
	// happens; the cap is the max wait at this attempt level.)
	return time.Duration(float64(time.Millisecond) + rnd()*(cap-float64(time.Millisecond)))
}

// backoffCapAt returns the pre-jitter cap for an attempt level (exported for
// tests and for operators reasoning about worst-case reconnect latency).
func backoffCapAt(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	cap := float64(backoffBase) * math.Pow(2, float64(attempt))
	if cap > float64(backoffCap) {
		cap = float64(backoffCap)
	}
	return time.Duration(cap)
}
