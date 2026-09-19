package sdk

import (
	"testing"
	"time"
)

// fixedRnd returns a jitter source pinned to a value, for deterministic
// bounds checks.
func fixedRnd(v float64) func() float64 { return func() float64 { return v } }

func TestNextBackoffWithinBounds(t *testing.T) {
	// For each attempt level, the delay must be in (0, cap] where cap
	// doubles from 1s up to the 30s ceiling.
	for attempt := 0; attempt <= 10; attempt++ {
		cap := backoffCapAt(attempt)
		// Check at jitter extremes (just above 0 and at 1).
		for _, v := range []float64{0.0001, 0.5, 0.9999} {
			d := nextBackoff(attempt, fixedRnd(v))
			if d <= 0 {
				t.Fatalf("attempt %d rnd %v: delay %v must be > 0", attempt, v, d)
			}
			if d > cap {
				t.Fatalf("attempt %d rnd %v: delay %v exceeds cap %v", attempt, v, d, cap)
			}
		}
	}
}

func TestNextBackoffFirstRetryAboutOneSecond(t *testing.T) {
	// The first retry (attempt 0) has a 1s cap: with full jitter the delay
	// is in (0, 1s].
	d := nextBackoff(0, fixedRnd(0.9999))
	if d > time.Second {
		t.Fatalf("first retry delay %v exceeds 1s", d)
	}
	if d <= 0 {
		t.Fatalf("first retry delay %v must be positive", d)
	}
}

func TestBackoffCapDoublingAndCeiling(t *testing.T) {
	want := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second, // capped (32s would exceed)
		30 * time.Second, // stays capped
		30 * time.Second,
	}
	for i, w := range want {
		if got := backoffCapAt(i); got != w {
			t.Fatalf("backoffCapAt(%d) = %v, want %v", i, got, w)
		}
	}
}

func TestBackoffCapNegativeAttempt(t *testing.T) {
	if got := backoffCapAt(-5); got != time.Second {
		t.Fatalf("backoffCapAt(-5) = %v, want 1s", got)
	}
}
