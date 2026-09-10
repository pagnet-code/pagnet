package daemon

// P6 worker auto-update: the pure version-comparison gate (shouldUpdate)
// plus the daemon-side gates (idle gate, single-flight, 1h backoff) and
// the configStale fingerprint — all testable without a network.

import (
	"testing"
	"time"

	"pagnet/internal/domain"
)

// shouldUpdate is the pure version-comparison gate for worker
// auto-update; the table pins its semantics (see the function docs).
func TestShouldUpdate(t *testing.T) {
	cases := []struct {
		name    string
		current string
		latest  string
		want    bool
	}{
		// equal
		{"equal plain", "1.2.3", "1.2.3", false},
		{"equal v-prefixed", "v1.2.3", "v1.2.3", false},
		{"equal across v prefix", "v1.2.3", "1.2.3", false},
		// dev / hash / non-numeric current -> any release
		{"dev to release", "dev", "v1.0.0", true},
		{"git hash to release", "a1b2c3d4e5f6", "v0.3.0", true},
		{"non-numeric current to release", "nightly-20260910", "v0.3.0", true},
		// numeric per-component (NOT lexicographic)
		{"patch bump", "1.2.3", "1.2.4", true},
		{"patch older", "1.2.4", "1.2.3", false},
		{"numeric 1.10 > 1.9", "1.9", "1.10", true},
		{"numeric 1.9 < 1.10", "1.10", "1.9", false},
		{"major wins", "1.99", "2.0", true},
		{"major older", "2.0", "1.99", false},
		{"missing component = 0 (equal)", "1.2", "1.2.0", false},
		{"missing component = 0 (newer)", "1.2", "1.2.1", true},
		{"leading zeros compare numerically (equal)", "1.02", "1.2", false},
		{"leading zeros compare numerically (newer)", "1.02", "1.3", true},
		// empty / garbage latest
		{"empty current", "", "v1.0.0", false},
		{"empty latest", "v1.0.0", "", false},
		{"garbage latest", "1.0.0", "garbage", false},
		{"suffixed latest is not a release", "1.0.0", "v1.0.0-rc1", false},
		{"word latest", "1.0.0", "latest", false},
		// pre-release / build suffix on current compares as its base
		{"dirty current does not loop to same base", "1.2.3-dirty", "1.2.3", false},
		{"dirty current updates to newer base", "1.2.3-dirty", "1.2.4", true},
		{"build suffix does not loop", "1.2.3+build", "1.2.3", false},
		{"v-prefixed dirty does not loop", "v0.2.2-dirty", "v0.2.2", false},
		{"v-prefixed dirty updates to newer", "v0.2.2-dirty", "v0.3.0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldUpdate(tc.current, tc.latest); got != tc.want {
				t.Fatalf("shouldUpdate(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
			}
		})
	}
}

// The trigger gates: disabled / no newer version / 1h failure backoff
// must each keep the update from starting (no goroutine, no flag set).
func TestTriggerAutoUpdate_Gates(t *testing.T) {
	setLatest := func(d *Daemon, v string) {
		d.updMu.Lock()
		d.latestVersion = v
		d.updMu.Unlock()
	}
	updating := func(d *Daemon) bool {
		d.updMu.Lock()
		defer d.updMu.Unlock()
		return d.updating
	}

	t.Run("disabled", func(t *testing.T) {
		d := newTestDaemon(t)
		d.Version = "1.0.0"
		d.AutoUpdate = false
		setLatest(d, "1.0.1")
		d.triggerAutoUpdate()
		if updating(d) {
			t.Fatal("auto-update must not start when disabled")
		}
	})
	t.Run("no newer version", func(t *testing.T) {
		d := newTestDaemon(t)
		d.Version = "1.0.0"
		d.AutoUpdate = true
		setLatest(d, "1.0.0")
		d.triggerAutoUpdate()
		if updating(d) {
			t.Fatal("auto-update must not start when versions are equal")
		}
	})
	t.Run("backoff after a failed attempt", func(t *testing.T) {
		d := newTestDaemon(t)
		d.Version = "1.0.0"
		d.AutoUpdate = true
		d.updMu.Lock()
		d.latestVersion = "1.0.1"
		d.lastAttempt = time.Now() // inside the 1h backoff window
		d.updMu.Unlock()
		d.triggerAutoUpdate()
		if updating(d) {
			t.Fatal("auto-update must not start inside the backoff window")
		}
	})
}

// IDLE GATE (pre): a busy worker defers the update WITHOUT recording a
// download attempt (no backoff — the next heartbeat retries).
func TestPerformAutoUpdate_DefersWhenBusy(t *testing.T) {
	d := newTestDaemon(t)
	d.Version = "1.0.0"
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID:   domain.NewID().String(),
		DefinitionID: "def-1",
		Runtime:      "fake",
		Status:       "working",
	}); err != nil {
		t.Fatal(err)
	}
	d.performAutoUpdate("1.0.1")
	d.updMu.Lock()
	attempt := d.lastAttempt
	upd := d.updating
	d.updMu.Unlock()
	if upd {
		t.Fatal("performAutoUpdate must release the updating flag")
	}
	if !attempt.IsZero() {
		t.Fatal("a busy worker must not record a download attempt (no backoff)")
	}
}

// Failure path: an unparseable server URL makes the download fail before
// any network I/O — the attempt must record the backoff timestamp and
// release the updating flag (the daemon keeps running, never crashes).
func TestPerformAutoUpdate_FailureSetsBackoff(t *testing.T) {
	d := newTestDaemon(t)
	d.Version = "1.0.0"
	d.ServerURL = "" // download URL has no scheme: a clean failure
	d.performAutoUpdate("1.0.1")
	d.updMu.Lock()
	attempt := d.lastAttempt
	upd := d.updating
	d.updMu.Unlock()
	if upd {
		t.Fatal("performAutoUpdate must release the updating flag")
	}
	if attempt.IsZero() {
		t.Fatal("a failed attempt must set the backoff timestamp")
	}
}

// activeWorkCount is the idle-gate metric: zero when idle, non-zero for
// each active work unit (turn, PTY, working instance).
func TestActiveWorkCount(t *testing.T) {
	d := newTestDaemon(t)
	if n := d.activeWorkCount(); n != 0 {
		t.Fatalf("fresh daemon must be idle, got %d active", n)
	}
	id := domain.NewID().String()
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: id, DefinitionID: "def-1", Runtime: "fake", Status: "working",
	}); err != nil {
		t.Fatal(err)
	}
	if n := d.activeWorkCount(); n != 1 {
		t.Fatalf("one working instance must count as 1 active, got %d", n)
	}
	d.turnMu.Lock()
	d.activeTurns[id] = true
	d.turnMu.Unlock()
	if n := d.activeWorkCount(); n != 2 {
		t.Fatalf("working instance + active turn must count as 2 active, got %d", n)
	}
}

// configStale (P6): the fingerprint is recorded when a PTY starts and
// must go stale when the daemon's version changes (an auto-update
// re-exec) — and never stale for an instance that never had a PTY.
func TestConfigStale_Fingerprint(t *testing.T) {
	d := newTestDaemon(t)
	d.Version = "1.0.0"
	id := domain.NewID().String()
	row := InstanceRow{
		InstanceID: id, DefinitionID: "def-1", Runtime: "fake",
		Status: "idle", NetworkID: "net-1", AgentName: "coder",
	}
	if err := d.state.UpsertInstance(row); err != nil {
		t.Fatal(err)
	}
	// No PTY yet: empty fingerprint, never stale.
	if d.configStaleFor(id) {
		t.Fatal("an instance without a PTY is never config-stale")
	}
	// A PTY started under 1.0.0 records the current fingerprint.
	if err := d.state.SetInstanceConfigFingerprint(id, d.instanceFingerprint(&row)); err != nil {
		t.Fatal(err)
	}
	if d.configStaleFor(id) {
		t.Fatal("a PTY started under the current version is not stale")
	}
	// The daemon re-execs as 1.0.1 (an auto-update): the stored
	// fingerprint no longer matches the rendered config.
	d.Version = "1.0.1"
	if !d.configStaleFor(id) {
		t.Fatal("a PTY started under the old version is stale after an update")
	}
	// A fresh PTY under the new version clears the staleness.
	if err := d.state.SetInstanceConfigFingerprint(id, d.instanceFingerprint(&row)); err != nil {
		t.Fatal(err)
	}
	if d.configStaleFor(id) {
		t.Fatal("a PTY restarted under the current version is not stale")
	}
}
