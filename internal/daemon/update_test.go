package daemon

// P6 worker auto-update: the pure version-comparison gate (shouldUpdate)
// plus the daemon-side gates (idle gate, single-flight, 1h backoff) and
// the configStale fingerprint — all testable without a network.

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/domain"
	"github.com/pagnet-code/pagnet/internal/release"
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

// --- one-binary release format: validation + atomic self-replace -----------
// The release tarball carries exactly ONE executable (pagnet — CLI,
// daemon and MCP bridges; the daemon self-spawns its bridges from its own
// executable). An update that cannot find it must fail cleanly, and the
// replace of the daemon's own binary must never leave a partial file.

// writeReleaseTarball builds a flat pagnet-*.tar.gz with the given
// member names (each a tiny shell script) in dir.
func writeReleaseTarball(t *testing.T, dir string, names ...string) string {
	t.Helper()
	path := filepath.Join(dir, "release.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, n := range names {
		body := []byte("#!/bin/sh\n# " + n + "\n")
		hdr := &tar.Header{Name: n, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractPagnet(t *testing.T) {
	t.Run("new-format tarball extracts pagnet, leaves the rest", func(t *testing.T) {
		tarPath := writeReleaseTarball(t, t.TempDir(),
			"pagnet", "LICENSE", "README.md", "pagnet-fake-runtime")
		out := t.TempDir()
		got, err := release.ExtractPagnet(tarPath, out)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if want := filepath.Join(out, release.BinaryName); got != want {
			t.Fatalf("returned %q, want %q", got, want)
		}
		st, err := os.Stat(got)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o100 == 0 {
			t.Fatalf("pagnet is not executable: %v", st.Mode())
		}
		// Non-binary members and the fake runtime are not update inputs.
		for _, n := range []string{"LICENSE", "README.md", "pagnet-fake-runtime"} {
			if _, err := os.Stat(filepath.Join(out, n)); err == nil {
				t.Fatalf("%s must not be extracted by an update", n)
			}
		}
	})

	t.Run("a pre-unified tarball still updates", func(t *testing.T) {
		// Old-format tarballs carried pagnet alongside pagnetd and the
		// bridges: a new daemon updating from an old /download/ must work.
		tarPath := writeReleaseTarball(t, t.TempDir(),
			"pagnet", "pagnetd", "pagnet-mcp", "pagnet-control")
		if _, err := release.ExtractPagnet(tarPath, t.TempDir()); err != nil {
			t.Fatalf("old tarball must not break the update: %v", err)
		}
	})

	t.Run("no pagnet member is fatal", func(t *testing.T) {
		// A foreign or broken artifact: the update must fail cleanly,
		// never fabricate a binary.
		tarPath := writeReleaseTarball(t, t.TempDir(), "pagnetd", "pagnet-mcp")
		if _, err := release.ExtractPagnet(tarPath, t.TempDir()); !errors.Is(err, release.ErrNoBinary) {
			t.Fatalf("err = %v, want ErrNoBinary", err)
		}
	})
}

// TestPerformAutoUpdate_BadTarballGraceful: a release tarball without the
// unified binary (e.g. the server still serves a pre-unified artifact)
// must fail the update GRACEFULLY — backoff recorded, single-flight flag
// released, the daemon keeps running its current build. No crash, no
// tight retry: the 1h backoff bounds the next attempt (the WSS read loop
// is never blocked, the failure is logged and swallowed).
func TestPerformAutoUpdate_BadTarballGraceful(t *testing.T) {
	dir := t.TempDir()
	writeReleaseTarball(t, dir, "pagnetd", "pagnet-mcp") // no pagnet member
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/download/"+release.TarballName(runtime.GOOS, runtime.GOARCH) {
			http.ServeFile(w, r, filepath.Join(dir, "release.tar.gz"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)

	d := newTestDaemon(t)
	d.Version = "1.0.0"
	d.ServerURL = ts.URL
	d.performAutoUpdate("1.0.1") // must not panic or leave the daemon wedged
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
	// The backoff gate now blocks an immediate retry (no retry storm):
	// a newer version is still advertised, yet no second attempt starts.
	d.updMu.Lock()
	d.latestVersion = "1.0.1"
	d.updMu.Unlock()
	d.triggerAutoUpdate()
	d.updMu.Lock()
	upd = d.updating
	d.updMu.Unlock()
	if upd {
		t.Fatal("a second attempt must not start inside the backoff window")
	}
}

// TestReplaceBinary_Atomic: the replace stages in the TARGET's own
// directory and renames over it — the target ends with the new content
// and the executable bit, and no staging file is left behind (a crash
// mid-write leaves at most an orphan temp file, never a partial target).
func TestReplaceBinary_Atomic(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged-pagnet")
	if err := os.WriteFile(src, []byte("new binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "pagnet")
	if err := os.WriteFile(dst, []byte("old binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := release.ReplaceBinary(src, dst); err != nil {
		t.Fatalf("replace: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new binary" {
		t.Fatalf("target content = %q, want the new binary", got)
	}
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("target mode = %v, want 0755", st.Mode())
	}
	// Only src + dst remain: no orphan staging file in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("dir has %v, want exactly [pagnet staged-pagnet]", names)
	}
}

// TestReplaceBinary_StagesInTargetDir: the staging file lives in the
// target's directory (same filesystem → atomic rename): a read-only
// target dir fails at staging, before anything is written, and the
// target is left untouched.
func TestReplaceBinary_StagesInTargetDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	src := filepath.Join(t.TempDir(), "staged-pagnet")
	if err := os.WriteFile(src, []byte("new binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	ro := t.TempDir()
	dst := filepath.Join(ro, "pagnet")
	if err := os.WriteFile(dst, []byte("old binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	if err := release.ReplaceBinary(src, dst); err == nil {
		t.Fatal("want a failure when the target dir is read-only (staging happens there)")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old binary" {
		t.Fatalf("target content = %q, want the old binary (a failed replace must not touch it)", got)
	}
}
