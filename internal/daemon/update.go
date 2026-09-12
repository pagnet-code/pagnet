package daemon

// Worker auto-update (P6): the control plane advertises the latest
// release version over the host connection (host.latest_version, on
// connect and with every heartbeat); when it is newer than the running
// build, the daemon downloads the release tarball and re-execs IN PLACE
// (syscall.Exec: same PID, same flags/env — systemd/service supervision
// stays intact, the process is replaced, not killed+respawned).
//
// Safety:
//   - IDLE GATE: the update runs only when the daemon has no active work
//     (no working/starting/waking instance, no in-flight turn, no live
//     PTY) — a re-exec would otherwise orphan running runtime processes.
//   - BACKOFF: after any failed attempt the daemon does not retry the
//     download for an hour (a bad release must not hammer /download/).
//   - NEVER CRASH: every failure is logged and swallowed; the daemon
//     keeps running its current build.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pagnet-code/pagnet/internal/release"
	"github.com/pagnet-code/pagnet/transport"
)

const (
	// updateBackoff bounds the retry rate after a failed update attempt:
	// a bad release must not hammer the control plane's /download/.
	updateBackoff = time.Hour
)

// shouldUpdate reports whether a daemon running `current` should update
// to `latest` (pure — the table tests pin the semantics):
//
//   - false when either is empty or the two are identical;
//   - false when `latest` is not a plain release version (an optional
//     leading "v" + dot-separated numeric components, e.g. v1.2.3 /
//     1.2.3 — the operator advertises a clean tag, never a dirty build,
//     a path, or a word);
//   - true when `current` is not a version at all (dev, a git hash, a
//     non-numeric base): a non-release build updates to any release;
//   - otherwise true iff `latest` is numerically newer per component
//     (major.minor.patch, missing = 0) — "1.10" > "1.9" (numeric, not
//     lexicographic). Pre-release/build suffixes on `current` ("-dirty",
//     "+build") compare as their base, so "1.2.3-dirty" does NOT update
//     to "1.2.3" (no loop-update).
func shouldUpdate(current, latest string) bool {
	if current == "" || latest == "" || current == latest {
		return false
	}
	if !isReleaseVersion(latest) {
		return false
	}
	base := versionBase(current)
	if !isNumericVersion(base) {
		// dev / git hash / non-numeric: treat as older than any release.
		return true
	}
	return compareNumeric(base, versionBase(latest)) < 0
}

// versionBase strips the optional leading "v" and any pre-release/build
// suffix (from the first "-" or "+") from a version string.
func versionBase(v string) string {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	return v
}

// isReleaseVersion reports whether v is a plain release version: an
// optional leading "v" followed by dot-separated numeric components.
// Suffixes ("-dirty", "+build") disqualify it: the operator advertises a
// clean release tag, never a dirty build.
func isReleaseVersion(v string) bool {
	if strings.HasPrefix(v, "v") {
		v = v[1:]
	}
	return isNumericVersion(v)
}

// isNumericVersion reports whether v is one or more dot-separated
// non-empty numeric components ("1", "1.2", "1.2.3").
func isNumericVersion(v string) bool {
	if v == "" {
		return false
	}
	for _, part := range strings.Split(v, ".") {
		if !isDigits(part) {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// compareNumeric compares two numeric version strings per dot-separated
// component (missing components = 0). Components are digit strings, so
// (length, then lexicographic) is an exact numeric comparison — no int
// overflow for absurdly long components.
func compareNumeric(a, b string) int {
	ca := strings.Split(a, ".")
	cb := strings.Split(b, ".")
	for i := 0; i < len(ca) || i < len(cb); i++ {
		x, y := "0", "0"
		if i < len(ca) {
			x = ca[i]
		}
		if i < len(cb) {
			y = cb[i]
		}
		if c := cmpDigits(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// cmpDigits compares two digit strings numerically: leading zeros are
// stripped first (semver forbids them, but a dirty local build may carry
// them), then (length, then lexicographic) is an exact numeric
// comparison — no int overflow for absurdly long components.
func cmpDigits(x, y string) int {
	x = strings.TrimLeft(x, "0")
	y = strings.TrimLeft(y, "0")
	if len(x) != len(y) {
		if len(x) < len(y) {
			return -1
		}
		return 1
	}
	return strings.Compare(x, y)
}

// handleLatestVersion applies one host.latest_version envelope: it
// records the advertised release, logs the check outcome, and hands the
// (possibly expensive) update work to a goroutine — the WSS read loop
// must never block on a download. The server re-advertises on every
// heartbeat, so a REPEATED identical advertisement logs at debug (the
// Info line is emitted when the advertised version changes — the
// greppable "update check" record of each distinct outcome).
func (d *Daemon) handleLatestVersion(env transport.Envelope) {
	var p transport.LatestVersionPayload
	if err := env.DecodePayload(&p); err != nil || p.LatestVersion == "" {
		return
	}
	d.updMu.Lock()
	changed := d.latestVersion != p.LatestVersion
	d.latestVersion = p.LatestVersion
	d.updMu.Unlock()
	avail := shouldUpdate(d.Version, p.LatestVersion)
	if changed {
		d.Log.Info("update check", "latest", p.LatestVersion,
			"current", d.Version, "updateAvailable", avail)
	} else {
		d.Log.Debug("update check", "latest", p.LatestVersion,
			"current", d.Version, "updateAvailable", avail)
	}
	if avail {
		d.triggerAutoUpdate()
	}
}

// triggerAutoUpdate starts the update flow when it is enabled, a newer
// version is advertised, no update is in flight, and the 1h failure
// backoff has elapsed. Non-blocking: the work runs on its own goroutine.
func (d *Daemon) triggerAutoUpdate() {
	d.updMu.Lock()
	if !d.AutoUpdate {
		d.updMu.Unlock()
		return
	}
	latest := d.latestVersion
	if latest == "" || !shouldUpdate(d.Version, latest) {
		d.updMu.Unlock()
		return
	}
	if d.updating {
		d.updMu.Unlock()
		return
	}
	if !d.lastAttempt.IsZero() && time.Since(d.lastAttempt) < updateBackoff {
		d.updMu.Unlock()
		return
	}
	d.updating = true
	d.updMu.Unlock()
	go d.performAutoUpdate(latest)
}

// performAutoUpdate runs the update flow for latest:
//
//  1. IDLE GATE (pre): no active work, or defer to the next heartbeat
//     (no backoff — nothing was downloaded);
//  2. download + extract the release tarball (any failure: 1h backoff);
//  3. IDLE GATE (final): a turn or PTY may have started during the
//     download — defer (the download was consumed: 1h backoff);
//  4. best-effort replace the installed binary, then re-exec in place
//     (a successful exec never returns — the process image is replaced,
//     and the new process reports the new version, so no loop).
func (d *Daemon) performAutoUpdate(latest string) {
	defer func() {
		d.updMu.Lock()
		d.updating = false
		d.updMu.Unlock()
	}()
	// IDLE GATE (pre): a re-exec replaces this process; any running
	// runtime process (turn subprocess, PTY) would be orphaned from the
	// daemon's view. Defer to the next heartbeat — no backoff, nothing
	// was downloaded.
	if n := d.activeWorkCount(); n > 0 {
		d.Log.Info("deferring auto-update to "+latest+": worker not idle", "active", n)
		return
	}
	d.updMu.Lock()
	d.lastAttempt = time.Now()
	d.updMu.Unlock()
	newBin, err := d.downloadAndExtract()
	if err != nil {
		d.Log.Error("auto-update failed: "+err.Error()+"; backing off 1h", "latest", latest)
		return
	}
	// IDLE GATE (final): the download took seconds; a turn or PTY may
	// have started in that window. The re-exec must not orphan it.
	if n := d.activeWorkCount(); n > 0 {
		d.Log.Info("deferring auto-update to "+latest+": worker not idle", "active", n)
		return
	}
	// ATOMIC SELF-REPLACE: the daemon replaces its OWN executable — the
	// staged binary is written into the self path's directory and
	// renamed over it (same directory: the rename is atomic, and on
	// Linux it replaces even a running executable, the live process
	// keeps its inode). Best-effort: a read-only install dir must not
	// break the update — the re-exec then uses the staged copy, and the
	// on-disk install keeps the old build until a writable update.
	execPath := d.selfExe
	if err := release.ReplaceBinary(newBin, d.selfExe); err != nil {
		d.Log.Warn("auto-update: installed binary not replaced (re-exec uses the staged copy)", "err", err)
		execPath = newBin
	}
	d.Log.Info("auto-updating to " + latest + " (idle)")
	if err := syscall.Exec(execPath, os.Args, os.Environ()); err != nil {
		// Exec only fails on a broken binary/OS error: log + back off,
		// the daemon keeps running its current build.
		d.Log.Error("auto-update failed: exec: "+err.Error()+"; backing off 1h", "latest", latest)
	}
}

// activeWorkCount is the idle-gate metric: the number of active work
// units — in-flight turns, live PTY sessions, and instances in a
// working/starting/waking state. Zero = the daemon is idle enough to
// re-exec without orphaning a runtime process.
func (d *Daemon) activeWorkCount() int {
	n := 0
	d.turnMu.Lock()
	n += len(d.activeTurns)
	d.turnMu.Unlock()
	n += d.terminal.activeCount()
	insts, err := d.state.ListInstances()
	if err == nil {
		for _, i := range insts {
			switch i.Status {
			case "working", "starting", "waking":
				n++
			}
		}
	}
	return n
}

// downloadAndExtract fetches the host's release tarball from the
// control plane's /download/ endpoint (the existing release-serving
// handler, same pagnet-latest-<os>-<arch>.tar.gz convention as the
// wget-install bootstrap) and extracts the unified pagnet binary into
// the staging dir; it returns the staged binary's path. The staging dir
// is removed on failure; on success the update re-execs and never
// returns (the next daemon start clears the leftover).
func (d *Daemon) downloadAndExtract() (string, error) {
	staging := d.updateStagingDir()
	if err := os.RemoveAll(staging); err != nil {
		return "", fmt.Errorf("clear staging dir: %w", err)
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return "", fmt.Errorf("create staging dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(staging) }
	tarPath := filepath.Join(staging, "release.tar.gz")
	if err := release.Download(d.ServerURL, tarPath); err != nil {
		cleanup()
		return "", fmt.Errorf("download: %w", err)
	}
	newBin, err := release.ExtractPagnet(tarPath, staging)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("extract: %w", err)
	}
	return newBin, nil
}

// updateStagingDir is where the release tarball is unpacked ahead of the
// re-exec.
func (d *Daemon) updateStagingDir() string {
	return filepath.Join(d.StateDir, "update-staging")
}

// instanceFingerprint is the fingerprint of the runtime-injected config
// (P6 configStale): the daemon version plus the MCP bridge config and
// identity env the daemon renders for this instance. It changes when a
// re-exec'd daemon (an auto-update) would inject a different bridge into
// a runtime process, so a PTY started under the old build compares
// unequal to the current one.
func (d *Daemon) instanceFingerprint(row *InstanceRow) string {
	h := sha256.New()
	for _, part := range []string{
		d.Version,
		d.mcpConfig(row),
		"PAGNET_INSTANCE_ID=" + row.InstanceID,
		"PAGNET_AGENT_NAME=" + row.AgentName,
		"PAGNET_NETWORK_ID=" + row.NetworkID,
	} {
		_, _ = io.WriteString(h, part)
		_, _ = io.WriteString(h, "\x00")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// configStaleFor reports whether the instance's last PTY ran under a
// different runtime-injected config than the daemon renders NOW (P6):
// the main trigger is an auto-update re-exec — a PTY (live or hibernated)
// started under the old build still runs the old bridge. An empty stored
// fingerprint (the instance never had a PTY) is never stale.
func (d *Daemon) configStaleFor(instanceID string) bool {
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok || row.ConfigFingerprint == "" {
		return false
	}
	return row.ConfigFingerprint != d.instanceFingerprint(row)
}
