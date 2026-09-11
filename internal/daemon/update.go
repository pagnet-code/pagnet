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
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"pagnet/internal/transport"
)

const (
	// updateBackoff bounds the retry rate after a failed update attempt:
	// a bad release must not hammer the control plane's /download/.
	updateBackoff = time.Hour
	// updateDownloadTimeout bounds the tarball download.
	updateDownloadTimeout = 5 * time.Minute
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
	// Best-effort: also update the ON-DISK install (on Linux the rename
	// replaces even a running executable — the process keeps its inode —
	// but a read-only install dir must not break the update).
	if exe, e := os.Executable(); e == nil {
		if e := replaceFile(newBin, exe); e != nil {
			d.Log.Warn("auto-update: installed binary not replaced (re-exec uses the staged copy)", "err", e)
		}
		d.installBridges(filepath.Dir(exe))
	}
	d.Log.Info("auto-updating to " + latest + " (idle)")
	if err := syscall.Exec(newBin, os.Args, os.Environ()); err != nil {
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
// wget-install bootstrap) and extracts the binaries the daemon depends on
// into the staging dir; it returns the pagnetd path. The staging dir is
// removed on failure; on success the update re-execs and never returns (the
// next daemon start clears the leftover).
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
	if err := d.downloadRelease(tarPath); err != nil {
		cleanup()
		return "", fmt.Errorf("download: %w", err)
	}
	newBin, err := extractReleaseBinaries(tarPath, staging)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("extract: %w", err)
	}
	return newBin, nil
}

// updateStagingDir is where a release tarball is unpacked ahead of the
// re-exec. It is deterministic because performAutoUpdate reads the bridges
// back out of it to install them next to the real binary.
func (d *Daemon) updateStagingDir() string {
	return filepath.Join(d.StateDir, "update-staging")
}

// installBridges puts the MCP bridges from the staged release next to the
// daemon's own binary, which is where resolveBridge looks when they are not
// on PATH. Replacing only pagnetd would leave a self-updated worker handing
// its agents a bridge it does not have — and a runtime treats a missing
// stdio MCP server as optional, so the agent would simply come up without
// its network tools. Best-effort like the pagnetd replace: a read-only
// install dir must not fail the update. A member missing from an older
// tarball is skipped rather than fatal.
func (d *Daemon) installBridges(installDir string) {
	if installDir == "" || installDir == d.updateStagingDir() {
		return // already running from the staging copy
	}
	for _, name := range bridgeBinaries {
		src := filepath.Join(d.updateStagingDir(), name)
		if _, err := os.Stat(src); err != nil {
			d.Log.Warn("auto-update: release tarball carries no "+name+
				"; this worker needs install.sh re-run to get the bridge", "err", err)
			continue
		}
		if err := replaceFile(src, filepath.Join(installDir, name)); err != nil {
			d.Log.Warn("auto-update: "+name+" not updated (install.sh owns this dir)",
				"dir", installDir, "err", err)
		}
	}
}

// downloadRelease fetches the host's release tarball over HTTPS with the
// daemon's host credential (the same bearer it uses for the host WSS).
func (d *Daemon) downloadRelease(dst string) error {
	u := strings.TrimSuffix(d.ServerURL, "/") +
		"/download/pagnet-latest-" + runtime.GOOS + "-" + runtime.GOARCH + ".tar.gz"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.Credential)
	client := &http.Client{Timeout: updateDownloadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, werr := io.Copy(f, resp.Body)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// extractReleaseBinaries unpacks the wanted members of the release tarball
// (a flat pagnet-*.tar.gz) into dir and returns the path of the pagnetd
// binary inside it. A tarball built before the bridges shipped simply has
// fewer members — only a missing pagnetd is fatal, so an old /download/
// cannot break a worker's self-update.
func extractReleaseBinaries(tarPath, dir string) (string, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var found string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("tar: %w", err)
		}
		base := filepath.Base(hdr.Name)
		if hdr.Typeflag != tar.TypeReg || !releaseWanted(base) {
			continue
		}
		dst := filepath.Join(dir, base)
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return "", err
		}
		if err := out.Close(); err != nil {
			return "", err
		}
		if base == "pagnetd" && found == "" {
			found = dst
		}
	}
	if found == "" {
		return "", fmt.Errorf("pagnetd binary not found in tarball")
	}
	return found, nil
}

// bridgeBinaries are the binaries the daemon hands to every agent it starts:
// the worker MCP surface and the representative control surface (§9 keeps
// them in separate binaries). They are part of a release, not extras — a
// worker that updates without them silently loses its agents' network tools.
var bridgeBinaries = []string{"pagnet-mcp", "pagnet-control"}

// releaseWanted reports whether a tarball member is one the daemon needs to
// keep. pagnet and pagnet-fake-runtime are deliberately not wanted: the CLI
// may be in use in the operator's shell and the fake runtime is --debug-only,
// so a self-update must not swap either out from under them.
func releaseWanted(name string) bool {
	if name == "pagnetd" {
		return true
	}
	for _, b := range bridgeBinaries {
		if b == name {
			return true
		}
	}
	return false
}

// replaceFile copies src over dst atomically (write a sibling temp file,
// rename). On Linux the rename replaces even a RUNNING executable (the
// live process keeps its inode) — that is how the on-disk install is
// updated alongside the re-exec.
func replaceFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".pagnetd-update-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
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
