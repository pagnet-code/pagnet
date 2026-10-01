// `pagnet update` — the manual self-update (packaging migration, step 6):
// download the latest release for this platform from the control plane's
// public /download/, validate that it carries the unified pagnet binary,
// and atomically replace THIS binary on disk (stage in the same directory
// + rename — never a partial file).
//
// The command does NOT restart the daemon: a running daemon keeps the old
// build in memory, so the command prints the restart steps instead (the
// daemon's own auto-update covers the hands-off path, and this command is
// the deliberate operator operation for hosts where it is disabled).

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/pagnet-code/pagnet/internal/localipc"
	"github.com/pagnet-code/pagnet/internal/release"
)

func updateCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the pagnet binary to the latest release",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUpdate(cmd, serverURL, stateDir)
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "",
		"daemon state dir (default ~/.pagnet; stored control plane URL + running-daemon detection)")
	return cmd
}

// runUpdate is the `pagnet update` body: replace the SELF binary (the
// pagnet executable this command runs from) with the latest release,
// then print how to restart the daemon so the new version takes effect.
func runUpdate(cmd *cobra.Command, serverURL, stateDir string) error {
	if runtime.GOOS == "windows" {
		return errors.New("Windows self-update is not supported yet; close pagnet and replace pagnet.exe manually, or rebuild from source")
	}
	// Server precedence: --server > $PAGNET_SERVER > stored account config
	// > build default (resolveServerURL; the param carries the --server flag).
	cfg, _, _ := loadAccountConfig(machineStateDir(stateDir))
	serverURL = resolveServerURL(cfg)
	if serverURL == "" {
		return errors.New("no control plane URL — set --server / $PAGNET_SERVER, or run 'pagnet enroll --server <url>' first")
	}
	// Resolve SELF explicitly (canonicalized): a bare name would make the
	// replace a PATH guess, and a symlinked install must update the real
	// file.
	self, err := os.Executable()
	if err != nil || self == "" {
		return fmt.Errorf("cannot resolve own executable: %w", err)
	}
	if canonical, err := filepath.EvalSymlinks(self); err == nil {
		self = canonical
	}
	fmt.Fprintf(cmd.OutOrStdout(), "→ downloading pagnet (%s/%s) from %s\n",
		runtime.GOOS, runtime.GOARCH, strings.TrimSuffix(serverURL, "/"))
	if err := updateBinaryAt(serverURL, self); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "→ updated %s", self)
	if nv := newVersionAt(self); nv != "" {
		fmt.Fprintf(cmd.OutOrStdout(), " (pagnet %s → %s)", version, nv)
	}
	fmt.Fprintln(cmd.OutOrStdout())

	// Restart hint: a running daemon keeps the old build in memory until
	// it is restarted (the state dir is unchanged, so enrollment and
	// sessions survive).
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		stateDir = filepath.Join(home, ".pagnet")
	}
	if daemonRunning(stateDir) {
		fmt.Fprintln(cmd.OutOrStdout(), "The installed binary is updated. Your running daemon and sessions continue using the existing process.")
		fmt.Fprintln(cmd.OutOrStdout(), "If automatic updates are enabled, the daemon upgrades when the server advertises the release and all active turns, terminals and runtime processes have finished or hibernated.")
		fmt.Fprintln(cmd.OutOrStdout(), "For a manual restart, wait for that safe idle state, then stop only this daemon gracefully: Ctrl+C for foreground serve; for a detached daemon, SIGTERM to its verified PID or its process manager.")
		fmt.Fprintln(cmd.OutOrStdout(), "Start it again with its original command, state directory, account and server options. Keep the existing state directory.")
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "No daemon is running. Start with pagnet serve (foreground) or pagnet -d (background), using your existing state directory, account and server options.")
	}
	return nil
}

// updateBinaryAt downloads the latest release for this platform from
// serverURL's public /download/, verifying the signed release manifest
// (Ed25519 signature against the pinned key + the tarball's sha256),
// validates that it carries the unified pagnet binary, and atomically
// replaces the binary at path. A failure (bad server, untrusted manifest,
// wrong artifact) leaves the installed binary untouched.
func updateBinaryAt(serverURL, path string) error {
	tmp, err := os.MkdirTemp("", "pagnet-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	tarPath := filepath.Join(tmp, "release.tar.gz")
	if err := release.DownloadLatestVerified(serverURL, tarPath, insecureRemoteHTTP); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	newBin, err := release.ExtractPagnet(tarPath, tmp)
	if err != nil {
		return err
	}
	return release.ReplaceBinary(newBin, path)
}

// newVersionAt runs the freshly replaced binary's `version` subcommand
// (best-effort: a failure just omits the version from the output).
func newVersionAt(path string) string {
	out, err := exec.Command(path, "version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// daemonRunning probes the machine-wide daemon's bridge socket with the
// same liveness check the daemon itself uses against a double start: a
// LIVE daemon answers the auth probe; a stale socket file (crashed
// daemon) has no listener and does not.
func daemonRunning(stateDir string) bool {
	sock, err := localipc.BridgeSocketPath(stateDir)
	if err != nil {
		return false
	}
	probe, err := net.Dial("unix", sock)
	if err != nil {
		return false
	}
	defer probe.Close()
	_ = probe.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = probe.Write([]byte(`{"type":"auth","instanceId":"pagnet-update-probe","networkId":""}` + "\n"))
	buf := make([]byte, 1)
	_, rerr := probe.Read(buf)
	return rerr == nil
}
