package main

// `pagnet worker` — the single-directory worker (the "claude-in-a-folder"
// shape): run it inside any directory and that directory becomes the
// worker's ONLY workspace. State is kept per directory under
// ~/.pagnet/workers/<hash>, so several directories on the same machine
// are several independent workers — each sees only its own folder.
//
// First run (needs an enrollment token from the web UI, Hosts → Add a
// worker):
//
//	pagnet worker --server http://controlplane:18080 --token <token> --user-token <admin-token>
//
// or with env vars (handy for scripts / provisioning):
//
//	PAGNET_SERVER=http://controlplane:18080 PAGNET_ENROLL_TOKEN=<token> PAGNET_TOKEN=<admin-token> pagnet worker
//
// Subsequent runs:
//
//	pagnet worker
//
// Then join a network from the terminal (run from INSIDE this directory —
// the CLI picks up this worker's state automatically):
//
//	pagnet run . -n <network> -r qwen-code
//
// --user-token (or $PAGNET_TOKEN) stores a validated user/admin bearer in
// the worker state, so `pagnet run .` and friends work from this
// directory without $PAGNET_TOKEN (REST is user-scoped; the host
// credential alone gets 401).
//
// --no-scan turns off automatic git-repo discovery (persisted in the
// worker state; PAGNET_SCAN_WORKSPACES=0 does it for one run). The
// directory itself is still the worker's workspace either way.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"pagnet/internal/config"
	"pagnet/internal/daemon"
)

func workerCmd() *cobra.Command {
	var name, token, userTok, stateDir string
	var noScan, scan bool
	cmd := &cobra.Command{
		Use:   "worker",
		Short: "Run a single-directory worker here (this directory is its only workspace)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if noScan && scan {
				return errors.New("--no-scan and --scan are mutually exclusive")
			}
			abs, err := filepath.Abs(".")
			if err != nil {
				return err
			}
			if info, err := os.Stat(abs); err != nil || !info.IsDir() {
				return fmt.Errorf("%s is not a directory", abs)
			}
			if stateDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				stateDir = filepath.Join(home, ".pagnet", "workers", dirHash(abs))
			}

			cfg, err := config.LoadDaemon(stateDir)
			if err != nil {
				return err
			}
			if cfg.Credential == "" || cfg.HostID == "" {
				// First run in this directory: enroll this directory as
				// its own worker (root = this directory).
				if err := doEnroll(serverURL, token, name, []string{abs}, stateDir); err != nil {
					return err
				}
				cfg, err = config.LoadDaemon(stateDir)
				if err != nil {
					return err
				}
			}
			if cfg.ServerURL == "" {
				return errors.New("no control plane URL in state; run with --server <url> (or set $PAGNET_SERVER)")
			}
			// Explicit flags persist to the worker state so the choice
			// survives re-runs; without either, the stored value and
			// PAGNET_SCAN_WORKSPACES (already folded into cfg.NoScan)
			// apply.
			noScanEnabled := cfg.NoScan
			switch {
			case noScan:
				noScanEnabled = true
				if err := mergeConfigFile(stateDir, map[string]any{"noScan": true}); err != nil {
					return err
				}
			case scan:
				noScanEnabled = false
				if err := mergeConfigFile(stateDir, map[string]any{"noScan": false}); err != nil {
					return err
				}
			}
			if userTok == "" {
				userTok = userToken // root --token / $PAGNET_TOKEN
			}
			if userTok != "" {
				// Validate against /auth/me (never store an unverified
				// bearer) and persist it in THIS worker's state so
				// terminal commands run from this directory are
				// authenticated by default.
				base := strings.TrimSuffix(cfg.ServerURL, "/") + "/"
				ok, err := bearerMe(&http.Client{Timeout: 30 * time.Second}, base, userTok)
				if err != nil {
					return fmt.Errorf("validate --user-token: %w", err)
				}
				if !ok {
					return errors.New("--user-token was rejected by the server")
				}
				if err := saveUserToken(stateDir, cfg.ServerURL, userTok); err != nil {
					return err
				}
			}
			roots := cfg.AllowedRoots
			if len(roots) == 0 {
				roots = []string{abs}
			}

			log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			d, err := daemon.New(daemon.Config{
				ServerURL:        cfg.ServerURL,
				Credential:       cfg.Credential,
				HostID:           cfg.HostID,
				StateDir:         stateDir,
				AllowedRoots:     roots,
				Version:          "pagnet-worker/dev",
				Heartbeat:        cfg.HeartbeatInterval,
				RuntimeEnv:       cfg.RuntimeEnv,
				PrimaryWorkspace: abs,
				NoScan:           noScanEnabled,
			}, log)
			if err != nil {
				return err
			}
			defer d.Close()

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			log.Info("pagnet worker",
				"dir", abs, "server", cfg.ServerURL, "host", cfg.HostID, "noScan", noScanEnabled)
			fmt.Fprintf(os.Stderr,
				"worker running in %s — it connects OUT to %s (no inbound ports needed)\n"+
					"this is a long-lived daemon: leave it running while agents work here (Ctrl+C stops it)\n"+
					"find it in the web console → Hosts page (status: online)\n"+
					"launch agents on it from the web console, or from another terminal in this directory:\n"+
					"  pagnet run . -n <network> -r <runtime>\n",
				abs, cfg.ServerURL)
			if err := d.Run(ctx); err != nil && ctx.Err() == nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "host name (default: machine hostname)")
	cmd.Flags().StringVar(&token, "token", envOrDefault("PAGNET_ENROLL_TOKEN", ""), "one-time enrollment token, first run only ($PAGNET_ENROLL_TOKEN)")
	cmd.Flags().StringVar(&userTok, "user-token", "", "user/admin bearer validated and stored for \"pagnet run .\" from this directory ($PAGNET_TOKEN)")
	cmd.Flags().BoolVar(&noScan, "no-scan", false, "don't auto-discover git repos in the allowed roots (persisted; add workspaces explicitly)")
	cmd.Flags().BoolVar(&scan, "scan", false, "re-enable automatic git-repo discovery (persisted; overrides a stored --no-scan)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "worker state dir (default ~/.pagnet/workers/<dir-hash>)")
	return cmd
}

// dirHash derives a stable, filesystem-safe worker state dir slug from an
// absolute path (first 12 hex chars of sha256).
func dirHash(abs string) string {
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])[:12]
}
