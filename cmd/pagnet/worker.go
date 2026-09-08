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
// Subsequent runs:
//
//	pagnet worker
//
// Then join a network from the terminal (run from INSIDE this directory —
// the CLI picks up this worker's state automatically):
//
//	pagnet run . -n <network> -r qwen-code
//
// --user-token stores a validated user/admin bearer in the worker state,
// so `pagnet run .` and friends work from this directory without
// $PAGNET_TOKEN (REST is user-scoped; the host credential alone gets 401).

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
	var name, token, userToken, stateDir string
	cmd := &cobra.Command{
		Use:   "worker",
		Short: "Run a single-directory worker here (this directory is its only workspace)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
				return errors.New("no control plane URL in state; run with --server <url>")
			}
			if userToken != "" {
				// Validate against /auth/me (never store an unverified
				// bearer) and persist it in THIS worker's state so
				// terminal commands run from this directory are
				// authenticated by default.
				base := strings.TrimSuffix(cfg.ServerURL, "/") + "/"
				ok, err := bearerMe(&http.Client{Timeout: 30 * time.Second}, base, userToken)
				if err != nil {
					return fmt.Errorf("validate --user-token: %w", err)
				}
				if !ok {
					return errors.New("--user-token was rejected by the server")
				}
				if err := saveUserToken(stateDir, cfg.ServerURL, userToken); err != nil {
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
			}, log)
			if err != nil {
				return err
			}
			defer d.Close()

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			log.Info("pagnet worker",
				"dir", abs, "server", cfg.ServerURL, "host", cfg.HostID)
			fmt.Fprintf(os.Stderr,
				"worker running in %s — Ctrl+C stops it\n"+
					"join a network from the terminal: pagnet run . -n <network> -r <runtime>\n",
				abs)
			if err := d.Run(ctx); err != nil && ctx.Err() == nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "host name (default: machine hostname)")
	cmd.Flags().StringVar(&token, "token", "", "one-time enrollment token (first run only)")
	cmd.Flags().StringVar(&userToken, "user-token", "", "user/admin bearer validated and stored for `pagnet run .` from this directory")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "worker state dir (default ~/.pagnet/workers/<dir-hash>)")
	return cmd
}

// dirHash derives a stable, filesystem-safe worker state dir slug from an
// absolute path (first 12 hex chars of sha256).
func dirHash(abs string) string {
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])[:12]
}
