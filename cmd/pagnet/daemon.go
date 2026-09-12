// The unified daemon entrypoint (packaging migration, step 2):
//
//	pagnet daemon — the host daemon in the FOREGROUND (containers,
//	                supervisors; the pagnetd flag set, same behavior)
//	pagnet -d     — the same daemon DETACHED from the terminal: re-exec
//	                of `pagnet daemon`, stdio appended to
//	                <state-dir>/pagnetd.log, prints the pid and exits
//
// The daemon itself is the shared internal/daemon implementation — the
// same code path `pagnet worker` runs, with the machine-wide state dir
// (~/.pagnet by default) instead of a per-directory one. The old
// `pagnetd` binary keeps building and behaves identically until the
// migration's later steps remove it.

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"pagnet/internal/config"
	"pagnet/internal/daemon"
)

// The daemon flag values. The same flag set is registered on the ROOT
// command (local flags, so `pagnet -d --state-dir ...` parses) and on
// the `daemon` subcommand; both write these variables, and only one
// command runs per invocation.
var (
	daemonStateDir     string
	daemonLogLevel     string
	daemonDebug        bool
	daemonNoAutoUpdate bool
	// detach is the root-level -d/--detach flag (see runDetach).
	detach bool
)

// daemonCmd is `pagnet daemon`: the host daemon in the foreground.
func daemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the pagnet host daemon in the foreground (top-level -d detaches it)",
		Args:  cobra.NoArgs,
		RunE:  runDaemon,
	}
	registerDaemonFlags(cmd)
	return cmd
}

// registerDaemonFlags binds the pagnetd flag set to cmd.
func registerDaemonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&daemonStateDir, "state-dir", "", "daemon state dir (default ~/.pagnet)")
	cmd.Flags().StringVar(&daemonLogLevel, "log-level", envOrDefault("PAGNET_LOG_LEVEL", "info"),
		"log level: debug|info|warn|error (default from PAGNET_LOG_LEVEL, else info)")
	// --debug enables development/test-only behavior (registers the
	// deterministic fake runtime). It ORs with PAGNET_DEBUG / the state
	// file's `debug:` field. Default off: a production daemon never
	// offers the fake runtime.
	cmd.Flags().BoolVar(&daemonDebug, "debug", false,
		"enable development/test-only behavior (register the fake runtime; also PAGNET_DEBUG=1 or state-file debug:)")
	// --no-auto-update disables worker self-update (P6). Auto-update is
	// ON by default: the daemon re-execs itself (same PID) when the
	// control plane advertises a newer release and the worker is idle.
	// It ANDs with PAGNET_AUTO_UPDATE / the state file's `autoUpdate:`.
	cmd.Flags().BoolVar(&daemonNoAutoUpdate, "no-auto-update", false,
		"disable worker self-update (default on; also PAGNET_AUTO_UPDATE=0 or state-file autoUpdate: false)")
}

// runDaemon is the `pagnet daemon` foreground body — the same init path
// as pagnetd: state-dir config, daemon.New, signals, Run.
func runDaemon(cmd *cobra.Command, _ []string) error {
	var level slog.Level
	switch daemonLogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.LoadDaemon(daemonStateDir)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.ServerURL == "" {
		return errors.New("no control plane URL; run `pagnet enroll --server <url>` first")
	}

	d, err := daemon.New(daemon.Config{
		ServerURL:    cfg.ServerURL,
		Credential:   cfg.Credential,
		HostID:       cfg.HostID,
		StateDir:     cfg.StateDir,
		AllowedRoots: cfg.AllowedRoots,
		Version:      version,
		Heartbeat:    cfg.HeartbeatInterval,
		RuntimeEnv:   cfg.RuntimeEnv,
		NoScan:       cfg.NoScan,
		// The --debug flag ORs with PAGNET_DEBUG / the state file's
		// debug: field (both loaded into cfg.Debug).
		Debug: daemonDebug || cfg.Debug,
		// The --no-auto-update flag ANDs with PAGNET_AUTO_UPDATE / the
		// state file's autoUpdate: field (opt-out; default on, P6).
		AutoUpdate: cfg.AutoUpdate && !daemonNoAutoUpdate,
	}, log)
	if err != nil {
		return fmt.Errorf("init daemon: %w", err)
	}
	defer d.Close()

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("pagnet daemon starting",
		"server", cfg.ServerURL, "state_dir", cfg.StateDir,
		"allowed_roots", cfg.AllowedRoots)
	if err := d.Run(ctx); err != nil {
		return err
	}
	return nil
}

// runDetach implements `pagnet -d`: re-exec this binary as
// `pagnet daemon <flags>` in a new session, stdio appended to
// <state-dir>/pagnetd.log, and print the child pid. -d is a launcher
// convenience, not a second runtime mode: the child runs the identical
// foreground `daemon` path.
func runDetach(cmd *cobra.Command) error {
	// The log path needs the state dir BEFORE the re-exec: the flag
	// value when given, else LoadDaemon's default (~/.pagnet).
	stateDir := daemonStateDir
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		stateDir = filepath.Join(home, ".pagnet")
	}
	changed := map[string]bool{
		"state-dir":      cmd.Flags().Changed("state-dir"),
		"log-level":      cmd.Flags().Changed("log-level"),
		"debug":          cmd.Flags().Changed("debug"),
		"no-auto-update": cmd.Flags().Changed("no-auto-update"),
	}
	return daemonizeSelf(stateDir, detachArgs(os.Args[1:], changed))
}

// detachArgs builds the child argv for `pagnet -d`: the `daemon`
// subcommand plus only the daemon flags the user explicitly set
// (changed). The -d/--detach flag itself is stripped, and anything that
// is not a daemon flag (--server, --token, unknown args) is dropped —
// the child is `daemon`, which knows only the daemon flag set.
func detachArgs(osArgs []string, changed map[string]bool) []string {
	valueFlags := map[string]bool{"state-dir": true, "log-level": true}
	boolFlags := map[string]bool{"debug": true, "no-auto-update": true}
	args := []string{"daemon"}
	for i := 0; i < len(osArgs); i++ {
		a := osArgs[i]
		name, hasVal := a, false
		if strings.HasPrefix(a, "--") {
			if eq := strings.IndexByte(a, '='); eq > 0 {
				name, hasVal = a[:eq], true
			}
		}
		name = strings.TrimLeft(name, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if name == "d" || name == "detach" {
			continue // the detach flag itself
		}
		switch {
		case valueFlags[name] && changed[name]:
			if hasVal {
				args = append(args, a)
			} else if i+1 < len(osArgs) {
				args = append(args, a, osArgs[i+1])
				i++
			}
		case boolFlags[name] && changed[name]:
			args = append(args, a)
		}
	}
	return args
}

// daemonizeSelf re-executes the same binary (os.Executable,
// canonicalized; os.Args[0] only when resolution fails) with args in a
// new session (Setsid), stdio appended to <stateDir>/pagnetd.log, and
// exits. The child is reparented to init/launchd and keeps running
// after the terminal closes.
func daemonizeSelf(stateDir string, args []string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	logPath := filepath.Join(stateDir, "pagnetd.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = os.Args[0]
	} else if canonical, err := filepath.EvalSymlinks(exe); err == nil {
		exe = canonical
	}
	child := exec.Command(exe, args...)
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	child.Stdin = nil
	child.Stdout = f
	child.Stderr = f
	child.Env = os.Environ()
	if err := child.Start(); err != nil {
		f.Close()
		return err
	}
	pid := child.Process.Pid
	// The child owns its session; the parent must not wait on it.
	_ = child.Process.Release()
	f.Close()
	fmt.Printf("pagnet daemon started (pid %d) — log: %s\n", pid, logPath)
	return nil
}
