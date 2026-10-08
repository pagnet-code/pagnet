// The unified daemon entrypoint (packaging migration, step 2):
//
//	pagnet serve — the host daemon in the FOREGROUND (containers,
//	               supervisors)
//	pagnet -d    — the same daemon DETACHED from the terminal: re-exec
//	               of `pagnet serve`, stdio appended to
//	               <state-dir>/pagnetd.log, prints the pid and exits
//
// The daemon itself is the shared internal/daemon implementation — the
// same code path `pagnet worker` runs, with the machine-wide state dir
// (~/.pagnet by default) instead of a per-directory one. The unified
// binary is the only daemon entrypoint (the separate daemon binary is
// gone; pre-unified installs migrate via install.sh / `pagnet update`).

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pagnet-code/pagnet/internal/netpolicy"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/fabric/telemetry"
	"github.com/pagnet-code/pagnet/internal/config"
	"github.com/pagnet-code/pagnet/internal/daemon"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	otel "github.com/pagnet-code/pagnet/internal/telemetry"
)

// The daemon flag values. The same flag set is registered on the ROOT
// command (local flags, so `pagnet -d --state-dir ...` parses) and on
// the `serve` subcommand; both write these variables, and only one
// command runs per invocation.
var (
	daemonLocal          bool
	daemonLocalDirectory string
	daemonStateDir       string
	daemonLogLevel       string
	daemonDebug          bool
	daemonNoAutoUpdate   bool
	// detach is the root-level -d/--detach flag (see runDetach).
	detach bool
)

// daemonCmd is `pagnet serve`: the host daemon in the foreground.
func daemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the pagnet local service in the foreground (top-level -d starts it detached)",
		Args:  cobra.NoArgs,
		RunE:  runDaemon,
	}
	registerDaemonFlags(cmd)
	return cmd
}

// registerDaemonFlags binds the daemon flag set to cmd.
func registerDaemonFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&daemonLocal, "local", false, "serve an explicitly initialized local Fabric node without cloud enrollment")
	cmd.Flags().StringVar(&daemonLocalDirectory, "local-dir", "", "private local installation directory (with --local)")
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

// needsEnroll reports whether the host needs (re-)enrollment before the
// daemon can start: no stored host credential + identity yet. An
// already-enrolled host (credential + hostId present) starts WITHOUT a user
// login — a `pagnet logout` (which removes only the user credential) must
// not break an enrolled host.
func needsEnroll(cfg config.Daemon) bool {
	return cfg.Credential == "" || cfg.HostID == ""
}

// runDaemon is the `pagnet serve` foreground body: state-dir config,
// daemon.New, signals, Run.
func runDaemon(cmd *cobra.Command, _ []string) error {
	if daemonLocal {
		for _, name := range []string{"state-dir", "debug", "server", "account", "token"} {
			if cmd.Flags().Changed(name) {
				return fmt.Errorf("--%s does not apply to local Fabric serve", name)
			}
		}
		return runLocalFabricDaemon(cmd, daemonLocalDirectory)
	}
	if cmd.Flags().Changed("local-dir") {
		return fmt.Errorf("--local-dir requires --local")
	}

	if err := hostPlatformError(); err != nil {
		return err
	}
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

	root := machineStateDir(daemonStateDir)
	cfg, account, err := loadAccountConfig(root)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	// First run on this machine: the host is NOT enrolled (no credential +
	// host id). Connect it in the FOREGROUND — the token-first paste must
	// run before the daemon starts. An already-enrolled host starts WITHOUT
	// a user login (logout must not break an enrolled host).
	//
	// firstRun is the definitive first-run event: host registration happens
	// exactly once, so it is the trigger for the console handoff (below).
	firstRun := needsEnroll(cfg)
	if firstRun {
		if err := enrollHostForeground(root, account, "", nil, "", ""); err != nil {
			return err
		}
		cfg, _, err = loadAccountConfig(root)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
	}
	// §3 Safe control-plane switching: the host credential in the account
	// config is tied to the serverUrl in the SAME file. If the resolved
	// server differs from the stored one, the stored credential is stale
	// (for the old server) and must NOT be sent to the new server.
	if err := ensureServerSwitch(root, account, &cfg); err != nil {
		return err
	}
	server := resolveServerURL(cfg)
	if server == "" {
		return errors.New("no control plane URL — set --server / $PAGNET_SERVER, or run 'pagnet enroll --server <url>' first")
	}

	// First-run console handoff (BINDING 2026-09-22): the terminal's job is
	// runtime; the browser's job is composition. On the definitive first-run
	// event (host registration) print the next-steps block and open the
	// console's /welcome page (only when interactive). On later runs print a
	// one-line reminder when the account has zero networks. Both are best-
	// effort: they must never break or delay serve startup.
	if firstRun {
		printFirstRunHandoff(server, cfg.HostID, cfg.HostName)
	} else {
		printZeroNetworksReminder(server, cfg.HostID, root, account)
	}

	// Export the state dir into the process environment so the session-driven
	// driver (persistent_fake.stateDir) and the supervisor (supervisor.go)
	// resolve the SAME dir as the daemon's --state-dir. Without this, the
	// driver falls back to ~/.local/state/pagnet and writes session files
	// where the e2e harness (and the daemon's own state) cannot find them.
	if cfg.StateDir != "" {
		os.Setenv("PAGNET_STATE_DIR", cfg.StateDir)
	}

	// Fused installed hosted product (Phase A step 6): pagnet serve is the
	// cloud daemon AND, when the operator has a local Fabric installation, the
	// actual installed hosted product over it. An ABSENT installation is
	// daemon-only (one honest log line, never a silent fixture); a PRESENT but
	// corrupt installation is a startup failure (no silent skip). The
	// daemon-side components and the per-connect advertisement gate are wired
	// here; the runtime bindings, catalog publisher and importer are wired
	// post-daemon (they need the daemon, which does not exist yet).
	installDir, _, err := localFabricPaths("", "")
	if err != nil {
		return err
	}
	// Observability stack (E4.4): the configured OTLP exporter (or the
	// no-op default) + the bounded durable metadata-only trace store in
	// the machine state dir. It is composed BEFORE the installation so
	// the installed node's InstalledConfig.Tracing carries the real
	// provider. A misconfigured exporter is a startup failure (explicit
	// operator configuration fails closed); the empty-endpoint default
	// is exactly the previous no-op behavior.
	tel, err := otel.Compose(cmd.Context(), telemetryStackConfig(cfg, filepath.Join(cfg.StateDir, "telemetry")))
	if err != nil {
		return fmt.Errorf("compose observability: %w", err)
	}
	// Defer order (LIFO): the node close registers NEXT, so it runs
	// BEFORE the stack shutdown — the node's final spans flush into the
	// store/exporter before the exporter drains and the store closes.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := tel.Shutdown(cleanup); err != nil {
			log.Warn("observability shutdown", "error", err)
		}
	}()
	node, err := openFusedInstallation(cmd.Context(), installDir, tel.Provider)
	if err != nil {
		var retained *fabricnode.InstalledOpenError
		if errors.As(err, &retained) {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err = errors.Join(err, retained.CloseContext(cleanup))
		}
		return err
	}
	if node == nil {
		log.Info("pagnet serve: no local Fabric installation; serving daemon-only (hosted product unavailable)", "dir", installDir)
	}

	daemonCfg := daemon.Config{
		ServerURL:    server,
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
		// --insecure-remote-http (dev-only plain-HTTP opt-in for a
		// non-loopback control plane / release URL).
		InsecureRemoteHTTP: insecureRemoteHTTP,
	}
	// advertiseGate is assigned post-daemon (the runtime bindings need the
	// daemon); the closure is fail-closed (never advertises) until then, and
	// it is called on the connect context once per (re)connect.
	var advertiseGate func(context.Context) bool
	if node != nil {
		h := node.Hosted
		daemonCfg.HostedOwnerGuard = h.OwnerGuard
		daemonCfg.HostedInvocationGuard = h.InvocationGuard
		daemonCfg.HostedFabricSideports = h.Sideports
		// The managed runtimes' MCP bridges dial this socket (the Landlock
		// sandbox must open its parent directory) — grant it through the
		// PAGNET_FABRIC_SIDEPORT launch env pair (see the daemon Config).
		daemonCfg.HostedFabricSideportSocket = node.Installation.Configuration().Settings.SocketPath
		daemonCfg.HostedAdvertise = func(ctx context.Context) bool {
			return advertiseGate != nil && advertiseGate(ctx)
		}
	}
	d, err := daemon.New(daemonCfg, log)
	if err != nil {
		if node != nil {
			_ = node.Close()
		}
		return fmt.Errorf("init daemon: %w", err)
	}
	// Close order: the daemon FIRST (its hosted catalog importer feeds the
	// node's search backend and must stop before the node releases its Store),
	// then the node (which closes the installation last). Defers run LIFO, so
	// the node close is registered before the daemon close.
	defer func() {
		if node != nil {
			_ = node.Close()
		}
	}()
	defer d.Close()

	// Post-daemon wiring of the fused hosted product. It needs the daemon,
	// which does not exist when the node is composed, and it all completes
	// BEFORE the first host connection (d.Run). A failure here is a startup
	// failure (the defers close the daemon, then the node).
	if node != nil {
		h := node.Hosted
		wireCtx := cmd.Context()
		bindings, bErr := fabricnode.NewHostedRuntimeBindings(wireCtx, node.Installation.Store, h.Profiles, d, h.OwnerGuard)
		if bErr != nil {
			return bErr
		}
		advertiseGate = func(ctx context.Context) bool { return bindings.Ready(ctx) == nil }
		owner, oErr := node.Installation.Operator(wireCtx)
		if oErr != nil {
			return oErr
		}
		publisher, pErr := fabricnode.NewHostedCatalogPublisher(wireCtx, bindings, owner)
		if pErr != nil {
			return pErr
		}
		h.SetBindings(bindings)
		h.SetPublisher(publisher)
		h.SetDaemon(d)
		h.SetProbe(d.ProbeHostedProfile)
		if networks := h.Networks(); len(networks) > 0 {
			importer, iErr := daemon.NewHostedCatalogImporter(d, daemon.HostedCatalogImporterConfig{
				TrustedRoots: []registry.GenesisRecord{node.Installation.Store.Genesis()},
				Networks:     networks,
				Feed: func(ctx context.Context, _ string, batch search.Batch) error {
					return h.SearchBackend.Apply(ctx, batch)
				},
			})
			if iErr != nil {
				return iErr
			}
			d.HostedCatalogImporter = importer
		}
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("pagnet serve starting",
		"server", server, "state_dir", cfg.StateDir,
		"allowed_roots", cfg.AllowedRoots)
	if err := d.Run(ctx); err != nil {
		return err
	}
	return nil
}

// openFusedInstallation loads the operator's local Fabric installation for the
// fused pagnet serve. An ABSENT installation dir is honest daemon-only (nil,
// nil); a PRESENT dir that fails to load (corrupt/invalid) is a genuine
// startup error (no silent skip). A present, valid installation composes the
// actual installed hosted product (explicit Hosted config, never implicit).
// tracing is the composed observability provider (E4.4); nil is the
// node's no-op default.
func openFusedInstallation(ctx context.Context, installDir string, tracing telemetry.Provider) (*fabricnode.InstalledNode, error) {
	if _, statErr := os.Stat(installDir); os.IsNotExist(statErr) {
		return nil, nil
	} else if statErr != nil {
		return nil, fmt.Errorf("inspect local installation: %w", statErr)
	}
	binary, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable for local installation: %w", err)
	}
	return fabricnode.OpenInstalled(ctx, fabricnode.InstalledConfig{
		Directory: installDir,
		Binary:    binary,
		Hosted:    &fabricnode.InstalledHostedConfig{},
		// The installed federation exposure surface (slice-1 config surface)
		// is explicit, like Hosted. The declared signed record is consumed by
		// the serving slice; declaring it before then is config-first, not a
		// non-functional surface (no daemon lane or other capability is
		// required to compose it).
		Federation: &fabricnode.InstalledFederationConfig{},
		// The configured observability provider (the OTLP exporter + the
		// bounded durable trace store behind it); nil = the node's no-op
		// default.
		Tracing: tracing,
	})
}

// telemetryStackConfig maps the daemon config's Telemetry surface onto the
// observability stack composition, with the durable trace store rooted at
// traceDir. The metadata-only privacy invariants live in fabric/telemetry;
// this mapping only selects the transport and the retention bounds.
func telemetryStackConfig(cfg config.Daemon, traceDir string) otel.Config {
	return otel.Config{
		ExporterEndpoint:   cfg.Telemetry.ExporterEndpoint,
		ExporterProtocol:   cfg.Telemetry.ExporterProtocol,
		Headers:            cfg.Telemetry.Headers,
		AcceptRemoteParent: cfg.Telemetry.AcceptRemoteParent,
		TraceDir:           traceDir,
		Retention:          cfg.Telemetry.TraceRetention,
		MaxTraces:          cfg.Telemetry.MaxTraces,
	}
}

// --- first-run console handoff (BINDING 2026-09-22) ---------------------------
//
// The terminal's job is runtime; the browser's job is composition. `pagnet
// serve` completes the connection and then HANDS OFF to the console: no
// interactive create/join flows in the CLI.

// printFirstRunHandoff prints the first-run next-steps block and opens the
// console's /welcome page (only when interactive). It runs after a
// successful first-run host registration — the definitive first-run event.
// The printed block respects --silent; the browser-open is gated by
// interactivity (hasTTY / --non-interactive) and PAGNET_NO_BROWSER, mirroring
// the OIDC device flow.
func printFirstRunHandoff(server, hostID, hostName string) {
	origin := strings.TrimSuffix(server, "/")
	if !silent {
		fmt.Printf("✓ signed in · host %q connected to %s\n\n", hostName, origin)
		fmt.Println("  Next steps — in your browser:")
		fmt.Printf("    %s/welcome      ← create your first network and add this host\n", origin)
		fmt.Println("    docs.pagnet.dev/quickstart  ← then launch your first agent")
	}
	if interactiveMode() && os.Getenv("PAGNET_NO_BROWSER") != "1" {
		if err := openBrowserFn(origin + "/welcome?host=" + hostID); err != nil {
			fmt.Println("(could not open a browser — use the URL above)")
		}
	}
}

// printZeroNetworksReminder prints a one-line reminder when the account has
// zero networks (a later run on an already-enrolled host). It checks the
// networks list via the authenticated API; on ANY error or non-200 it prints
// nothing — the reminder must never break or delay serve startup. It is
// skipped entirely when networks exist.
func printZeroNetworksReminder(server, hostID, root, account string) {
	if silent {
		return
	}
	bearer := loadUserToken(accountConfigDir(root, account), account, server)
	if bearer == "" {
		return
	}
	if countNetworks(server, bearer) != 0 {
		return
	}
	origin := strings.TrimSuffix(server, "/")
	fmt.Printf("no networks yet — create your first: %s/welcome?host=%s\n", origin, hostID)
}

// countNetworks returns the number of networks the user's account has, via
// the authenticated GET /api/v1/networks. Any error (no bearer, network
// failure, non-200, decode failure) returns -1 so the caller treats it as
// "unknown" and prints nothing — the reminder must never break or delay
// serve startup.
func countNetworks(base, bearer string) int {
	if bearer == "" {
		return -1
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(base, "/")+"/api/v1/networks", nil)
	if err != nil {
		return -1
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	client := netpolicy.NewHTTPClient(5*time.Second, insecureRemoteHTTP)
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1
	}
	var nets []struct {
		ID string `json:"ID"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&nets); err != nil {
		return -1
	}
	return len(nets)
}

// runDetach implements `pagnet -d`: re-exec this binary as
// `pagnet serve <flags>` in a new session, stdio appended to
// <state-dir>/pagnetd.log, and print the child pid. -d is a launcher
// convenience, not a second runtime mode: the child runs the identical
// foreground `serve` path.
func runDetach(cmd *cobra.Command) error {
	if daemonLocal {
		return runLocalFabricDetached(cmd, daemonLocalDirectory)
	}
	if cmd.Flags().Changed("local-dir") {
		return fmt.Errorf("--local-dir requires --local")
	}
	if err := hostPlatformError(); err != nil {
		return err
	}
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
	// First run on this machine: the host is NOT enrolled (no credential +
	// host id). Connect it in the FOREGROUND before detaching — the
	// token-first paste must run before the child starts, and the paste
	// never runs inside the detached child. (A config load failure is not
	// fatal here: the child reports it.)
	if cfg, account, err := loadAccountConfig(stateDir); err == nil && needsEnroll(cfg) {
		if err := enrollHostForeground(stateDir, account, "", nil, "", ""); err != nil {
			return err
		}
	}
	changed := map[string]bool{
		"state-dir":      cmd.Flags().Changed("state-dir"),
		"log-level":      cmd.Flags().Changed("log-level"),
		"debug":          cmd.Flags().Changed("debug"),
		"no-auto-update": cmd.Flags().Changed("no-auto-update"),
	}
	return daemonizeSelf(stateDir, detachArgs(os.Args[1:], changed))
}

// detachArgs builds the child argv for `pagnet -d`: the `serve`
// subcommand plus only the daemon flags the user explicitly set
// (changed). The -d/--detach flag itself is stripped, and anything that
// is not a daemon flag (--server, --token, unknown args) is dropped —
// the child is `serve`, which knows only the daemon flag set.
func detachArgs(osArgs []string, changed map[string]bool) []string {
	valueFlags := map[string]bool{"state-dir": true, "log-level": true}
	boolFlags := map[string]bool{"debug": true, "no-auto-update": true}
	args := []string{"serve"}
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
	child.SysProcAttr = detachedProcessAttrs()
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
	if !silent {
		fmt.Printf("pagnet service started (pid %d) — log: %s\n", pid, logPath)
	}
	return nil
}
