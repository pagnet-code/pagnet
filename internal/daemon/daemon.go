package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/netpolicy"
	"github.com/pagnet-code/pagnet/internal/proc"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// ErrDeferred means the command cannot be executed right now but must NOT
// be acknowledged or failed: it stays queued server-side and is re-sent by
// the host dispatcher (e.g. the instance is busy and maxConcurrentTurns=1).
var ErrDeferred = errors.New("deferred: stays queued")

// ErrUnenrolled means the control plane removed (or revoked) this host:
// the credential is dead, reconnecting would only 401, and the daemon
// stops itself instead of retrying forever.
var ErrUnenrolled = errors.New("host unenrolled from the control plane — the credential is no longer valid; to join again, create a new enrollment token and run `pagnet enroll`")

// ErrSuperseded means a NEWER daemon connection took over this host's
// identity (the control plane closes the older connection with
// transport.CloseCodeSuperseded). Another daemon process now owns the
// host — reconnecting would only fight it forever, so the daemon stops.
var ErrSuperseded = errors.New("superseded by a newer daemon connection — another daemon now owns this host; stop this one")

// ErrOutdated means the control plane speaks a protocol version this daemon
// does not support (protocol.upgrade_required / a newer envelope). A v1
// daemon against a v2 server would misparse the wire, so the only correct
// move is to stop and surface the user-facing message.
var ErrOutdated = errors.New("control plane requires a newer protocol — update the pagnet client")

// Config is the daemon configuration (plain data, safe to pass by value).
type Config struct {
	ServerURL    string
	Credential   string
	HostID       string
	StateDir     string
	AllowedRoots []string
	// RootsMode is the initial roots enforcement mode (allow_all by
	// default, allow_list to confine to AllowedRoots). The server is the
	// source of truth and replaces it at runtime via host.update_roots.
	// Empty = allow_all.
	RootsMode string
	Version   string
	Heartbeat time.Duration
	// RuntimeEnv is applied to spawned runtime processes (E2E simulation
	// knobs live here; a real deployment leaves it empty).
	RuntimeEnv []string
	// PrimaryWorkspace, when set, is registered as a workspace on every
	// connect (host.workspace_detected) even when it is not a git
	// repository — the single-directory worker mode: the inventory scan
	// only reports git repos, so without this a fresh/empty directory
	// would never be launchable from the UI or CLI.
	PrimaryWorkspace string
	// NoScan disables automatic git-repository discovery (inventory
	// reports no workspaces; PrimaryWorkspace is still reported, since
	// it is the worker's identity, not a discovery result). Workspaces
	// are then managed explicitly from the UI or CLI.
	NoScan bool
	// Debug enables development/test-only behavior: it registers the
	// deterministic fake runtime (a test/demo stand-in, never a real
	// agent runtime). Default FALSE — a production daemon never offers
	// the fake runtime. Set from --debug / PAGNET_DEBUG / config.
	Debug bool
	// AutoUpdate enables worker self-update (P6): when the control plane
	// advertises a newer release (PAGNET_RELEASE_VERSION) and the daemon
	// is idle, it downloads the release tarball and re-execs in place
	// (same PID). Default TRUE — opt out via PAGNET_AUTO_UPDATE=0,
	// --no-auto-update, or the state file's autoUpdate: false.
	AutoUpdate bool
	// InsecureRemoteHTTP is the --insecure-remote-http flag value: it opts
	// into plain HTTP for a non-loopback control plane / release URL
	// (development only). ORed with the PAGNET_INSECURE_REMOTE_HTTP env by
	// the netpolicy check. Default FALSE — a non-loopback remote must be
	// HTTPS.
	InsecureRemoteHTTP bool

	// --- Process-containment limits (abuse addendum Part B §29–§35) ---
	// Zero values fall back to the supervisor's safe defaults (and the
	// PAGNET_* environment, see proc.EnvConfig). These are SAFETY ceilings,
	// not product licensing: they bound how much of the host one pagnet
	// installation may consume.
	// MaxActiveTurns: global ceiling of simultaneously active turn
	// processes (the launch semaphore). Default 4.
	MaxActiveTurns int
	// TurnProcessesWarn / TurnProcessesHard: per-turn owned-process
	// thresholds. Hard crossing terminates the turn group. Default 64/128.
	TurnProcessesWarn int
	TurnProcessesHard int
	// OwnedProcessesHard: global owned-process ceiling across all active
	// turns. Reaching it refuses new launches. Default 256.
	OwnedProcessesHard int
	// HostPressurePct: refuse new launches at this percentage of the
	// effective soft RLIMIT_NPROC (0 = disabled). Default 80.
	HostPressurePct int
	// TurnTermGrace: TERM → grace → KILL window for group termination.
	// Default 5s.
	TurnTermGrace time.Duration
	// LaunchBackoffMin/Max: exponential backoff bounds after
	// resource-pressure launch failures. Default 1s/30s.
	LaunchBackoffMin time.Duration
	LaunchBackoffMax time.Duration
	// LaunchCircuitFailures/Window/Block: the launch circuit breaker.
	// Default 5 failures / 60s window / 60s block.
	LaunchCircuitFailures int
	LaunchCircuitWindow   time.Duration
	LaunchCircuitBlock    time.Duration
}

// Daemon is a running host-daemon instance.
type Daemon struct {
	Config
	Log *slog.Logger

	state    *State
	adapters map[domain.RuntimeName]agentruntime.Adapter

	// selfExe is this process's canonicalized own executable path,
	// resolved ONCE at construction (New). The agent runtimes spawn the
	// MCP bridges as <selfExe> mcp worker|control (packaging migration
	// step 5): the daemon never searches PATH for sibling bridge
	// binaries — an install dir that is not on PATH must still give
	// agents their network tools.
	selfExe string

	// bootID is this process's runner identity (Phase 3 Host→Runner model):
	// minted once at startup and carried in every WSS connect so the control
	// plane registers the daemon as a runner under the host, keyed by
	// (host_id, boot_id). A reconnect of the same process reuses its runner;
	// a new process (new boot id) is a distinct, coexisting runner.
	bootID string

	// unenrolled is set by the read loop on host.unenrolled (or by Run on
	// an auth-rejected dial) so Run exits instead of reconnecting.
	unenrolled bool

	// superseded is set by the read loop when the control plane closes
	// the connection with CloseCodeSuperseded (a newer daemon owns the
	// host now) so Run exits instead of reconnecting.
	superseded bool

	// outdated is set by the read loop on protocol.upgrade_required (or a
	// newer envelope version) so Run exits with the user-facing "update"
	// message instead of reconnecting.
	outdated bool

	// serveLockFile is the open <StateDir>/serve.lock file (acquired in
	// Run via acquireServeLock, held for the daemon's lifetime). It is
	// kept on the Daemon — not only in the release closure — so an
	// auto-update re-exec can carry the flock across the exec: Go opens
	// every file with O_CLOEXEC, so a closure-only fd would be closed
	// at exec and the lock silently released, letting a second `pagnet
	// serve` take the state dir in the window before the new image
	// re-acquires it.
	serveLockFile *os.File

	// rootsMu guards AllowedRoots: host.update_roots replaces it at
	// runtime (the server-side root list is the source of truth).
	rootsMu sync.RWMutex

	turnMu      sync.Mutex
	activeTurns map[string]bool

	// turnCtx cancels when the daemon shuts down (Close): adapters kill
	// the running turn subprocess on cancellation (spec §90: context
	// cancellation must terminate subprocess work), so a SIGTERM never
	// orphans a mid-turn process.
	turnCtx    context.Context
	turnCancel context.CancelFunc

	// closeOnce makes Close idempotent: tests and shutdown paths may call
	// it more than once (explicit Close + t.Cleanup), and the underlying
	// resources (sql.DB, supervisor) must not be torn down twice.
	closeOnce sync.Once

	// Per-repository lock serializing the §29 isolation decision
	// (resolveWorkspace) and the instance registration that follows it:
	// concurrent launches of different instances run on parallel
	// per-instance queues, and two near-simultaneous RW launches must not
	// both decide they are the "first RW agent" on a repository.
	repoLockMu sync.Mutex
	repoLocks  map[string]*sync.Mutex

	// Active attach sessions per instance (§35: no hibernation
	// underneath an attached user). In-memory: a daemon restart drops
	// the tracking, which is safe — worst case the instance hibernates
	// and the next attach re-wakes it.
	attachMu sync.Mutex
	attaches map[string]map[string]time.Time // instanceID -> attachSessionID

	// PTY terminal sessions (addendum §8–§15): the long-lived interactive
	// runtime process per instance, separate from the process-per-turn
	// machinery. In-memory: a daemon restart drops the PTY (the process
	// cannot survive it); the next attach starts a fresh session with the
	// stored runtime session resume.
	terminal *terminalManager

	// sup is the CENTRAL turn-process supervisor (abuse addendum Part B
	// §20): one registry, launch gate, semaphore, and cleanup path for
	// every turn process AND every PTY session this daemon owns. It is
	// injected into each runtime adapter (LifecycleSetter) and used
	// directly by the terminal manager.
	sup *proc.Supervisor
	// helper is the bounded short-lived-command executor (§37) for git
	// probes, runtime version checks, and worktree operations.
	helper *proc.Helper

	// sessions is the persistent-session core (runtime-lifecycle refactor,
	// Phase 1): the vendor-agnostic RuntimeSession/Driver/Manager the
	// daemon drives for PERSISTENT runtimes (one long-lived endpoint that
	// services many logical submits). Nil outside debug mode (the fake
	// persistent runtime is the only Phase-1 driver; the five real vendors
	// still use the legacy process-per-turn Adapter path until Phase 2).
	sessions *session.Manager

	// Live host connection (for the bridge relay; nil while disconnected).
	connMu  sync.Mutex
	curConn *websocket.Conn
	// websocket.Conn allows ONE concurrent writer; the heartbeat, command
	// acks, and bridge relay all share the connection, so writes serialize.
	writeMu sync.Mutex

	// Pending agent.request -> waiting bridge-socket client.
	pendingMu sync.Mutex
	pending   map[string]chan transport.AgentResponsePayload

	// Bridge Unix socket listener (agent MCP bridge, PROTOCOL §6).
	bridgeMu sync.Mutex
	bridgeL  net.Listener
	// Bridge connection accounting (external audit F-010): caps on
	// concurrent bridge connections, global and per-instance, so a
	// misbehaving or hostile agent cannot exhaust daemon resources by
	// opening unbounded bridge connections.
	bridgeConnMu    sync.Mutex
	bridgeConns     int
	bridgeConnsInst map[string]int

	// Inventory single-flight (external audit F-016): the workspace scan +
	// runtime version probes fan out bounded helper processes, and a
	// reconnect + a host.request_inventory + an UpdateRoots can arrive
	// close together. invFlight guards the scan so concurrent callers
	// share one scan instead of multiplying the probe storm.
	invMu     sync.Mutex
	invFlight *inventoryFlight

	// Per-instance command queues: commands for one instance run strictly
	// in order (launch before deliver, wake before deliver, ...), while
	// different instances run in parallel. The WSS read loop only
	// ENQUEUES — it must never block on a command's execution, because a
	// turn on a real runtime runs for minutes and would otherwise stall
	// every other envelope on the host connection (agent responses,
	// wakes, other agents' commands).
	queueMu    sync.Mutex
	instQueues map[string]*instQueue

	// CommandIDs already claimed by this process: in flight or terminally
	// handled (success OR failure). The server re-dispatches a command
	// while it is un-acked (dispatchPending ticks every 2 s), and with
	// per-instance FIFO queues those re-sends queue BEHIND the original —
	// after a failed turn the instance is no longer busy, so a queued
	// duplicate would start a second turn (a provider-hammering loop for
	// rate-limited work). Claiming at start and keeping the claim on a
	// terminal failure drops the duplicates. Deferred commands release
	// the claim: they were not handled, and the server's re-send is the
	// one that must run. (Crash-safe: a crash loses the claims, which is
	// exactly when a re-send SHOULD run again; terminal successes are
	// additionally persisted in processed_commands.) Claims carry a
	// timestamp so maintainState can evict stale ones (spec §91: bounded
	// period) — a claim only matters while the server may re-dispatch the
	// same id, which ends once the ack lands.
	seenMu sync.Mutex
	seen   map[string]time.Time

	// deliveredEvents is the ONE-wake-per-event dedup for v2 event
	// deliveries (keyed by the event delivery row id = the ack idempotency
	// key). A redelivery with the same deliveryID acks without re-running
	// the trigger turn, so a flaky re-send never fires two turns for one
	// event. Same timestamped TTL hygiene as seen (maintainState evicts
	// stale entries).
	deliveredMu     sync.Mutex
	deliveredEvents map[string]time.Time

	// Auto-update state (P6): latestVersion is the release version the
	// control plane last advertised (host.latest_version); updating
	// guards the single-flight download/exec; lastAttempt bounds the
	// retry rate after a failed attempt (1h backoff).
	updMu         sync.Mutex
	latestVersion string
	updating      bool
	lastAttempt   time.Time

	// cryptoMu guards cryptoMgr (lazy init on the first crypto command or
	// inventory report). The manager caches the stable host E2EE identity
	// and per-network NKA instances (the NKA must stay alive across an
	// enrollment round-trip — see crypto.go).
	cryptoMu  sync.Mutex
	cryptoMgr *cryptoManager
}

// Bounded dedup retention (spec §91 "bounded period").
const (
	// seenTTL: in-memory claims older than this are evicted. Far beyond
	// any re-send dedup window (server re-dispatch ticks every 2 s while a
	// command is un-acked); command implementations are idempotent enough
	// that a post-eviction re-run is at most one redundant turn.
	seenTTL = 24 * time.Hour
	// processedRetention: persistent gate lifetime. Covers daemon restarts
	// before a lost ack is noticed; a command un-acked longer than this
	// has stale server-side state (sweeps have already failed the flows).
	processedRetention = 30 * 24 * time.Hour
	// maintenanceEvery: how often stale claims are evicted + SQLite pruned.
	maintenanceEvery = time.Hour
)

// instQueue is a single-consumer FIFO for one instance's commands.
type instQueue struct {
	mu   sync.Mutex
	ch   chan func()
	live bool
	// done is closed by finishQueue when the instance is stopped/forgotten:
	// the worker exits instead of ranging on a never-closed channel forever
	// (one dormant goroutine per instance id is an unbounded leak in a
	// long-lived daemon).
	done chan struct{}
}

// procConfigFromDaemon builds the supervisor's process-containment
// config from the daemon Config. Precedence (highest first): explicit
// daemon Config fields (set by the serve command) > PAGNET_* environment
// (proc.EnvConfig) > safe defaults. The StateDir is always the daemon's
// state dir (ownership records live there, §39).
func procConfigFromDaemon(cfg Config) proc.Config {
	c := proc.EnvConfig() // env + safe defaults
	c.StateDir = cfg.StateDir
	if cfg.MaxActiveTurns > 0 {
		c.MaxActiveTurns = cfg.MaxActiveTurns
	}
	if cfg.TurnProcessesWarn > 0 {
		c.TurnProcessesWarn = cfg.TurnProcessesWarn
	}
	if cfg.TurnProcessesHard > 0 {
		c.TurnProcessesHard = cfg.TurnProcessesHard
	}
	if cfg.OwnedProcessesHard > 0 {
		c.OwnedProcessesHard = cfg.OwnedProcessesHard
	}
	if cfg.HostPressurePct >= 0 && cfg.HostPressurePct != 0 {
		c.HostPressurePct = cfg.HostPressurePct
	}
	if cfg.TurnTermGrace > 0 {
		c.TermGrace = cfg.TurnTermGrace
	}
	if cfg.LaunchBackoffMin > 0 {
		c.BackoffMin = cfg.LaunchBackoffMin
	}
	if cfg.LaunchBackoffMax > 0 {
		c.BackoffMax = cfg.LaunchBackoffMax
	}
	if cfg.LaunchCircuitFailures > 0 {
		c.CircuitFailures = cfg.LaunchCircuitFailures
	}
	if cfg.LaunchCircuitWindow > 0 {
		c.CircuitWindow = cfg.LaunchCircuitWindow
	}
	if cfg.LaunchCircuitBlock > 0 {
		c.CircuitBlock = cfg.LaunchCircuitBlock
	}
	return c
}

// New builds a daemon. State is opened at stateDir/daemon.sqlite.
func New(cfg Config, log *slog.Logger) (*Daemon, error) {
	return newDaemon(cfg, log, resolveSelfExecutable)
}

// newDaemon is New with an explicit self-executable resolver: the MCP
// bridges are spawned from the daemon's own binary path, and the
// resolver is the seam tests use to exercise the explicit startup
// failure (a daemon that cannot resolve its own executable must not
// start — its agents would come up with no network tools).
func newDaemon(cfg Config, log *slog.Logger, selfExeResolver func() (string, error)) (*Daemon, error) {
	if log == nil {
		log = slog.Default()
	}
	// HTTPS-required-for-non-loopback (client-hardening wave 2): a
	// non-loopback control plane over plain HTTP is refused at
	// construction, so a misconfigured daemon fails fast instead of
	// shipping the host credential over an unencrypted channel.
	if err := netpolicy.Check(cfg.ServerURL, cfg.InsecureRemoteHTTP); err != nil {
		return nil, err
	}
	// The MCP bridges are spawned as <self> mcp worker|control: resolve
	// the daemon's own executable ONCE, up front, and fail explicitly
	// when it cannot be resolved — never fall back to a bare name or a
	// PATH search (packaging migration step 5).
	selfExe, err := selfExeResolver()
	if err != nil {
		return nil, fmt.Errorf("cannot resolve own executable for MCP bridge spawn: %w", err)
	}
	// 0700: the state dir holds the host credential (config.yaml) and the
	// agent-bridge socket — never world-traversable (SEC-102).
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	st, err := OpenState(filepath.Join(cfg.StateDir, "daemon.sqlite"))
	if err != nil {
		return nil, err
	}
	if cfg.HostID != "" {
		_ = st.KVSet("host_id", cfg.HostID)
	}
	// Process-per-turn runtimes are always registered: the daemon reports
	// whichever of these it can actually drive (detectRuntimes resolves
	// each binary). qwen-code is NOT here (Wave B): it is session-driven
	// (the Qwen Dual Output persistent driver below) — its legacy
	// process-per-turn adapter was removed.
	adapters := map[domain.RuntimeName]agentruntime.Adapter{
		domain.RuntimeClaudeCode: agentruntime.NewClaude(""),
		domain.RuntimeOpenCode:   agentruntime.NewOpenCode(""),
	}
	// The session core (runtime-lifecycle refactor, Phase 1): the
	// vendor-agnostic persistent-session orchestrator. It is ALWAYS
	// created (not debug-only) so the real persistent drivers (Qwen Dual
	// Output, Phase 4) can be registered in production. The fake
	// persistent driver is debug-only (like the process-per-turn Fake).
	sessions := session.NewManager()
	var persistentFake *agentruntime.PersistentFake
	if cfg.Debug {
		fake := agentruntime.NewFake("")
		fake.Env = cfg.RuntimeEnv
		adapters[domain.RuntimeFake] = fake
		// The fake PERSISTENT runtime (runtime-lifecycle refactor, Phase 1):
		// the reference implementation of the persistent model — ONE long-
		// lived endpoint process that services many logical submits. It is
		// driven through the session core (Manager + Driver), not the
		// legacy process-per-turn Adapter path. Like the process-per-turn
		// Fake it is debug-only and NOT a real agent runtime.
		persistentFake = agentruntime.NewPersistentFake("")
		persistentFake.Env = cfg.RuntimeEnv
		// Phase 3 (terminal session unification): the fake persistent
		// endpoint OWNS its TUI PTY, so a terminal attach connects a human
		// to the ENDPOINT'S OWN PTY (the human plane) instead of spawning a
		// second interactive process. The PTY is allocated per-endpoint at
		// launch (PTYSize non-nil); PTY ownership stays optional — a
		// runtime whose driver leaves PTYSize nil keeps the no-PTY topology
		// (invariant I1).
		persistentFake.PTYSize = &pty.Winsize{Rows: 24, Cols: 80}
		sessions.RegisterDriver(persistentFake)
	}
	// The Qwen Dual Output persistent driver (runtime-lifecycle
	// refactor, Phase 4): ONE long-lived qwen TUI per instance, driven
	// through the session core. It is registered when the qwen binary is
	// resolvable (binary presence only — no --version subprocess at
	// boot). Wave B removed the legacy process-per-turn Qwen adapter:
	// qwen-code is session-driven whenever the binary resolves (the
	// daemon routes a qwen instance to the persistent path when a
	// session driver is registered for it).
	qwenPersistent := agentruntime.NewQwenPersistent("")
	qwenPersistent.Env = cfg.RuntimeEnv
	qwenPersistentRegistered := qwenPersistent.Available()
	if qwenPersistentRegistered {
		sessions.RegisterDriver(qwenPersistent)
	}
	// Central turn-process supervisor (abuse addendum Part B §20): ONE
	// registry/launch-gate/cleanup path for every turn process and PTY
	// session this daemon owns. Limits come from the daemon Config (set by
	// the serve command) with the PAGNET_* environment and safe defaults
	// as fallbacks.
	sup := proc.NewSupervisor(procConfigFromDaemon(cfg), log)
	// Inject the central supervisor into every adapter that manages OS
	// processes (the LifecycleSetter seam; test stubs skip it).
	for _, ad := range adapters {
		if ls, ok := ad.(agentruntime.LifecycleSetter); ok {
			ls.SetLifecycle(sup)
		}
	}
	// The persistent fake driver owns its long-lived endpoint process
	// through the supervisor's ClassEndpoint path, so it gets the same
	// central supervisor (the LifecycleSetter seam).
	if persistentFake != nil {
		persistentFake.SetLifecycle(sup)
	}
	// The Qwen Dual Output driver owns its long-lived endpoint process
	// through the supervisor's ClassEndpoint path (the same seam).
	if qwenPersistentRegistered {
		qwenPersistent.SetLifecycle(sup)
	}
	// Bounded helper-command executor (§37) for git/version/worktree probes.
	helper := proc.NewHelper(0)
	turnCtx, turnCancel := context.WithCancel(context.Background())
	d := &Daemon{
		Config:          cfg,
		Log:             log,
		state:           st,
		adapters:        adapters,
		selfExe:         selfExe,
		bootID:          domain.NewID().String(),
		activeTurns:     map[string]bool{},
		attaches:        map[string]map[string]time.Time{},
		pending:         map[string]chan transport.AgentResponsePayload{},
		bridgeConnsInst: map[string]int{},
		instQueues:      map[string]*instQueue{},
		seen:            map[string]time.Time{},
		deliveredEvents: map[string]time.Time{},
		turnCtx:         turnCtx,
		turnCancel:      turnCancel,
		repoLocks:       map[string]*sync.Mutex{},
		sup:             sup,
		helper:          helper,
		sessions:        sessions,
	}
	d.terminal = newTerminalManager(d)
	// Crash/restart reconciliation (§39): a hard crash may have left a
	// turn process tree alive. Verify ownership (start-identity, never a
	// bare PID) and reclaim proven-ours groups; PID reuse is never killed.
	sup.Reconcile()
	// Spec §91: start from a bounded dedup set (drops rows prunable
	// while the daemon was down).
	if err := st.PruneProcessed(time.Now().UTC().Add(-processedRetention)); err != nil {
		log.Warn("prune processed_commands at startup", "err", err)
	}
	// §66: a process-per-turn turn cannot survive a daemon restart, so a
	// locally 'working' row at startup is stale (its subprocess is gone).
	// Reconcile to hibernated/idle; the server re-sends the un-acked
	// command, which re-wakes the instance and re-runs the turn.
	if n, err := st.ReconcileRestart(); err == nil && n > 0 {
		log.Warn("reconciled instances left working by a previous run", "n", n)
	}
	// P6 auto-update: clear a leftover staging dir from a previous
	// update that re-exec'd successfully (nothing runs after the exec to
	// clean it up).
	_ = os.RemoveAll(filepath.Join(cfg.StateDir, "update-staging"))
	return d, nil
}

// enqueueInstance queues fn for one instance: strict per-instance FIFO,
// parallel across instances. The read loop hands the job over and keeps
// reading — even while a long turn occupies the instance's worker.
//
// Returns false WITHOUT enqueuing when the instance's queue is full: the
// command was never acked, so the server's dispatcher re-sends it on the
// next tick and it is retried then. (Blocking here would stall the WSS
// read loop — heartbeats, other instances, the bridge relay — until the
// busy worker drained, which for a real-runtime turn is minutes.)
func (d *Daemon) enqueueInstance(instanceID string, fn func()) bool {
	d.queueMu.Lock()
	q, ok := d.instQueues[instanceID]
	if !ok {
		q = &instQueue{ch: make(chan func(), 64), done: make(chan struct{})}
		d.instQueues[instanceID] = q
	}
	d.queueMu.Unlock()

	q.mu.Lock()
	if !q.live {
		q.live = true
		go func() {
			for {
				select {
				case <-q.done:
					return
				case job := <-q.ch:
					job()
				}
			}
		}()
	}
	select {
	case q.ch <- fn:
		q.mu.Unlock()
		return true
	default:
		q.mu.Unlock()
		d.Log.Warn("instance command queue full; dropping (server re-send retries)",
			"instance", instanceID)
		return false
	}
}

// finishQueue removes an instance's queue and stops its worker. The
// instance is stopped/forgotten: any still-queued jobs are un-acked, so
// the server re-sends them (they will be refused/finalized on the fresh
// queue) — nothing is silently lost.
func (d *Daemon) finishQueue(instanceID string) {
	d.queueMu.Lock()
	q, ok := d.instQueues[instanceID]
	if ok {
		delete(d.instQueues, instanceID)
	}
	d.queueMu.Unlock()
	if ok {
		close(q.done)
	}
}

// Close shuts the daemon down: kills the PTY terminal sessions and
// cancels in-flight turns (adapters kill the subprocesses, spec §90),
// waits briefly for them to die, then closes the bridge socket and state.
// Idempotent: a second call returns nil without re-tearing-down resources.
func (d *Daemon) Close() error {
	var err error
	d.closeOnce.Do(func() {
		// Shutdown (abuse addendum Part B §38): stop accepting new
		// launches, terminate every owned process group (turns AND PTYs)
		// with a bounded grace, reap, and flush state. The supervisor owns
		// the group termination and the bounded wait — never wait forever
		// for one runtime.
		d.turnCancel()       // ctx watchers terminate active turn groups
		d.terminal.stopAll() // stop PTY sessions (delegates to the supervisor)
		if n := d.sup.StopAll(10 * time.Second); n > 0 {
			d.Log.Error("shutdown: process groups not reaped within deadline", "survivors", n)
		}
		d.stopBridgeSocket()
		err = d.state.Close()
	})
	return err
}

// serveLockFDEnv carries the serve-lock fd across an auto-update
// re-exec: the old image clears CLOEXEC on the lock fd and passes it in
// the exec environment (serveLockExecEnv); the new image adopts it in
// acquireServeLock so the flock is never released (a CLOEXEC fd would
// be closed at exec and the lock would drop, letting a second `pagnet
// serve` take the state dir in the window before the new image
// re-acquires it).
const serveLockFDEnv = "PAGNET_SERVE_LOCK_FD"

// acquireServeLock takes an exclusive advisory lock on
// <StateDir>/serve.lock (external audit F-006) and returns a release
// function. The lock is held for the daemon's lifetime; closing the fd
// (on release or process exit) drops the flock. A second daemon with the
// same state dir gets EWOULDBLOCK and must refuse to start.
//
// Re-exec adoption: when the environment carries a lock fd from a
// re-exec'd image (serveLockFDEnv), it is adopted instead of freshly
// acquired — the flock is held by the open file description, so the
// lock was never released and no second daemon can have taken the state
// dir in between.
func (d *Daemon) acquireServeLock() (func(), error) {
	path := filepath.Join(d.StateDir, "serve.lock")

	if v := os.Getenv(serveLockFDEnv); v != "" {
		if release, ok := d.adoptServeLock(path, v); ok {
			d.Log.Info("adopted serve lock across re-exec")
			return release, nil
		}
		// Stale/foreign fd: fall through to the normal fresh acquire.
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("serve lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another pagnet daemon is already running (state dir %s is locked): %w", d.StateDir, err)
	}
	d.serveLockFile = f
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// adoptServeLock re-adopts the serve lock carried across a re-exec. The
// carried fd is verified to be exactly the lock file (fstat dev+ino vs
// the path — a reused fd number or a stale env from an unrelated
// process must not be adopted) and the lock is re-asserted on the same
// open file description (a re-flock succeeds only for the current
// holder). On any mismatch the fd is closed and false is returned (the
// caller does a fresh acquire).
//
// CLOEXEC is re-set IMMEDIATELY after the identity check, before the
// verifying flock: from that point on the fd can never leak into a
// spawned process (runtime children, MCP bridges, git/update helpers).
// If it leaked, the lock would survive this daemon's exit — a
// descendant still holding the descriptor keeps the flock — and the
// state dir would be permanently locked.
func (d *Daemon) adoptServeLock(path, fdStr string) (func(), bool) {
	fd, err := strconv.Atoi(fdStr)
	if err != nil || fd <= 0 {
		return nil, false
	}
	f := os.NewFile(uintptr(fd), "serve.lock")
	// Verify the fd is actually our lock file (fstat on the fd vs the
	// path): a closed/reused fd number must not be adopted.
	fdFi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, false
	}
	pathFi, err := os.Stat(path)
	if err != nil {
		_ = f.Close()
		return nil, false
	}
	fdSt, ok1 := fdFi.Sys().(*syscall.Stat_t)
	pathSt, ok2 := pathFi.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 || fdSt.Dev != pathSt.Dev || fdSt.Ino != pathSt.Ino {
		_ = f.Close()
		return nil, false
	}
	// Re-arm CLOEXEC NOW (before the verifying flock): the fd must not
	// leak into processes this daemon spawns; only a deliberate
	// re-exec carries it (serveLockExecEnv clears it again).
	if _, err := unix.FcntlInt(f.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		_ = f.Close()
		return nil, false
	}
	// Prove we hold the lock: a re-flock on the same open file
	// description succeeds only for the current holder.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, false
	}
	os.Unsetenv(serveLockFDEnv)
	d.serveLockFile = f
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, true
}

// serveLockExecEnv prepares the serve lock to survive an auto-update
// re-exec and returns the env var that carries the fd to the new image
// ("" when the daemon holds no serve lock). The flock is held by the
// open file description, not the process: Go opens every file with
// O_CLOEXEC, so without clearing the flag the fd would be closed at
// exec and the lock silently released — opening a window in which a
// second `pagnet serve` can take over the state dir. The adopt path
// re-sets CLOEXEC immediately, so the carried fd cannot leak into
// spawned processes of the new image.
func (d *Daemon) serveLockExecEnv() (string, error) {
	if d.serveLockFile == nil {
		return "", nil
	}
	if _, err := unix.FcntlInt(d.serveLockFile.Fd(), unix.F_SETFD, 0); err != nil {
		return "", fmt.Errorf("clear CLOEXEC on serve lock fd: %w", err)
	}
	return serveLockFDEnv + "=" + strconv.FormatInt(int64(d.serveLockFile.Fd()), 10), nil
}

// Run connects and stays connected (reconnecting with backoff) until ctx is
// canceled.
func (d *Daemon) Run(ctx context.Context) error {
	if d.Credential == "" {
		return fmt.Errorf("no host credential; run `pagnet login` first")
	}
	// State-dir flock (external audit F-006): refuse to run if another
	// daemon already owns this state dir. Two daemons on one host with the
	// same state dir would fight over the host identity (each new
	// connection supersedes the other) and double-launch processes. The
	// bridge-socket double-start guard is a narrower second layer that only
	// catches a LIVE socket; this lock closes the window before the socket
	// exists.
	releaseLock, err := d.acquireServeLock()
	if err != nil {
		return err
	}
	defer releaseLock()
	// The agent bridge socket is local and independent of the WSS
	// connection: it is up as soon as the daemon is, and relayed calls
	// fail cleanly (not hang) while the host connection is down.
	if err := d.startBridgeSocket(); err != nil {
		return err
	}
	backoff := time.Second
	for ctx.Err() == nil {
		err := d.connectAndRun(ctx)
		if d.unenrolled {
			// The control plane removed/revoked this host (live
			// host.unenrolled, or an auth-rejected dial): the credential
			// is dead, so stop with a message instead of retrying forever.
			d.Log.Error("stopping: host unenrolled", "err", ErrUnenrolled)
			return ErrUnenrolled
		}
		if d.superseded {
			// A newer daemon connection owns this host's identity;
			// reconnecting would only fight that daemon forever.
			d.Log.Error("stopping: superseded by a newer daemon", "err", ErrSuperseded)
			fmt.Fprintln(os.Stderr,
				"pagnet: a newer daemon took over this host — this daemon is stopping")
			return ErrSuperseded
		}
		if d.outdated {
			// The control plane requires a protocol this daemon cannot
			// speak. Reconnecting would just re-receive the upgrade notice
			// forever — stop with the user-facing message.
			d.Log.Error("stopping: protocol upgrade required", "err", ErrOutdated)
			fmt.Fprintln(os.Stderr,
				"pagnet: "+transport.UpgradeRequiredMessage)
			return ErrOutdated
		}
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			if isAuthReject(err) {
				// 401/403 on dial: the credential no longer exists (host
				// deleted or revoked while we were down). Same outcome as
				// a live host.unenrolled — stop, with the reason visible.
				d.unenrolled = true
				d.Log.Error("stopping: credential rejected by the control plane", "err", err)
				return ErrUnenrolled
			}
			d.Log.Warn("connection lost", "err", err, "retry_in", backoff)
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
	return nil
}

// isAuthReject reports whether a dial error is an auth rejection (401/403)
// from the control plane — the daemon's credential is dead, not a network
// problem, so reconnecting cannot help.
func isAuthReject(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "http 401") || strings.Contains(s, "http 403")
}

func (d *Daemon) wsURL() string {
	base := strings.TrimSuffix(d.ServerURL, "/")
	u, err := url.Parse(base)
	if err != nil {
		return base + "/api/v1/hosts/ws"
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/v1/hosts/ws"
	// Runner boot identity (Phase 3): the control plane registers this
	// daemon process as a runner under the host, keyed by (host_id, boot_id).
	q := u.Query()
	q.Set("boot_id", d.bootID)
	u.RawQuery = q.Encode()
	return u.String()
}

func (d *Daemon) connectAndRun(ctx context.Context) error {
	// Re-check the HTTPS policy on every (re)connect: New checked it at
	// construction, but this is the actual dial — a defense-in-depth
	// guard so no code path can ever open a plain-HTTP non-loopback
	// control-plane connection.
	if err := netpolicy.Check(d.ServerURL, d.InsecureRemoteHTTP); err != nil {
		return err
	}
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+d.Credential)
	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, d.wsURL(), hdr)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial: %v (http %d)", err, resp.StatusCode)
		}
		return err
	}
	defer conn.Close()
	d.connMu.Lock()
	d.curConn = conn
	d.connMu.Unlock()
	defer func() {
		d.connMu.Lock()
		d.curConn = nil
		d.connMu.Unlock()
	}()
	d.Log.Info("connected to control plane")

	// Announce inventory on (re)connect: runtimes + workspaces, and it
	// triggers the server's reconnect wake re-evaluation (pending commands
	// are re-sent; we deduplicate locally by CommandID).
	d.sendInventory(conn)
	// V2: re-sync endpoint liveness for every tracked instance. The
	// host.endpoint_status reports are live / at-most-once, so a daemon
	// restart (or a reconnect) drops the prior connection's reports —
	// re-reporting them now converges the control plane's derived
	// PrincipalEndpoint rows with the daemon's actual instance state.
	d.reportAllEndpointStatuses(conn)
	if d.PrimaryWorkspace != "" {
		// Single-directory worker: register the directory itself even
		// when it is not a git repository (gitWorkspaceReport degrades
		// gracefully — empty remote/branch, no resource key).
		_ = d.send(conn, transport.MsgWorkspaceDetected, d.gitWorkspaceReport(d.PrimaryWorkspace))
	}

	heartbeat := time.NewTicker(d.Heartbeat)
	defer heartbeat.Stop()
	maint := time.NewTicker(maintenanceEvery)
	defer maint.Stop()
	// Exits when THIS connection ends (not only on daemon shutdown) — a
	// goroutine that only watches ctx would survive every reconnect as a
	// dormant leak capturing the dead conn.
	connDone := make(chan struct{})
	defer close(connDone)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-connDone:
				return
			case <-heartbeat.C:
				d.sendHeartbeat(conn)
			case <-maint.C:
				d.maintainState()
			}
		}
	}()

	// Unblock the read loop on shutdown: closing the connection makes a
	// pending ReadMessage return an error so the daemon can exit cleanly.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_, raw, err := conn.ReadMessage()
		if err != nil {
			var closeErr *websocket.CloseError
			if errors.As(err, &closeErr) && closeErr.Code == transport.CloseCodeSuperseded {
				// The control plane closed this connection because a
				// NEWER daemon connection took over the host identity
				// (a second daemon was started). Stop: reconnecting
				// would only fight the other daemon forever.
				d.superseded = true
				return ErrSuperseded
			}
			return err
		}
		var env transport.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			d.Log.Warn("bad envelope from server", "err", err)
			continue
		}
		if env.ProtocolVersion > transport.ProtocolVersion {
			// Protocol v2 gate (V2 cutover): the control plane speaks a
			// protocol this daemon does not support. The server sent
			// protocol.upgrade_required (or a newer envelope) — stopping is
			// the only correct move (a v1 daemon against a v2 server would
			// misparse the wire). Surface the user-facing message, not a
			// silent retry loop.
			d.outdated = true
			d.Log.Error("protocol upgrade required — stopping", "required", env.ProtocolVersion, "have", transport.ProtocolVersion)
			fmt.Fprintln(os.Stderr, "pagnet: "+transport.UpgradeRequiredMessage)
			return ErrOutdated
		}
		if env.Type == transport.MsgUpgradeRequired {
			// protocol.upgrade_required/v1: the server's explicit "your
			// client is outdated" notice. Same outcome as a newer envelope
			// version: stop with the user-facing message.
			d.outdated = true
			d.Log.Error("protocol upgrade required — stopping")
			fmt.Fprintln(os.Stderr, "pagnet: "+transport.UpgradeRequiredMessage)
			return ErrOutdated
		}
		if env.Type == transport.MsgHostUnenrolled {
			// The control plane removed this host (deleted or unenrolled).
			// Stop with a message the operator sees, not a silent retry
			// loop into 401s.
			d.unenrolled = true
			d.Log.Error("host unenrolled — stopping", "err", ErrUnenrolled)
			fmt.Fprintln(os.Stderr,
				"pagnet: this host was unenrolled from the control plane — the daemon is stopping")
			return ErrUnenrolled
		}
		if env.Type == transport.MsgAgentResponse {
			d.deliverAgentResponse(env)
			continue
		}
		if env.Type == transport.MsgListDirs {
			// LIVE request/response (directory picker): answered directly,
			// not through the durable command queue (no ack, at-most-once).
			d.handleListDirs(conn, env)
			continue
		}
		if env.Type == transport.MsgLatestVersion {
			// LIVE (auto-update, P6): the advertised release version. The
			// handler only records it and (at most) spawns the update
			// goroutine — it never blocks the read loop on a download.
			d.handleLatestVersion(env)
			continue
		}
		if env.Type == transport.MsgNetworkCrypto {
			// LIVE (E2EE, plan §12): the network's crypto lifecycle state
			// (status + announced epoch + tenant id). The handler only
			// updates the in-memory cache — it never blocks the read loop.
			d.handleNetworkCrypto(env)
			continue
		}
		d.handleCommand(conn, env)
	}
}

// listDirsCap bounds how many subdirectories one listing returns, so a
// directory with thousands of entries cannot bloat the picker reply.
const listDirsCap = 500

// listDirs computes the directory listing for the picker: it validates the
// path against the daemon's allowed roots — the enforcement point, so a
// browse request can never read outside them — and returns its
// subdirectories (sorted, capped). It never reads file contents, only
// directory names. Errors are fixed strings (SEC-012: no internal detail
// to callers).
func (d *Daemon) listDirs(path string) (transport.ListDirsResultPayload, error) {
	res := transport.ListDirsResultPayload{Path: path}
	if !d.workspaceAllowed(path) {
		return res, errors.New("path is not under an allowed root")
	}
	resolved, err := pathResolved(path)
	if err != nil {
		return res, errors.New("cannot resolve path")
	}
	res.Path = resolved
	entries, err := os.ReadDir(resolved)
	if err != nil {
		// Not a directory, gone, or unreadable — report it, don't leak the
		// raw OS error.
		return res, errors.New("cannot read directory")
	}
	// Directories only (the picker selects a directory), sorted by name,
	// capped.
	out := make([]transport.DirEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		out = append(out, transport.DirEntry{Name: e.Name(), IsDir: true})
		if len(out) >= listDirsCap {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	res.Entries = out
	return res, nil
}

// handleListDirs answers a LIVE directory-listing request (the
// click-to-select directory picker) by computing the listing and replying
// with MsgListDirsResult correlated by RequestID.
func (d *Daemon) handleListDirs(conn *websocket.Conn, env transport.Envelope) {
	var p transport.ListDirsPayload
	if err := env.DecodePayload(&p); err != nil || p.RequestID == "" {
		return
	}
	res, err := d.listDirs(p.Path)
	res.RequestID = p.RequestID
	if err != nil {
		res.Error = err.Error()
		res.Entries = nil
	}
	_ = d.send(conn, transport.MsgListDirsResult, res)
}

// send wraps a payload in a versioned envelope and writes it. It prefers
// the CURRENT host connection over the one captured when the caller was
// queued: a turn runs for minutes, and if the connection drops and
// reconnects mid-turn, the turn events and acks must go out on the live
// connection — writing to the captured (dead) conn would silently lose
// the runtime audit trail.
func (d *Daemon) send(conn *websocket.Conn, msgType string, payload any) error {
	d.connMu.Lock()
	if cur := d.curConn; cur != nil {
		conn = cur
	}
	d.connMu.Unlock()
	env, err := transport.NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return d.write(conn, raw)
}

// write serializes a raw write to the host connection (single-writer rule).
// A nil conn (disconnected with no live connection yet) is a clean error —
// the caller's command stays un-acked and the server re-sends it.
func (d *Daemon) write(conn *websocket.Conn, raw []byte) error {
	if conn == nil {
		return errors.New("no host connection")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	// A stalled peer must not stall the command workers (or heartbeats /
	// the bridge relay): with an unbounded write, one clogged socket can
	// freeze a per-instance FIFO for minutes — a stop then lands past any
	// UI/CLI deadline. A bounded write fails fast instead; the failed ack
	// leaves the command un-acked, so the server's re-send takes over.
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return conn.WriteMessage(websocket.TextMessage, raw)
}

// sendAck reports the command outcome. The error is the WRITE error: a
// lost ack means the server never learns the outcome and will re-send.
func (d *Daemon) sendAck(conn *websocket.Conn, commandID, errMsg string) error {
	return d.send(conn, transport.MsgCommandAck, map[string]any{
		"commandId": commandID,
		"error":     errMsg,
	})
}

// sendAckResult is sendAck for commands that report a result payload in the
// ack (the E2EE crypto commands, plan §11.6/§11.7/§11.8). The `result` field
// is included only when non-nil and `error` only when non-empty — the two are
// mutually exclusive (a command either succeeds with a result or fails with
// an error). The error return is the WRITE error, as in sendAck.
func (d *Daemon) sendAckResult(conn *websocket.Conn, commandID string, errMsg string, result any) error {
	payload := map[string]any{"commandId": commandID}
	if errMsg != "" {
		payload["error"] = errMsg
	}
	if result != nil {
		payload["result"] = result
	}
	return d.send(conn, transport.MsgCommandAck, payload)
}

func (d *Daemon) sendHeartbeat(conn *websocket.Conn) {
	metrics := transport.HeartbeatPayload{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		DaemonVer: d.Version,
	}
	metrics.Metrics.CPUCount = runtime.NumCPU()
	if load, err := readLoadAvg(); err == nil {
		metrics.Metrics.CPULoad = load
	}
	// Host memory from /proc/meminfo (NOT the daemon's Go heap — the old
	// values reported the daemon process as the whole machine).
	if total, used, ok := readMemInfo(); ok {
		metrics.Metrics.MemTotalBytes = total
		metrics.Metrics.MemUsedBytes = used
	}
	if diskFree, err := readDiskFree(d.StateDir); err == nil {
		metrics.Metrics.DiskFreeBytes = diskFree
	}
	insts, err := d.state.ListInstances()
	if err == nil {
		for _, i := range insts {
			ist := transport.InstanceStatus{
				InstanceID: i.InstanceID,
				Status:     i.Status,
			}
			// §59: the running turn's process id (process-per-turn: set
			// only while a turn is in flight).
			if ad, ok := d.adapters[domain.RuntimeName(i.Runtime)]; ok {
				if p := ad.PID(i.InstanceID); p != nil {
					ist.PID = *p
				}
			}
			metrics.Instances = append(metrics.Instances, ist)
		}
	}
	_ = d.send(conn, transport.MsgHeartbeat, metrics)
}

// handleCommand enqueues one structured command from the control plane.
// Execution is per-instance serialized (FIFO) on a worker goroutine, so
// the WSS read loop is never blocked by a long turn — agent responses and
// other instances' commands must keep flowing while an agent works (real
// runtimes take minutes per turn). Idempotency: the CommandID is
// remembered in local SQLite (marked processed on success). A daemon crash
// mid-flight causes at most one re-execution, which every handler
// tolerates.
//
// Re-send dedup happens AT ENQUEUE, not at execution: while a command is
// un-acked the server re-dispatches it every 2 s, and per-instance FIFO
// queues would park those re-sends behind the original until a long turn
// finished — filling the queue and stalling the read loop. Claiming on
// enqueue means at most ONE copy of an un-acked command ever sits in the
// queue.
func (d *Daemon) handleCommand(conn *websocket.Conn, env transport.Envelope) {
	switch env.Type {
	case transport.MsgLaunchAgent:
		var p transport.LaunchAgentPayload
		if err := env.DecodePayload(&p); err != nil {
			// Structurally broken: the CommandID lives inside the payload,
			// so this copy cannot be acked and the server will re-send it.
			// Make that visible instead of dropping it silently.
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, p.InstanceID, p.CommandID, func() {
			d.guarded(conn, p.CommandID, func() error { return d.doLaunch(conn, p) })
		})

	case transport.MsgStopAgent:
		var p transport.StopAgentPayload
		if err := env.DecodePayload(&p); err != nil {
			// Structurally broken: the CommandID lives inside the payload,
			// so this copy cannot be acked and the server will re-send it.
			// Make that visible instead of dropping it silently.
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, p.InstanceID, p.CommandID, func() {
			d.guarded(conn, p.CommandID, func() error { return d.doStop(conn, p.InstanceID) })
		})

	case transport.MsgRestartAgent:
		var p transport.RestartAgentPayload
		if err := env.DecodePayload(&p); err != nil {
			// Structurally broken: the CommandID lives inside the payload,
			// so this copy cannot be acked and the server will re-send it.
			// Make that visible instead of dropping it silently.
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, p.InstanceID, p.CommandID, func() {
			d.guarded(conn, p.CommandID, func() error { return d.doRestart(conn, p.InstanceID) })
		})

	case transport.MsgWakeAgent:
		var p transport.WakeAgentPayload
		if err := env.DecodePayload(&p); err != nil || p.WakeRequestID == "" {
			d.Log.Warn("wake command undecodable or missing wakeRequestId", "type", env.Type,
				"err", err.Error(), "wakeRequestId", p.WakeRequestID)
			return
		}
		d.enqueueCommand(conn, p.InstanceID, p.WakeRequestID, func() {
			d.guarded(conn, p.WakeRequestID, func() error { return d.doWake(conn, p.InstanceID, p.Reason) })
		})

	case transport.MsgDeliverNetworkEvent:
		var p transport.NetworkEventPayload
		if err := env.DecodePayload(&p); err != nil {
			// Structurally broken: the CommandID lives inside the payload,
			// so this copy cannot be acked and the server will re-send it.
			// Make that visible instead of dropping it silently.
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, p.InstanceID, p.CommandID, func() {
			d.guarded(conn, p.CommandID, func() error { return d.doDeliver(conn, p) })
		})

	case transport.MsgAttachTerminal:
		var p transport.TerminalAttachPayload
		if err := env.DecodePayload(&p); err != nil {
			// Structurally broken: the CommandID lives inside the payload,
			// so this copy cannot be acked and the server will re-send it.
			// Make that visible instead of dropping it silently.
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, p.InstanceID, p.CommandID, func() {
			d.guarded(conn, p.CommandID, func() error { return d.doAttach(conn, p) })
		})

	case transport.MsgDetachTerminal:
		var p transport.DetachTerminalPayload
		if err := env.DecodePayload(&p); err != nil {
			// Structurally broken: the CommandID lives inside the payload,
			// so this copy cannot be acked and the server will re-send it.
			// Make that visible instead of dropping it silently.
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, p.InstanceID, p.CommandID, func() {
			d.guarded(conn, p.CommandID, func() error { return d.doDetach(conn, p) })
		})

	// LIVE terminal messages (PROTOCOL §3 "Live messages"): written
	// straight to the ordered live worker — no durable queue, no ack,
	// no busy-deferral. Keystroke semantics do not survive a Postgres
	// round-trip; a dropped key beats a duplicated or reordered one.
	case transport.MsgTerminalInput:
		var p transport.TerminalInputPayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("terminal input payload decode failed", "type", env.Type, "err", err)
			return
		}
		data, err := base64.StdEncoding.DecodeString(p.Data)
		if err != nil {
			d.Log.Warn("terminal input not base64", "instance", p.InstanceID, "err", err)
			return
		}
		d.terminal.submit(terminalLiveMsg{
			instance: p.InstanceID, session: p.SessionID, data: data,
		})

	case transport.MsgTerminalResize:
		var p transport.TerminalResizePayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("terminal resize payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.terminal.submit(terminalLiveMsg{
			isResize: true, instance: p.InstanceID, session: p.SessionID,
			cols: p.Cols, rows: p.Rows,
		})

	case transport.MsgTerminalStop:
		var p transport.TerminalStopPayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("terminal stop payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, p.InstanceID, p.CommandID, func() {
			d.guarded(conn, p.CommandID, func() error { return d.doTerminalStop(conn, p) })
		})

	case transport.MsgTerminalSnapshot:
		var p transport.TerminalSnapshotPayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("terminal snapshot payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, p.InstanceID, p.CommandID, func() {
			d.guarded(conn, p.CommandID, func() error { return d.doTerminalSnapshot(conn, p) })
		})

	case transport.MsgForgetInstance:
		var p transport.ForgetInstancePayload
		if err := env.DecodePayload(&p); err != nil {
			// Structurally broken: the CommandID lives inside the payload,
			// so this copy cannot be acked and the server will re-send it.
			// Make that visible instead of dropping it silently.
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, p.InstanceID, p.CommandID, func() {
			d.guarded(conn, p.CommandID, func() error { return d.doForget(conn, p.InstanceID) })
		})

	case transport.MsgRequestInventory:
		var p transport.RequestInventoryPayload
		if err := env.DecodePayload(&p); err != nil {
			// Structurally broken: the CommandID lives inside the payload,
			// so this copy cannot be acked and the server will re-send it.
			// Make that visible instead of dropping it silently.
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		// Read-only, but the git scan can take seconds — don't block the
		// read loop either. The command is acked AFTER the reply: an
		// un-acked inventory request stays pending server-side, and the
		// dispatcher re-send → reply → re-send cycle would hot-loop.
		commandID := p.CommandID
		go func() {
			d.sendInventory(conn)
			// Pre-fix inventory requests carry no commandId: there is
			// nothing to ack (the server-side row is cleaned up, not
			// self-healed, by design).
			if commandID != "" {
				d.sendAck(conn, commandID, "")
			}
		}()

	case transport.MsgUpdateRoots:
		var p transport.UpdateRootsPayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.guarded(conn, p.CommandID, func() error {
			d.SetAllowedRoots(p.Roots)
			d.SetRootsMode(p.Mode)
			d.Log.Info("allowed roots updated", "roots", p.Roots, "mode", p.Mode)
			// Re-report: the workspace set may have changed (a root was
			// added or removed), and the server persists the inventory's
			// roots as the host's source-of-truth list.
			d.sendInventory(conn)
			return nil
		})

	// E2EE / Private Network crypto commands (plan §11.6/§11.7/§11.8). All
	// are durable + idempotent and network-scoped: they enqueue on the
	// per-network queue key "crypto:<networkId>" so a network's activation /
	// enrollment legs run strictly in order (the WSS read loop only enqueues
	// — it never blocks on the local cryptography). The ack carries the leg's
	// result in the ack's `result` field (guardedResult).
	case transport.MsgCryptoActivate:
		var p transport.CryptoActivatePayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoActivate(p) })
		})

	case transport.MsgCryptoKeyPackage:
		var p transport.CryptoKeyPackagePayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoKeyPackage(p) })
		})

	case transport.MsgCryptoInstallKeyPackage:
		var p transport.CryptoInstallKeyPackagePayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoInstallKeyPackage(p) })
		})

	case transport.MsgCryptoChallenge:
		var p transport.CryptoChallengePayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoChallenge(p) })
		})

	case transport.MsgCryptoProve:
		var p transport.CryptoProvePayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoProve(p) })
		})

	case transport.MsgCryptoVerify:
		var p transport.CryptoVerifyPayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoVerify(p) })
		})

	case transport.MsgCryptoRotate:
		var p transport.CryptoRotatePayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoRotate(p) })
		})

	case transport.MsgCryptoShareEndpoint:
		var p transport.CryptoShareEndpointPayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoShareEndpoint(p) })
		})

	// Browser key-session commands (plan §13, p10). Same durable + idempotent,
	// network-scoped, per-network-queue posture as the other crypto commands
	// (the WSS read loop only enqueues — it never blocks on local
	// cryptography). The ack carries the result in the ack's `result` field
	// (guardedResult); a gone session acks the crypto_session_gone sentinel
	// (the control plane maps it to 410).
	case transport.MsgCryptoSessionStart:
		var p transport.CryptoSessionStartPayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoSessionStart(p) })
		})

	case transport.MsgCryptoUnwrapCek:
		var p transport.CryptoUnwrapCekPayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoUnwrapCek(p) })
		})

	case transport.MsgCryptoWrapCek:
		var p transport.CryptoWrapCekPayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoWrapCek(p) })
		})

	case transport.MsgCryptoSessionEnd:
		var p transport.CryptoSessionEndPayload
		if err := env.DecodePayload(&p); err != nil {
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, "crypto:"+p.NetworkID, p.CommandID, func() {
			d.guardedResult(conn, p.CommandID, func() (any, error) { return d.doCryptoSessionEnd(p) })
		})

	default:
		d.Log.Warn("unknown command type", "type", env.Type)
	}
}

// enqueueCommand applies the re-send dedup gate and enqueues job for
// instanceID:
//   - already processed (persisted): acked here, not enqueued;
//   - already claimed (queued or in flight): dropped silently — the
//     original copy owns the outcome;
//   - new: claimed, then enqueued. A queue-overflow drop releases the
//     claim again: the command is un-acked, so the server's re-send must
//     be the one that runs.
func (d *Daemon) enqueueCommand(conn *websocket.Conn, instanceID, commandID string, job func()) {
	if commandID != "" {
		if d.alreadyProcessed(commandID) {
			d.reAckProcessed(conn, commandID)
			return
		}
		d.seenMu.Lock()
		if _, dup := d.seen[commandID]; dup {
			d.seenMu.Unlock()
			d.Log.Debug("duplicate command dropped at enqueue", "command", commandID)
			return
		}
		d.seen[commandID] = time.Now()
		// Amortized eviction: processed commands keep their entry as a
		// tombstone (fast re-send ack); without a sweep the map grows for
		// the daemon's whole life.
		if len(d.seen) > 1024 {
			cutoff := time.Now().Add(-time.Hour)
			for id, claimed := range d.seen {
				if claimed.Before(cutoff) {
					delete(d.seen, id)
				}
			}
		}
		d.seenMu.Unlock()
	}
	if !d.enqueueInstance(instanceID, job) {
		d.releaseClaim(commandID)
	}
}

// reAckProcessed re-acks an already-processed command (a server re-send after
// a lost ack), echoing the STORED result verbatim (F8). A command that carried
// no result (non-crypto) gets the plain empty ack; a crypto command re-acks
// its original result so a lost ack + re-send does not yield a zero-value
// result that the server would misread (e.g. an empty activate result would
// look like a failed self-test and revert a successful activation).
func (d *Daemon) reAckProcessed(conn *websocket.Conn, commandID string) {
	if result, ok := d.state.GetProcessedResult(commandID); ok && result != "" {
		if aerr := d.sendAckResult(conn, commandID, "", json.RawMessage(result)); aerr != nil {
			d.Log.Warn("re-ack (stored result) lost; server re-send will re-ack", "command", commandID, "err", aerr)
		}
		return
	}
	if aerr := d.sendAck(conn, commandID, ""); aerr != nil {
		d.Log.Warn("re-ack lost; server re-send will re-ack", "command", commandID, "err", aerr)
	}
}

// guarded runs an already-claimed command (claim taken in enqueueCommand)
// and acks it. A deferred outcome (ErrDeferred) is NOT acked — and it
// RELEASES the claim: the command stays queued server-side and the
// dispatcher's re-send is the one that must run (§32: one active turn per
// instance, multiple inbound items queue durably). A terminal FAILURE
// keeps its claim (the failed command is never re-run; recovery is a NEW
// command: the coordinator's schedule_retry wake, §45).
func (d *Daemon) guarded(conn *websocket.Conn, commandID string, fn func() error) {
	err := fn()
	if errors.Is(err, ErrDeferred) {
		d.releaseClaim(commandID)
		d.Log.Debug("command deferred (stays queued)", "command", commandID)
		return
	}
	if errors.Is(err, context.Canceled) {
		// Daemon shutdown interrupted the command. Do NOT ack it as a
		// failure: the command must stay pending so the server's re-send
		// after reconnect is the one that runs (or re-acks).
		return
	}
	if err != nil {
		if aerr := d.sendAck(conn, commandID, err.Error()); aerr != nil {
			d.Log.Warn("failure ack lost; server re-send will re-fail it", "command", commandID, "err", aerr)
		}
		return // claim kept: terminal failure, re-sends are stale
	}
	if commandID != "" {
		_ = d.state.MarkProcessed(commandID, "", nil)
	}
	if aerr := d.sendAck(conn, commandID, ""); aerr != nil {
		// The outcome never reaches the server. Release the claim so the
		// re-send is the copy that finishes the protocol: it either re-acks
		// via alreadyProcessed (MarkProcessed succeeded) or re-runs (it
		// did not) — both safe, every handler tolerates re-execution.
		d.Log.Warn("ack lost; releasing claim for server re-send", "command", commandID, "err", aerr)
		d.releaseClaim(commandID)
	}
}

// guardedResult is guarded for commands that report a result payload in the
// ack (the E2EE crypto commands, plan §11.6/§11.7/§11.8). It has the SAME
// deferred / canceled / failure semantics as guarded, except a clean success
// acks the result (via sendAckResult) instead of an empty ack. The crypto
// commands are fast (local cryptography, no runtime turn), so they are
// enqueued on a per-network queue key (see handleCommand) and never defer.
func (d *Daemon) guardedResult(conn *websocket.Conn, commandID string, fn func() (any, error)) {
	result, err := fn()
	if errors.Is(err, ErrDeferred) {
		d.releaseClaim(commandID)
		d.Log.Debug("command deferred (stays queued)", "command", commandID)
		return
	}
	if errors.Is(err, context.Canceled) {
		// Daemon shutdown interrupted the command. Do NOT ack it as a
		// failure: the command must stay pending so the server's re-send
		// after reconnect is the one that runs (or re-acks).
		return
	}
	if err != nil {
		if aerr := d.sendAckResult(conn, commandID, err.Error(), nil); aerr != nil {
			d.Log.Warn("failure ack lost; server re-send will re-fail it", "command", commandID, "err", aerr)
		}
		return // claim kept: terminal failure, re-sends are stale
	}
	// Persist the ack result with the processed-command record so a re-send
	// of this command (lost ack) re-acks the SAME result verbatim (F8). A
	// nil result (e.g. install/verify legs) stores "" — the re-ack is then
	// the plain empty ack, which is correct for a result-less command.
	var resultJSON []byte
	if result != nil {
		if b, err := json.Marshal(result); err == nil {
			resultJSON = b
		}
	}
	if commandID != "" {
		_ = d.state.MarkProcessed(commandID, "", resultJSON)
	}
	if aerr := d.sendAckResult(conn, commandID, "", result); aerr != nil {
		// The outcome never reaches the server. Release the claim so the
		// re-send is the copy that finishes the protocol (both safe: the
		// crypto handlers are idempotent).
		d.Log.Warn("ack lost; releasing claim for server re-send", "command", commandID, "err", aerr)
		d.releaseClaim(commandID)
	}
}

// releaseClaim drops the enqueue-time claim for commandID ("" is a no-op).
func (d *Daemon) releaseClaim(commandID string) {
	if commandID == "" {
		return
	}
	d.seenMu.Lock()
	delete(d.seen, commandID)
	d.seenMu.Unlock()
}

func (d *Daemon) alreadyProcessed(commandID string) bool {
	if commandID == "" {
		return false
	}
	ok, err := d.state.IsProcessed(commandID)
	return err == nil && ok
}

// maintainState bounds the local dedup state (spec §91 "bounded period"):
// evict in-memory claims older than seenTTL and prune the persistent
// processed-command set to processedRetention.
func (d *Daemon) maintainState() {
	d.seenMu.Lock()
	cut := time.Now().Add(-seenTTL)
	for id, at := range d.seen {
		if at.Before(cut) {
			delete(d.seen, id)
		}
	}
	d.seenMu.Unlock()
	if err := d.state.PruneProcessed(time.Now().UTC().Add(-processedRetention)); err != nil {
		d.Log.Warn("prune processed_commands", "err", err)
	}
}

// allowedRoots returns a snapshot of the current allowed roots (they are
// replaced at runtime by host.update_roots — the server-side list, set via
// PUT /hosts/{id}/roots, is the source of truth).
func (d *Daemon) allowedRoots() []string {
	d.rootsMu.RLock()
	defer d.rootsMu.RUnlock()
	return append([]string(nil), d.AllowedRoots...)
}

// SetAllowedRoots atomically replaces the allowed roots (host.update_roots).
func (d *Daemon) SetAllowedRoots(roots []string) {
	d.rootsMu.Lock()
	d.AllowedRoots = append([]string(nil), roots...)
	d.rootsMu.Unlock()
}

// rootsMode returns the current roots enforcement mode (replaced at
// runtime by host.update_roots — the server-side mode is the source of
// truth). Empty = allow_all (the default).
func (d *Daemon) rootsMode() string {
	d.rootsMu.RLock()
	defer d.rootsMu.RUnlock()
	return d.RootsMode
}

// SetRootsMode atomically replaces the roots enforcement mode
// (host.update_roots).
func (d *Daemon) SetRootsMode(mode string) {
	d.rootsMu.Lock()
	d.RootsMode = mode
	d.rootsMu.Unlock()
}

// workspaceAllowed validates a path against the host's roots policy
// (resolved absolute match). allow_all (the default, or an empty mode)
// allows any absolute, existing path; allow_list confines to the allowed
// roots (the path must sit under one of them — the existing enforcement).
func (d *Daemon) workspaceAllowed(path string) bool {
	if path == "" {
		return false
	}
	clean, err := pathResolved(path)
	if err != nil {
		return false
	}
	if d.rootsMode() != domain.RootsModeAllowList {
		// allow_all (default): any absolute, existing path (pathResolved
		// already returns an absolute path).
		if _, err := os.Stat(clean); err != nil {
			return false
		}
		return true
	}
	// allow_list: the path must sit under one of the allowed roots.
	for _, root := range d.allowedRoots() {
		rc, err := pathResolved(root)
		if err != nil {
			continue
		}
		if clean == rc || strings.HasPrefix(clean, rc+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// applyCWD resolves a launch CWD override (a subdirectory of the
// workspace the agent should run in) against the resolved checkout. The
// CWD must be under an allowed root AND inside the selected workspace
// root (it cannot escape to a sibling or parent). The returned path is
// the subdir applied to the checkout, so it stays correct when the
// checkout is an automatic worktree rather than the main workspace.
func (d *Daemon) applyCWD(workspaceRoot, checkout, cwd string) (string, error) {
	if !d.workspaceAllowed(cwd) {
		return "", fmt.Errorf("cwd %q is not under an allowed root", cwd)
	}
	rel, err := filepath.Rel(workspaceRoot, cwd)
	if err != nil || filepath.IsAbs(rel) || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("cwd %q is not inside workspace %q", cwd, workspaceRoot)
	}
	return filepath.Join(checkout, rel), nil
}

// pathResolved is Abs+Clean plus symlink resolution (spec §11: an allowed
// root must not be bypassed by a symlink pointing outside it). The
// workspace may not exist yet, so the LONGEST EXISTING PREFIX is resolved
// (EvalSymlinks fails on missing paths) — a symlink component anywhere in
// an existing prefix is still resolved.
func pathResolved(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	for cur := abs; ; {
		if ev, err := filepath.EvalSymlinks(cur); err == nil {
			rest, _ := filepath.Rel(cur, abs)
			return filepath.Clean(filepath.Join(ev, rest)), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		cur = parent
	}
}

func filepathAbs(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// --- command implementations -------------------------------------------------

func (d *Daemon) doLaunch(conn *websocket.Conn, p transport.LaunchAgentPayload) error {
	// Boundary check (SEC-407): the instance id is server-provided and
	// becomes filesystem path components (representatives/, sessions/,
	// contracts/, worktrees/). A non-UUID value — from a buggy or
	// compromised control plane, or a spoofer holding a stolen host
	// credential — must not steer paths out of the daemon state dir.
	if _, err := domain.ParseID(p.InstanceID); err != nil {
		return fmt.Errorf("launch command carries an invalid instance id")
	}
	rn := domain.CanonicalRuntime(p.Runtime)
	if rn == "" {
		// No runtime requested: pick the first available REAL runtime.
		// The fake runtime is debug-only and is never auto-selected, so a
		// production daemon (no fake) still launches on its real runtimes
		// instead of hard-failing on an empty default. Availability is
		// the same check the explicit-runtime path below uses (an
		// adapter present AND Available, or a registered session driver
		// — qwen-code is session-driven since Wave B).
		for _, name := range []domain.RuntimeName{
			domain.RuntimeQwenCode, domain.RuntimeClaudeCode, domain.RuntimeOpenCode,
		} {
			if d.runtimeAvailable(name) {
				rn = name
				break
			}
		}
		if rn == "" {
			return fmt.Errorf("no runtime available on this host (install qwen, claude, or opencode)")
		}
	}
	// The runtime must be drivable on this host (an adapter OR a registered
	// session driver) and installed. A process-per-turn runtime is checked
	// via its adapter; a session-driven runtime (Phase 1: fake-persistent)
	// via its driver. The endpoint for a session-driven runtime launches
	// LAZILY on the first turn (EnsureActive), not at launch time — launch
	// only records/accepts the instance.
	if !d.runtimeSupported(rn) {
		return fmt.Errorf("runtime %q not supported on this host", p.Runtime)
	}
	if !d.runtimeAvailable(rn) {
		// Fail the launch now, not at the first turn: a host without the
		// runtime CLI must not ack a clean launch and idle until work
		// arrives.
		return fmt.Errorf("runtime %q is not installed on this host", p.Runtime)
	}
	access := p.Access
	if access != domain.AccessReadOnly {
		access = domain.AccessReadWrite
	}
	var (
		wsPath   string
		lock     *sync.Mutex
		worktree bool
	)
	if p.WorkspacePath == "" {
		// Representative (§37/§72): no git workspace; an pagnet-managed
		// stable runtime directory inside the daemon state.
		wsPath = filepath.Join(d.StateDir, "representatives", p.InstanceID)
		if err := os.MkdirAll(wsPath, 0o700); err != nil {
			return err
		}
	} else {
		if !d.workspaceAllowed(p.WorkspacePath) {
			return fmt.Errorf("workspace %q is not under an allowed root", p.WorkspacePath)
		}
		// §29 race: the "first RW agent keeps the checkout" decision and
		// the instance registration below must be atomic per repository —
		// launches for different instances run on parallel per-instance
		// queues, so without this lock two near-simultaneous RW launches
		// could both read "no other RW agent" and both keep the main
		// checkout.
		lock = d.repoLock(d.workspaceLockKey(p.WorkspacePath))
		lock.Lock()
		// §29: a second read/write agent on the same repository is
		// isolated into an automatic git worktree (fail clearly if that
		// is unsafe).
		var err error
		wsPath, err = d.resolveWorkspace(p, access)
		if err != nil {
			lock.Unlock()
			return err
		}
		worktree = wsPath != p.WorkspacePath
		// CWD override: run the agent in a subdirectory of the workspace
		// (it sees only from there forward). The subdir is applied relative
		// to the resolved checkout, so it stays correct when the checkout
		// is an automatic worktree rather than the main workspace.
		if p.CWD != "" {
			wsPath, err = d.applyCWD(p.WorkspacePath, wsPath, p.CWD)
			if err != nil {
				lock.Unlock()
				return err
			}
		}
	}
	// Launch registers the instance as idle: process-per-turn means no
	// process runs until work arrives (the runtime is the turn runner).
	kind := p.Kind
	if kind == "" {
		kind = "worker"
	}
	row := InstanceRow{
		InstanceID:       p.InstanceID,
		DefinitionID:     p.DefinitionID,
		Runtime:          string(rn),
		Workspace:        wsPath,
		Profile:          p.Profile,
		Status:           "idle",
		Access:           access,
		AgentName:        p.AgentName,
		NetworkID:        p.NetworkID,
		Kind:             kind,
		Model:            p.Model,
		Instruction:      p.AgentMD,
		AgentPrincipalID: p.AgentPrincipalID,
	}
	// Standing instruction (AGENT.md): materialize it in the daemon state
	// dir (NEVER the workspace) and record its path on the row so it
	// persists across turns. claude receives the path via
	// --append-system-prompt-file; other runtimes have the text appended
	// to a fresh session's first turn (turnSpecFor).
	if p.AgentMD != "" {
		path, _, err := d.writeAgentMD(&row)
		if err != nil {
			if lock != nil {
				lock.Unlock()
			}
			return err
		}
		row.AgentMDPath = path
	}
	if err := d.state.UpsertInstance(row); err != nil {
		if lock != nil {
			lock.Unlock()
		}
		return err
	}
	if lock != nil {
		lock.Unlock()
	}
	msg := "agent launched (idle, process-per-turn)"
	if worktree {
		msg = "agent launched (git worktree isolation, process-per-turn)"
	}
	d.Log.Info(msg,
		"instance", p.InstanceID, "runtime", rn, "workspace", wsPath, "access", access)
	_ = d.send(conn, transport.MsgAgentStarted, map[string]any{"instanceId": p.InstanceID})
	// V2: report the managed agent's endpoint liveness (online — it is now
	// idle and can accept work), carrying the agent principal + declared
	// capabilities (the control plane derives the PrincipalEndpoint row).
	d.reportEndpointStatus(conn, p.InstanceID)

	// North-star §15: a launch has an initial mission. The daemon runs it
	// as the FIRST turn of a fresh instance — the adapter translates it
	// into the runtime's mechanism (first prompt / session creation). A
	// resumed session never receives it again (its context already has it).
	if p.Mission != "" {
		row, ok, err := d.state.GetInstance(p.InstanceID)
		if err != nil {
			return err
		}
		if ok && row.SessionID == "" {
			d.Log.Info("mission first turn", "instance", p.InstanceID, "chars", len(p.Mission))
			return d.runTurn(conn, d.turnSpecFor(row, false, p.Mission, "mission"))
		}
	}
	return nil
}

// repoLock returns the per-repository serialization lock (F4).
func (d *Daemon) repoLock(key string) *sync.Mutex {
	d.repoLockMu.Lock()
	defer d.repoLockMu.Unlock()
	l, ok := d.repoLocks[key]
	if !ok {
		l = &sync.Mutex{}
		d.repoLocks[key] = l
	}
	return l
}

// workspaceLockKey is the serialization identity of a workspace: the
// repository's common dir when it is a git repo (checkout + all of its
// worktrees share it), the absolute path otherwise.
func (d *Daemon) workspaceLockKey(path string) string {
	if common, err := d.repoCommonDir(path); err == nil {
		return common
	}
	abs, _ := filepathAbs(path)
	return abs
}

// sessionDriverFor returns the session driver for the instance's runtime
// (nil when the runtime is NOT session-driven — i.e. the legacy
// process-per-turn path). The Phase-1 persistent endpoint lives in the
// session core (d.sessions), not the adapter map, so stop/forget/restart
// must drive it through the Manager. The same condition as the runTurn
// branch: the new code is guarded so the legacy path stays byte-identical.
func (d *Daemon) sessionDriverFor(row *InstanceRow) session.Driver {
	if d.sessions == nil {
		return nil
	}
	return d.sessions.DriverFor(domain.RuntimeName(row.Runtime))
}

// runtimeSupported reports whether rn is drivable on this host: a
// process-per-turn runtime via its adapter, or a session-driven runtime
// (qwen-code since Wave B; fake-persistent in debug) via a registered
// session driver.
func (d *Daemon) runtimeSupported(rn domain.RuntimeName) bool {
	if _, ok := d.adapters[rn]; ok {
		return true
	}
	return d.sessions != nil && d.sessions.DriverFor(rn) != nil
}

// runtimeAvailable reports whether rn is installed and usable: a
// process-per-turn runtime via its adapter's availability check, a
// session-driven runtime (qwen-code, fake-persistent) via its driver. A
// session driver without an availability check is assumed available.
func (d *Daemon) runtimeAvailable(rn domain.RuntimeName) bool {
	if ad, ok := d.adapters[rn]; ok {
		return ad.Available()
	}
	if d.sessions != nil {
		if drv := d.sessions.DriverFor(rn); drv != nil {
			if pf, ok := drv.(*agentruntime.PersistentFake); ok {
				return pf.Available()
			}
			if qp, ok := drv.(*agentruntime.QwenPersistent); ok {
				return qp.Available()
			}
			return true
		}
	}
	return false
}

func (d *Daemon) doStop(conn *websocket.Conn, instanceID string) error {
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unknown instance %s", instanceID)
	}
	d.terminal.stop(instanceID) // a stopped agent has no live terminal
	if ad, ok := d.adapters[domain.RuntimeName(row.Runtime)]; ok {
		_ = ad.Stop(instanceID)
	}
	// Phase 1 (runtime-lifecycle refactor): a persistent runtime's endpoint
	// lives in the session core, not the adapter map. Stop it (TERM →
	// grace → KILL via the supervisor) before the "stopped" bookkeeping.
	// The driver's Stop is synchronous (it waits for the endpoint to be
	// reaped), so no separate WaitForStop is needed for it.
	if d.sessionDriverFor(row) != nil {
		_ = d.sessions.Stop(instanceID)
	}
	// Wait for the reap (external audit F-004): Stop is async, and a
	// Stop→immediate-Start that does not wait would race the reap and hit
	// ErrInstanceBusy while the old turn is still registered. Bounded by
	// the TERM→grace→KILL sequence (well under the timeout).
	if !d.sup.WaitForStop(instanceID, 10*time.Second) {
		d.Log.Warn("stop: turn not fully reaped within the wait window", "instance", instanceID)
	}
	if err := d.state.SetInstanceStatus(instanceID, "stopped", ""); err != nil {
		return err
	}
	_ = d.send(conn, transport.MsgAgentStopped, map[string]any{
		"instanceId": instanceID, "reason": "stopped_by_command",
	})
	d.reportEndpointStatus(conn, instanceID) // offline
	d.finishQueue(instanceID)
	return nil
}

// doForget finalizes a server-side instance deletion: stops any process,
// removes the isolated worktree (the branch is kept — the work product
// stays reachable), and drops the local row. The instance is gone for
// good: no restart is possible, so there is nothing to preserve.
func (d *Daemon) doForget(conn *websocket.Conn, instanceID string) error {
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil {
		return err
	}
	if ok {
		d.terminal.stop(instanceID) // the forgotten instance keeps no process
		if ad, ok := d.adapters[domain.RuntimeName(row.Runtime)]; ok {
			_ = ad.Stop(instanceID)
		}
		// Phase 1: stop the persistent endpoint AND drop the session state
		// from the Manager. The instance is gone for good — there is
		// nothing to preserve. Dropping the session (and its prompt lock)
		// is what bounds the Manager's maps: without it, every forgotten
		// instance would leak a session entry and a lock forever.
		if d.sessionDriverFor(row) != nil {
			_ = d.sessions.Stop(instanceID)
			d.sessions.Forget(instanceID)
		}
		d.removeWorktree(row)
	}
	if err := d.state.DeleteInstance(instanceID); err != nil {
		return err
	}
	d.finishQueue(instanceID)
	d.Log.Info("instance forgotten", "instance", instanceID)
	return nil
}

func (d *Daemon) doRestart(conn *websocket.Conn, instanceID string) error {
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unknown instance %s", instanceID)
	}
	d.terminal.stop(instanceID) // cold start: the old PTY session dies with it
	if ad, ok := d.adapters[domain.RuntimeName(row.Runtime)]; ok {
		_ = ad.Stop(instanceID)
	}
	// Phase 1: stop the persistent endpoint AND clear the in-memory session
	// so the next turn starts FRESH (a new session id) — the explicit
	// "start fresh" semantics. Stop must precede Forget (Stop resolves the
	// driver through the session).
	if d.sessionDriverFor(row) != nil {
		_ = d.sessions.Stop(instanceID)
		d.sessions.Forget(instanceID)
	}
	// Cold start: the prior session is NOT resumed on restart — the local
	// session reference is cleared so the next turn starts fresh (this is
	// the explicit "Start fresh session" path after a lost session, §74).
	if err := d.state.SetInstanceSession(instanceID, ""); err != nil {
		return err
	}
	if err := d.state.SetInstanceStatus(instanceID, "idle", ""); err != nil {
		return err
	}
	_ = d.send(conn, transport.MsgAgentStarted, map[string]any{"instanceId": instanceID})
	d.reportEndpointStatus(conn, instanceID) // back online (idle)
	return nil
}

func (d *Daemon) doWake(conn *websocket.Conn, instanceID, reason string) error {
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil {
		return err
	}
	if !ok {
		// Not known locally yet (e.g. launched while we were offline). The
		// server keeps the wake pending; re-evaluated on next launch.
		return fmt.Errorf("unknown instance %s (wake deferred)", instanceID)
	}
	if row.Status == "blocked" || row.Status == "failed" || row.Status == "stopped" {
		// §74/§88: a blocked/failed instance must not auto-resume or start
		// a new session — only an explicit restart (human decision) does.
		return fmt.Errorf("instance %s is %s; explicit restart required", instanceID, row.Status)
	}
	if d.busy(instanceID) {
		d.Log.Info("instance busy; wake coalesced", "instance", instanceID)
		return nil
	}
	// Session-oriented wake (Phase 2): a session-driven instance that is
	// ALREADY LIVE (a persistent endpoint is up — idle or a turn in flight)
	// has nothing to wake: the session is already active, so the wake is a
	// NO-OP (plan Phase 2: "Wake of an active/idle instance = no-op (already
	// live)"). Only a HIBERNATED session-driven instance (endpoint stopped,
	// session preserved) is woken: the wake turn's EnsureActive re-activates
	// the endpoint, resuming the stored native session. (d.busy above only
	// tracks the legacy activeTurns map, which the persistent path does not
	// set, so the session's own liveness is the authoritative check here.)
	if d.sessionDriverFor(row) != nil {
		if sess := d.sessions.GetSession(instanceID); sess != nil && sess.State.Live() {
			d.Log.Info("instance already live; wake is a no-op", "instance", instanceID)
			return nil
		}
	}
	resume := row.SessionID != ""
	input := "You were woken. Reason: " + reason
	d.Log.Info("wake turn", "instance", instanceID, "reason", reason, "resume", resume)
	return d.runTurn(conn, d.turnSpecFor(row, resume, input, "wake"))
}

// hibernateInstance is the SESSION-ORIENTED hibernate for a session-driven
// instance (runtime-lifecycle refactor, Phase 2): it stops the persistent
// endpoint (TERM → grace → KILL via the supervisor; the runtime saves its
// native session state on SIGTERM — that is how the native session
// survives) and marks the instance hibernated with the session PRESERVED
// (invariant F: the native id + materialised flag remain in the Manager —
// stopping the endpoint must not delete the session).
//
// Trigger semantics — mirrored from the legacy process-per-turn path.
// Investigation of the legacy daemon: there is NO idle timer and NO
// explicit server hibernate command. Legacy hibernation is a state
// transition that happens exactly when the instance has no work in flight
// AND nothing keeps it awake — the turn process exits at turn end
// (process exits ⇒ hibernated), the last attach closes with no PTY
// (doDetach), or the terminal is stopped (doTerminalStop) — every one of
// those sites is gated on status idle + not busy + no attach/PTY, and
// every one emits the same wire shape (status hibernated +
// host.agent_hibernated {sessionId, reason}). This operation uses the
// SAME conditions and the SAME wire shape; only the mechanism differs —
// the endpoint is stopped instead of a process exit being observed. The
// legacy call sites (doDetach / doTerminalStop) route session-driven
// instances here; the turn-end site does not apply (the persistent
// endpoint does not exit at turn end — that is the point of the
// persistent model, plan §41).
//
// Never hibernate (plan §20 + addendum):
//   - a busy session (turn in flight) — the status gate below (only
//     "idle" is hibernatable) plus the Manager's own StateBusy refusal;
//   - a session with an unresolved interaction — the pending-interaction
//     gate below plus the Manager's own refusal;
//   - an actively attached terminal — the keep-awake gate below. Phase 3
//     (terminal session unification) landed the attached-terminal surface
//     for session-driven instances: a human attaches to the ENDPOINT'S OWN
//     TUI PTY (a terminal VIEW), and keep-awake is the HUMAN attach
//     (d.attached) — NOT the view itself (A6: terminal.active excludes
//     views, so a detached view does not block hibernation of an idle
//     endpoint).
//
// It is a no-op (nil) when the instance is kept awake by an attach/PTY.
func (d *Daemon) hibernateInstance(conn *websocket.Conn, instanceID, reason string) error {
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unknown instance %s", instanceID)
	}
	// Only an IDLE instance is hibernatable: working = a turn is in flight
	// (a busy session is never hibernated), blocked/failed/stopped are not
	// hibernatable at all. Mirrors the legacy gate (the legacy call sites
	// hibernate only when status == idle).
	if row.Status != "idle" {
		return fmt.Errorf("instance %s is %s; not hibernatable", instanceID, row.Status)
	}
	// Never hibernate underneath an attached user or a live terminal (§35
	// keep-awake; plan §20 "actively attached human terminal").
	if d.attached(instanceID) || d.terminal.active(instanceID) {
		d.Log.Info("hibernate deferred: instance kept awake (attach/pty active)",
			"instance", instanceID)
		return nil
	}
	// Never hibernate a session with an unresolved interaction (plan §20).
	// The Manager refuses too (defense in depth).
	if d.sessions.HasPendingInteraction(instanceID) {
		return fmt.Errorf("instance %s has an unresolved interaction; not hibernatable", instanceID)
	}
	// Stop the endpoint, PRESERVING the session (invariant F). The driver's
	// hibernate is synchronous: it runs the TERM → grace → KILL sequence
	// and waits for the endpoint to be reaped.
	if sess := d.sessions.GetSession(instanceID); sess != nil {
		if err := d.sessions.Hibernate(context.Background(), sess); err != nil {
			return err
		}
	}
	_ = d.state.SetInstanceStatus(instanceID, "hibernated", row.SessionID)
	_ = d.send(conn, transport.MsgAgentHibernated, map[string]any{
		"instanceId": instanceID, "sessionId": row.SessionID,
		"reason": reason,
	})
	d.reportEndpointStatus(conn, instanceID) // offline (hibernated)
	d.Log.Info("instance hibernated (persistent endpoint stopped, session preserved)",
		"instance", instanceID, "session", row.SessionID, "reason", reason)
	return nil
}

func (d *Daemon) doDeliver(conn *websocket.Conn, p transport.NetworkEventPayload) error {
	row, ok, err := d.state.GetInstance(p.InstanceID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unknown instance %s (work stays queued server-side)", p.InstanceID)
	}
	if row.Status == "blocked" || row.Status == "failed" || row.Status == "stopped" {
		// §74/§88: work stays durable server-side; no turn, no new session.
		return fmt.Errorf("instance %s is %s; delivery refused until explicit restart", p.InstanceID, row.Status)
	}
	if d.busy(p.InstanceID) {
		// maxConcurrentTurns=1: the delivery stays queued server-side
		// (re-sent by the dispatcher) until the current turn finishes.
		d.Log.Debug("instance busy; delivery stays queued", "instance", p.InstanceID)
		return ErrDeferred
	}
	// V2 event delivery (deterministic TRIGGER TURN, plan §46): a delivery
	// that carries the v2 event identity (EventID / EventType) is an event,
	// NOT a legacy message/task/notice. It routes to the trigger-turn path:
	// the turn input carries ONLY the event type + trusted routing metadata
	// (eventID / deliveryID / network) + the instruction to fetch the
	// payload via the network_event_get MCP tool. The RAW payload is DATA,
	// never inlined into the prompt (prompt-injection-safe).
	if p.EventID != "" || p.EventType != "" {
		return d.doDeliverEvent(conn, row, p)
	}

	kind := p.Kind
	if kind == "" {
		kind = "notice"
	}
	// The delivery's network: the instance's (workers) or the payload's
	// (representatives are network-NULL on the row but carry it on the
	// payload).
	netID := row.NetworkID
	if netID == "" {
		netID = p.NetworkID
	}
	// E2EE (plan §12) + plan D6 (always-encrypted): an encrypted delivery
	// carries the protected text as an envelope (ciphertext) + the verbatim
	// AAD; decrypt it JUST BEFORE the turn input so the plaintext never
	// crossed the cloud boundary. A decrypt failure fails the turn clean
	// (the work stays durable server-side for re-delivery) — never a
	// silent plaintext fallback.
	if p.Envelope != nil && p.AAD != nil {
		plain, err := d.decryptProtected(netID, *p.Envelope, *p.AAD)
		if err != nil {
			return fmt.Errorf("decrypt delivery: %w", err)
		}
		p.Body = plain
		// For tasks the acceptance criteria ride inside the envelope (the
		// plaintext already contains them), so the separate criteria list is
		// left empty to avoid double-rendering.
		p.AcceptanceCriteria = nil
	} else if netID != "" && deliveryHasContent(p) {
		// D6: every network is ALWAYS encrypted — there is no plaintext
		// path. A network-bound delivery carrying content WITHOUT an
		// envelope is refused: the content must be encrypted server-side
		// before it is delivered. Failing closed keeps the work durable
		// server-side (no plaintext ever reaches the agent).
		return fmt.Errorf("network %s is always encrypted: delivery for %s carried content without an envelope (no plaintext path)",
			netID, p.InstanceID)
	}
	// The turn input is a self-describing XML envelope (contract.go):
	// routing attributes + the immediate action for this delivery kind,
	// so the agent always knows this is a network message and HOW to
	// answer it — not just the rendered text.
	input := deliveryInput(row, p)
	d.Log.Info("delivery turn", "instance", p.InstanceID, "kind", kind)
	return d.runTurn(conn, d.turnSpecFor(row, row.SessionID != "", input, kind))
}

// deliveryHasContent reports whether a (pre-decryption) legacy delivery
// carries protected content that MUST be encrypted on an always-encrypted
// network: a non-empty body, acceptance criteria, or a task reference. An
// empty envelope-less delivery (a no-op notice) has no content to protect.
func deliveryHasContent(p transport.NetworkEventPayload) bool {
	return strings.TrimSpace(p.Body) != "" || len(p.AcceptanceCriteria) > 0 || p.TaskID != ""
}

func dashOr(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (d *Daemon) busy(instanceID string) bool {
	d.turnMu.Lock()
	defer d.turnMu.Unlock()
	return d.activeTurns[instanceID]
}

func (d *Daemon) turnSpecFor(row *InstanceRow, resume bool, input, kind string) agentruntime.TurnSpec {
	contractPath, contractText, _ := d.writeContract(row)
	// Standing instruction (AGENT.md): re-rendered per turn (idempotent),
	// mirroring the coordination contract. claude receives the path via
	// --append-system-prompt-file (every turn); other runtimes have the
	// text appended to a fresh session's first turn (they have no such
	// flag).
	agentMDPath, agentMDText, _ := d.writeAgentMD(row)
	if !resume {
		// §23/§24: the coordination contract is standing instructions and
		// must reach the model. A fresh session has no prior context, so
		// it rides with the first turn; a resumed session already carries
		// it in its context.
		input = input + "\n\n" + contractText
		// The standing instruction reaches non-claude runtimes the same
		// way: appended to a fresh session's first turn. claude gets it
		// natively via --append-system-prompt-file (spec.AgentMDPath), so
		// it is NOT appended here (no double delivery).
		if agentMDText != "" && row.Runtime != string(domain.RuntimeClaudeCode) {
			input = input + "\n\n" + agentMDText
		}
	}
	return agentruntime.TurnSpec{
		TurnID:       domain.NewID().String(),
		InstanceID:   row.InstanceID,
		DefinitionID: row.DefinitionID,
		Workspace:    row.Workspace,
		SessionDir:   filepath.Join(d.StateDir, "sessions", row.InstanceID),
		Resume:       resume,
		Input:        input,
		InputKind:    kind,
		Model:        row.Model,
		AgentMDPath:  agentMDPath,
		Metadata:     map[string]any{"profile": row.Profile},
		Env: []string{
			"PAGNET_INSTANCE_ID=" + row.InstanceID,
			"PAGNET_AGENT_NAME=" + row.AgentName,
			"PAGNET_NETWORK_ID=" + row.NetworkID,
			"PAGNET_MCP_CONFIG=" + d.mcpConfig(row),
			"PAGNET_COORDINATION_CONTRACT=" + contractPath,
		},
	}
}

// mcpConfig is the MCP client config the daemon injects into every
// managed agent: the bridge over the daemon's local Unix socket (the
// bridge authenticates to the daemon with the instance identity — the
// host credential never reaches the agent, §5/§17). Workers get the
// worker MCP surface (network_* tools); representatives get the
// control surface (control_* tools). The bridge is the daemon's OWN
// executable (self-spawn, packaging migration step 5): the runtime
// spawns <self> mcp worker|control, so the install dir never has to be
// on PATH — and a daemon that cannot resolve its own executable
// refuses to start (New) instead of handing agents a bridge it cannot
// spawn.
func (d *Daemon) mcpConfig(row *InstanceRow) string {
	name, args := "pagnet", []string{"mcp", "worker"}
	if row.Kind == "representative" {
		name, args = "pagnet-control", []string{"mcp", "control"}
	}
	args = append(args, "--socket", filepath.Join(d.StateDir, "pagnetd.sock"))
	cfg := map[string]any{
		"mcpServers": map[string]any{
			name: map[string]any{
				"command": d.selfExe,
				"args":    args,
				"env": map[string]string{
					"PAGNET_INSTANCE_ID": row.InstanceID,
					"PAGNET_NETWORK_ID":  row.NetworkID,
				},
			},
		},
	}
	b, _ := json.Marshal(cfg)
	return string(b)
}

// resolveSelfExecutable resolves this process's own executable path,
// canonicalized (symlinks resolved): the command the agent runtimes
// spawn the MCP bridges from (<self> mcp worker|control). It fails
// explicitly when the daemon cannot tell where its own binary lives —
// a bare name would become a PATH lookup in the RUNTIME's environment
// (ChildEnv filters credentials only, so PATH is inherited unchanged),
// and that environment is not guaranteed to contain the install dir:
// a miss means the agent silently comes up with no network tools.
func resolveSelfExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("os.Executable: %w", err)
	}
	if exe == "" {
		return "", errors.New("os.Executable returned an empty path")
	}
	canonical, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("canonicalize %s: %w", exe, err)
	}
	return canonical, nil
}

// runTurn executes one turn through the adapter, translating normalized
// events into host protocol events, then hibernates the instance when the
// process exits (process-per-turn).
func (d *Daemon) runTurn(conn *websocket.Conn, spec agentruntime.TurnSpec) error {
	row, ok, _ := d.state.GetInstance(spec.InstanceID)
	if !ok {
		return fmt.Errorf("unknown instance %s", spec.InstanceID)
	}
	// The session this turn starts from; a shutdown-interrupted turn rolls
	// back to exactly this (see the context.Canceled branch below).
	preTurnSession := row.SessionID

	// Phase 1 (runtime-lifecycle refactor): a PERSISTENT runtime is driven
	// through the session core — one long-lived endpoint that services many
	// logical submits (EnsureActive + Submit + consume normalized events) —
	// not the legacy process-per-turn Adapter path. qwen-code is
	// session-driven (Wave B: its legacy adapter was removed); the
	// process-per-turn claude-code / opencode / Fake keep the legacy path
	// below. The session core serializes prompt turns per instance
	// (promptLock), so no separate active-turn guard is needed.
	//
	// This is checked BEFORE the adapter lookup: a session-driven runtime
	// has NO adapter (it lives in the session core), so the adapter lookup
	// would fail for it. For a legacy runtime the check is a no-op (no
	// driver registered), so the legacy path below is byte-identical.
	if d.sessions != nil && d.sessions.DriverFor(domain.RuntimeName(row.Runtime)) != nil {
		return d.runTurnPersistent(conn, spec, row)
	}

	ad, ok := d.adapters[domain.RuntimeName(row.Runtime)]
	if !ok {
		return fmt.Errorf("no adapter for runtime %q", row.Runtime)
	}
	// The daemon creates the workspace at launch (launchAgent); if it is
	// gone at turn time it was deleted out from under the instance (host
	// /tmp hygiene, test cleanup). Refuse early with a clear error instead
	// of a spawn-time chdir failure.
	if _, err := os.Stat(spec.Workspace); err != nil {
		d.Log.Warn("turn refused: workspace missing",
			"instance", spec.InstanceID, "workspace", spec.Workspace)
		return fmt.Errorf("workspace %s not found", spec.Workspace)
	}

	d.turnMu.Lock()
	if d.activeTurns[spec.InstanceID] {
		d.turnMu.Unlock()
		return fmt.Errorf("instance %s already has an active turn", spec.InstanceID)
	}
	d.activeTurns[spec.InstanceID] = true
	d.turnMu.Unlock()
	started := time.Now()
	defer func() {
		d.turnMu.Lock()
		delete(d.activeTurns, spec.InstanceID)
		d.turnMu.Unlock()
	}()

	if err := d.state.SetInstanceStatus(spec.InstanceID, "working", ""); err != nil {
		return err
	}
	d.reportEndpointStatus(conn, spec.InstanceID) // online (turn in flight)
	events := make(chan agentruntime.TurnEvent, 16)
	turnDone := make(chan error, 1)
	go func() {
		// d.turnCtx is canceled on daemon shutdown: the adapter kills the
		// turn subprocess (exec.CommandContext), so a SIGTERM mid-turn
		// never orphans the process. Reconnects do NOT cancel it — a
		// turn survives a dropped host connection (events re-send on the
		// live conn, the ack replays from processed_commands).
		turnDone <- ad.StartTurn(d.turnCtx, spec, events)
	}()

	sessionID := ""
	var failedKind, failedErr string
	var failedRetry *string
	var sessionLost, completed bool
	// Phase 5: native-interaction observation. pendingInteraction tracks a
	// started-but-unresolved interaction; interactionDeferrable is the
	// adapter's capability for its kind (decides hibernate vs stay-waiting
	// at turn end). interactionIDs maps the runtime-native id to the
	// pagnet-side id the daemon mints (correlates started/resolved).
	pendingInteraction := false
	interactionDeferrable := false
	interactionIDs := map[string]string{}
	// E2EE (plan §12): the per-turn runtime-output stream id (object id for
	// the encrypted output chunks). Minted only when the instance's network
	// is an active private network; empty otherwise (plaintext output).
	var runtimeStreamID string
	if st, ok := d.cryptoManager().NetworkCrypto(row.NetworkID); ok && st.Status == "active" && st.EpochID != "" {
		runtimeStreamID = newObjectID()
	}

	for ev := range events {
		switch ev.Type {
		case agentruntime.EventSessionStarted, agentruntime.EventSessionResumed:
			sessionID = ev.SessionID
			d.reportSession(conn, spec.InstanceID, ev.SessionID,
				ev.Type == agentruntime.EventSessionResumed)
			_ = d.state.SetInstanceStatus(spec.InstanceID, "working", ev.SessionID)
		case agentruntime.EventSessionLost:
			sessionLost = true
		case agentruntime.EventTurnStarted:
			d.sendTurn(conn, transport.MsgRuntimeTurnStarted, spec, sessionID, nil, nil, nil, "", "", nil)
		case agentruntime.EventTurnOutput:
			d.sendRuntimeOutput(conn, row, runtimeStreamID, ev.Output)
		case agentruntime.EventTurnCompleted:
			completed = true
			d.sendTurn(conn, transport.MsgRuntimeTurnCompleted, spec, sessionID,
				ev.InputTokens, ev.OutputTokens, ev.CachedTokens, ev.Model, "", nil)
		case agentruntime.EventTurnFailed:
			failedKind = string(ev.FailureKind)
			failedErr = ev.Error
			failedRetry = ev.RetryAt
		case agentruntime.EventInteractionStarted:
			if ev.Interaction != nil {
				pendingInteraction = true
				if obs, ok := ad.(agentruntime.InteractionObserver); ok {
					interactionDeferrable = obs.SupportsDeferredInteraction(ev.Interaction.Kind)
				}
				d.sendInteraction(conn, transport.MsgInteractionStarted,
					spec, sessionID, row.Runtime, ev.Interaction, interactionIDs)
			}
		case agentruntime.EventInteractionResolved:
			if ev.Interaction != nil {
				pendingInteraction = false
				d.sendInteraction(conn, transport.MsgInteractionResolved,
					spec, sessionID, row.Runtime, ev.Interaction, interactionIDs)
			}
		}
	}
	turnErr := <-turnDone

	// The session this turn attempted: the live one if the runtime
	// reported one, else the one we tried to resume (needed so the control
	// plane can invalidate the exact stored session on session_lost,
	// §74/§88).
	attemptedSession := sessionID
	if attemptedSession == "" {
		attemptedSession = row.SessionID
	}

	switch {
	case sessionLost:
		// §74/§88: the resume failed — do NOT silently start a fresh
		// session. Report the attempted session id so the control plane
		// marks it invalid, drop the local reference, and block the
		// instance until a human explicitly restarts (cold start).
		d.sendTurn(conn, transport.MsgRuntimeTurnFailed, spec, attemptedSession,
			nil, nil, nil, "", "session_lost:no resumable session", nil)
		_ = d.state.SetInstanceSession(spec.InstanceID, "")
		_ = d.state.SetInstanceStatus(spec.InstanceID, "blocked", "")
		d.reportEndpointStatus(conn, spec.InstanceID) // offline (blocked)
		return fmt.Errorf("session lost: no resumable session (instance blocked)")
	case failedKind != "":
		// The turn consumed no work: fail the command so a delivery's
		// source message stays pending for re-delivery (§44) and a wake
		// request is resolved as failed (never a silent no-op).
		d.sendTurn(conn, transport.MsgRuntimeTurnFailed, spec, attemptedSession,
			nil, nil, nil, "", failedKind+":"+failedErr, failedRetry)
		st := "failed"
		switch failedKind {
		case "rate_limited":
			st = "rate_limited"
		case "auth_required":
			// §41: availability state, not a terminal failure — the
			// instance parks and can be woken once a human re-authenticates.
			st = "auth_required"
		}
		d.Log.Warn("turn failed", "instance", spec.InstanceID,
			"kind", failedKind, "error", failedErr, "retryAt", failedRetry)
		_ = d.state.SetInstanceStatus(spec.InstanceID, st, sessionID)
		d.reportEndpointStatus(conn, spec.InstanceID) // offline (failed/rate_limited/auth_required)
		return fmt.Errorf("turn failed: %s: %s", failedKind, failedErr)
	case errors.Is(turnErr, context.Canceled):
		// The daemon is shutting down (Close cancels d.turnCtx, spec §90)
		// mid-turn. That is NOT an instance failure: the turn consumed no
		// work, the command stays un-acked, and the documented recovery is
		// "the control plane re-sends the un-acked command" (ReconcileRestart
		// resets the stale "working" row on startup). Marking the instance
		// "failed" (or reporting a turn failure) would make doDeliver refuse
		// that re-delivery until an explicit instance restart — an ordinary
		// daemon restart mid-turn would brick the instance.
		// Roll back the session id the turn claimed optimistically: a
		// session is only trustworthy once the turn COMPLETED (completion
		// is what persists it). Reverting to the pre-turn value keeps a
		// killed resume resumable and a killed cold start cold.
		_ = d.state.SetInstanceSession(spec.InstanceID, preTurnSession)
		d.Log.Info("turn interrupted by daemon shutdown; no failure recorded, work stays queued",
			"instance", spec.InstanceID)
		return turnErr
	case errors.Is(turnErr, proc.ErrShuttingDown):
		// The supervisor is shutting down and refused the launch. Same
		// semantics as a shutdown cancel: no failure recorded, work stays
		// queued for the control plane's re-send.
		_ = d.state.SetInstanceSession(spec.InstanceID, preTurnSession)
		d.Log.Info("turn launch refused: supervisor shutting down; work stays queued",
			"instance", spec.InstanceID)
		return turnErr
	case errors.Is(turnErr, proc.ErrInstanceBusy):
		// Defense-in-depth: the daemon's activeTurns guard should prevent
		// a second turn for one instance, but if the supervisor sees a
		// live turn, defer — the command stays queued and is re-sent.
		return ErrDeferred
	case errors.Is(turnErr, proc.ErrHostPressure), errors.Is(turnErr, proc.ErrLimitRefused):
		// A pagnet-owned safety ceiling (active turns, owned processes,
		// circuit) or host process pressure refused the launch (§32/§33/
		// §54). This is a clean OPERATIONAL condition, not a runtime
		// failure and never a silent retry: no process was spawned, and
		// the distinct kind lets the control plane and operator see the
		// host protecting itself. The supervisor's backoff/circuit bounds
		// any re-send cadence.
		kind := "runtime_launch_refused"
		if errors.Is(turnErr, proc.ErrHostPressure) {
			kind = "host_resource_pressure"
		}
		d.Log.Warn("turn launch refused by process supervisor",
			"instance", spec.InstanceID, "kind", kind, "error", turnErr.Error())
		d.sendTurn(conn, transport.MsgRuntimeTurnFailed, spec, attemptedSession,
			nil, nil, nil, "", kind+":"+turnErr.Error(), nil)
		_ = d.state.SetInstanceStatus(spec.InstanceID, "failed", "")
		d.reportEndpointStatus(conn, spec.InstanceID) // offline (failed)
		return fmt.Errorf("turn launch refused: %s: %v", kind, turnErr)
	case turnErr != nil:
		// Adapter-level failure (spawn/IO), no turn events were produced.
		d.Log.Warn("turn failed (adapter error)",
			"instance", spec.InstanceID, "error", turnErr.Error())
		d.sendTurn(conn, transport.MsgRuntimeTurnFailed, spec, attemptedSession,
			nil, nil, nil, "", "process_error:"+turnErr.Error(), nil)
		_ = d.state.SetInstanceStatus(spec.InstanceID, "failed", "")
		d.reportEndpointStatus(conn, spec.InstanceID) // offline (failed)
		return fmt.Errorf("turn failed: process_error: %v", turnErr)
	case !completed:
		// The adapter exited cleanly but the turn produced NEITHER a
		// completion nor a failure event: the process was cut off between
		// events. Only a shutdown cancel can cause this cleanly (the kill
		// lands after the last event is consumed but before Wait returns,
		// so no error surfaces). The turn consumed no work — treat it
		// exactly like an interrupted turn: roll back the claimed session,
		// record no failure, and return context.Canceled so guarded() does
		// NOT ack the command; it stays pending and the server's re-send
		// after reconnect re-runs the turn.
		_ = d.state.SetInstanceSession(spec.InstanceID, preTurnSession)
		d.Log.Warn("turn ended without a completion event; no failure recorded, work stays queued",
			"instance", spec.InstanceID)
		return context.Canceled
	default:
		// Completed. §35: do not hibernate underneath an attached user —
		// and not underneath a live PTY either (addendum §10): an active
		// attach or terminal keeps the instance awake (idle, session
		// active); hibernation happens when the last one is closed.
		if d.attached(spec.InstanceID) || d.terminal.active(spec.InstanceID) {
			_ = d.state.SetInstanceStatus(spec.InstanceID, "idle", sessionID)
			_ = d.send(conn, transport.MsgAgentStatus, map[string]any{
				"instanceId": spec.InstanceID, "status": "idle",
			})
			d.reportEndpointStatus(conn, spec.InstanceID) // online (idle)
			d.Log.Info("turn completed; instance kept awake (attach/pty active)",
				"instance", spec.InstanceID, "duration", time.Since(started).Round(time.Second))
			return nil
		}
		// Phase 5: a NON-deferrable interaction is still pending. The
		// runtime cannot safely exit with it outstanding, so the instance
		// keeps its waiting status (the control plane set it to 'blocked'
		// on interaction.started) instead of hibernating. No polling / no
		// token burn: the instance simply waits until a human answers in
		// the native TUI (attach) and the resolution clears it.
		if pendingInteraction && !interactionDeferrable {
			_ = d.state.SetInstanceStatus(spec.InstanceID, "blocked", sessionID)
			_ = d.send(conn, transport.MsgAgentStatus, map[string]any{
				"instanceId": spec.InstanceID, "status": "blocked",
			})
			d.reportEndpointStatus(conn, spec.InstanceID) // offline (blocked)
			d.Log.Info("turn completed; non-deferrable interaction pending — instance stays waiting",
				"instance", spec.InstanceID, "duration", time.Since(started).Round(time.Second))
			return nil
		}
		// Completed: hibernate with the session preserved. (A deferrable
		// pending interaction is safe to hibernate under — the interaction
		// is durable and the instance wakes on the next work/resolve.)
		_ = d.state.SetInstanceStatus(spec.InstanceID, "hibernated", sessionID)
		_ = d.send(conn, transport.MsgAgentHibernated, map[string]any{
			"instanceId": spec.InstanceID, "sessionId": sessionID,
			"reason": "turn_completed",
		})
		d.reportEndpointStatus(conn, spec.InstanceID) // offline (hibernated)
		d.Log.Info("turn completed; instance hibernated",
			"instance", spec.InstanceID, "session", sessionID,
			"duration", time.Since(started).Round(time.Second))
	}
	return nil
}

// runTurnPersistent drives one turn through the session core (the
// runtime-lifecycle refactor, Phase 1): EnsureActive + Submit + consume
// normalized events, translating them into host protocol. Unlike the legacy
// process-per-turn path, the endpoint process is LONG-LIVED: it is NOT
// stopped when the turn completes (the instance goes idle, not hibernated),
// so the PID is stable across turns. Hibernation (stopping the endpoint,
// preserving the session) is a separate, explicit operation.
func (d *Daemon) runTurnPersistent(conn *websocket.Conn, spec agentruntime.TurnSpec, row *InstanceRow) error {
	started := time.Now()

	// The session this turn runs in (prepareSession: the pagnet-persisted
	// native id is restored so a daemon restart can resume the stored
	// session — Codex R4 — and the launch env is set for the endpoint
	// (re)activation).
	sess := d.prepareSession(row, spec)

	if err := d.state.SetInstanceStatus(spec.InstanceID, "working", ""); err != nil {
		return err
	}
	d.reportEndpointStatus(conn, spec.InstanceID) // online (turn in flight)

	// E2EE (plan §12): the per-turn runtime-output stream id (object id for
	// the encrypted output chunks). Minted only when the instance's network
	// is an active private network; empty otherwise (plaintext output).
	var runtimeStreamID string
	if st, ok := d.cryptoManager().NetworkCrypto(row.NetworkID); ok && st.Status == "active" && st.EpochID != "" {
		runtimeStreamID = newObjectID()
	}

	events := make(chan session.SessionEvent, 16)
	submitDone := make(chan struct{})
	var submitErr error
	go func() {
		defer close(submitDone)
		_, submitErr = d.sessions.Submit(d.turnCtx, sess, session.SubmitRequest{
			TurnID:    spec.TurnID,
			Kind:      session.SubmitPrompt,
			Input:     spec.Input,
			InputKind: spec.InputKind,
		}, events)
	}()

	sessionID := row.SessionID
	var failedKind, failedErr string
	var failedRetry *string
	var sessionLost, completed bool
	interactionIDs := map[string]string{}

	for ev := range events {
		// Turn identity (Phase 2): the driver echoes the submit's logical
		// turn id on every event it emits for that turn, so the event
		// stream carries the logical identity end-to-end. An event that
		// carries a DIFFERENT id is an attribution anomaly (the stream is
		// crossed with another turn) — log it loudly. The host-protocol
		// events still carry the spec's id (the authoritative one).
		if ev.TurnID != "" && ev.TurnID != spec.TurnID {
			d.Log.Warn("turn event attribution mismatch",
				"instance", spec.InstanceID, "expected", spec.TurnID,
				"got", ev.TurnID, "event", ev.Type)
		}
		switch ev.Type {
		case session.EventSessionStarted, session.EventSessionResumed:
			sessionID = ev.SessionID
			d.reportSession(conn, spec.InstanceID, ev.SessionID, ev.Type == session.EventSessionResumed)
			_ = d.state.SetInstanceStatus(spec.InstanceID, "working", ev.SessionID)
			// Phase 3 (A5/G8): the ACTIVATION site. The human-plane view
			// onto the endpoint's PTY is ensured the moment the endpoint
			// is live, not after the turn settles: its read loop is the
			// PTY's only reader while no human is attached, and without a
			// reader a native TUI blocks on tty writes once the PTY
			// buffer fills — the model turn then never starts (no user
			// event, no message_start; the e2e cold-start deadline).
			d.ensureEndpointView(row)
		case session.EventSessionLost:
			sessionLost = true
		case session.EventTurnStarted:
			d.sendTurn(conn, transport.MsgRuntimeTurnStarted, spec, sessionID, nil, nil, nil, "", "", nil)
		case session.EventTurnOutput:
			d.sendRuntimeOutput(conn, row, runtimeStreamID, ev.Output)
		case session.EventTurnCompleted:
			completed = true
			d.sendTurn(conn, transport.MsgRuntimeTurnCompleted, spec, sessionID,
				ev.InputTokens, ev.OutputTokens, ev.CachedTokens, ev.Model, "", nil)
		case session.EventTurnFailed:
			failedKind = ev.FailureKind
			failedErr = ev.Error
			failedRetry = ev.RetryAt
		case session.EventInteractionStarted:
			if ev.Interaction != nil {
				d.sendInteraction(conn, transport.MsgInteractionStarted, spec, sessionID,
					row.Runtime, sessionInteractionToAdapter(ev.Interaction), interactionIDs)
			}
		case session.EventInteractionResolved:
			if ev.Interaction != nil {
				d.sendInteraction(conn, transport.MsgInteractionResolved, spec, sessionID,
					row.Runtime, sessionInteractionToAdapter(ev.Interaction), interactionIDs)
			}
		}
	}
	<-submitDone

	attemptedSession := sessionID
	if attemptedSession == "" {
		attemptedSession = row.SessionID
	}

	// D4: the persistent path mirrors the legacy process-per-turn error
	// taxonomy EXACTLY. The supervisor's operational errors keep their
	// distinct semantics (a daemon restart mid-turn must not brick the
	// instance); they are NOT collapsed into a generic process_error.
	outcome, refusedKind := classifyTurnError(submitErr, completed, sessionLost, failedKind)
	switch outcome {
	case outcomeSessionLost:
		// The resume failed — do NOT silently start a fresh session. Report
		// the attempted session id so the control plane marks it invalid,
		// drop the local reference, and block the instance until a human
		// explicitly restarts (cold start).
		d.sendTurn(conn, transport.MsgRuntimeTurnFailed, spec, attemptedSession,
			nil, nil, nil, "", "session_lost:no resumable session", nil)
		_ = d.state.SetInstanceSession(spec.InstanceID, "")
		_ = d.state.SetInstanceStatus(spec.InstanceID, "blocked", "")
		d.reportEndpointStatus(conn, spec.InstanceID) // offline (blocked)
		return fmt.Errorf("session lost: no resumable session (instance blocked)")
	case outcomeTurnFailed:
		d.sendTurn(conn, transport.MsgRuntimeTurnFailed, spec, attemptedSession,
			nil, nil, nil, "", failedKind+":"+failedErr, failedRetry)
		st := "failed"
		switch failedKind {
		case "rate_limited":
			st = "rate_limited"
		case "auth_required":
			st = "auth_required"
		}
		d.Log.Warn("turn failed", "instance", spec.InstanceID,
			"kind", failedKind, "error", failedErr, "retryAt", failedRetry)
		_ = d.state.SetInstanceStatus(spec.InstanceID, st, sessionID)
		d.reportEndpointStatus(conn, spec.InstanceID) // offline (failed/rate_limited/auth_required)
		return fmt.Errorf("turn failed: %s: %s", failedKind, failedErr)
	case outcomeNoFailureQueued:
		// No failure recorded (a shutdown cancel, a supervisor shutdown
		// refusal, or a turn cut off between events). Roll back the session
		// id the turn claimed optimistically; the work stays queued for the
		// control plane's re-send.
		_ = d.state.SetInstanceSession(spec.InstanceID, row.SessionID)
		if submitErr != nil {
			d.Log.Info("turn interrupted; no failure recorded, work stays queued",
				"instance", spec.InstanceID, "error", submitErr.Error())
			return submitErr
		}
		d.Log.Warn("turn ended without a completion event; no failure recorded, work stays queued",
			"instance", spec.InstanceID)
		return context.Canceled
	case outcomeDeferred:
		// Defense-in-depth: the session core serializes prompt turns, but if
		// the supervisor sees a live endpoint, defer — the command stays
		// queued and is re-sent (NOT acked).
		return ErrDeferred
	case outcomeLaunchRefused:
		// A pagnet-owned safety ceiling (active turns, owned processes,
		// circuit) or host process pressure refused the endpoint launch
		// (§32/§33/§54). A clean OPERATIONAL condition, not a runtime
		// failure and never a silent retry: no process was spawned, and the
		// distinct kind lets the control plane and operator see the host
		// protecting itself.
		kind := string(refusedKind)
		d.Log.Warn("turn launch refused by process supervisor",
			"instance", spec.InstanceID, "kind", kind, "error", submitErr.Error())
		d.sendTurn(conn, transport.MsgRuntimeTurnFailed, spec, attemptedSession,
			nil, nil, nil, "", kind+":"+submitErr.Error(), nil)
		_ = d.state.SetInstanceStatus(spec.InstanceID, "failed", "")
		d.reportEndpointStatus(conn, spec.InstanceID) // offline (failed)
		return fmt.Errorf("turn launch refused: %s: %v", kind, submitErr)
	case outcomeProcessError:
		// Session-core / driver-level failure (spawn/IO), no turn events
		// were produced.
		d.Log.Warn("turn failed (session core error)",
			"instance", spec.InstanceID, "error", submitErr.Error())
		d.sendTurn(conn, transport.MsgRuntimeTurnFailed, spec, attemptedSession,
			nil, nil, nil, "", "process_error:"+submitErr.Error(), nil)
		_ = d.state.SetInstanceStatus(spec.InstanceID, "failed", "")
		d.reportEndpointStatus(conn, spec.InstanceID) // offline (failed)
		return fmt.Errorf("turn failed: process_error: %v", submitErr)
	default: // outcomeCompleted
		// Completed: the persistent endpoint STAYS ALIVE (the instance goes
		// idle, not hibernated) — the PID is stable across turns. An
		// explicit hibernate (a separate operation) stops the endpoint,
		// preserving the session for a later wake.
		_ = d.state.SetInstanceStatus(spec.InstanceID, "idle", sessionID)
		_ = d.send(conn, transport.MsgAgentStatus, map[string]any{
			"instanceId": spec.InstanceID, "status": "idle",
		})
		d.reportEndpointStatus(conn, spec.InstanceID) // online (idle)
		d.Log.Info("turn completed; persistent endpoint kept alive (idle)",
			"instance", spec.InstanceID, "session", sessionID,
			"duration", time.Since(started).Round(time.Second))
	}
	return nil
}

// sessionInteractionToAdapter converts a session-core interaction
// observation to the adapter-shaped one the host-protocol sendInteraction
// expects (the two are structurally identical; the session core is the
// vendor-agnostic source of the normalized fields).
func sessionInteractionToAdapter(ie *session.InteractionEvent) *agentruntime.InteractionEvent {
	if ie == nil {
		return nil
	}
	return &agentruntime.InteractionEvent{
		NativeInteractionID: ie.NativeInteractionID,
		Kind:                ie.Kind,
		Summary:             ie.Summary,
		NativePayload:       ie.NativePayload,
		Resolved:            ie.Resolved,
		Decision:            ie.Decision,
		Answer:              ie.Answer,
	}
}

// --- Phase 3: session-driven terminal plane (terminal session unification) ---
//
// A session-driven runtime's terminal is the ENDPOINT'S OWN PTY (A1): one
// process owns both planes — the PTY is the HUMAN plane (raw bytes to the
// native TUI), the JSONL pipes are the MACHINE plane (native protocol;
// never PTY keystrokes). Attach (A3) = "ensure the session is active, then
// view its PTY": hibernated → wake/resume, live → observational, and NEVER
// a second interactive process. The view (terminal.attachEndpoint) is
// created at ACTIVATION (A5/G8); keep-awake is the human attach
// (d.attached), not the view (A6).

// prepareSession is the session setup shared by every session-driven
// activation path (turns and attach): the logical session for the row,
// with the pagnet-persisted native id restored (Codex R4: the id is
// pagnet-persisted, never vendor-listed) and the launch env set (Phase 2 /
// R8: fixed at spawn; a change restarts the endpoint —
// session.RuntimeSession.Env semantics).
func (d *Daemon) prepareSession(row *InstanceRow, spec agentruntime.TurnSpec) *session.RuntimeSession {
	sess := d.sessions.Session(spec.InstanceID, domain.RuntimeName(row.Runtime), spec.Workspace)
	d.sessions.RestoreNativeState(spec.InstanceID, row.SessionID)
	d.sessions.SetLaunchEnv(sess, spec.Env)
	// The launch model (Phase 4 / B9): fixed at spawn; a change restarts
	// the endpoint on the next EnsureActive (preserving the session).
	d.sessions.SetModel(sess, spec.Model)
	return sess
}

// ensureEndpointView creates (or reconciles to) the human-plane VIEW onto
// a session-driven endpoint's own TUI PTY, at the ACTIVATION site (A5/G8:
// the view exists from activation, not from the first attach). It is a
// no-op unless the instance is session-driven AND the endpoint is live
// with a PTY (PTYSize-gated — the no-PTY topology is first-class, I1).
// The view is observational (it never owns the endpoint's lifecycle, G3/G5)
// and does NOT keep the instance awake (A6: keep-awake is d.attached).
//
// The config fingerprint (P6 configStale) is stamped only when a NEW view
// is created — i.e. at a genuine (re)activation, when the running endpoint
// was just launched with the daemon's CURRENT injected config. A reconcile
// to an existing view never re-stamps: the fingerprint must keep describing
// the config the running endpoint was actually launched with.
func (d *Daemon) ensureEndpointView(row *InstanceRow) {
	if d.sessionDriverFor(row) == nil {
		return
	}
	master := d.sessions.PTYMaster(row.InstanceID)
	if master == nil {
		return // no live endpoint, or a PTY-less endpoint (I1)
	}
	if _, created, err := d.terminal.attachEndpoint(row.InstanceID, master); err != nil {
		d.Log.Warn("endpoint view attach failed", "instance", row.InstanceID,
			"error", err.Error())
		return
	} else if created {
		_ = d.state.SetInstanceConfigFingerprint(row.InstanceID, d.instanceFingerprint(row))
	}
}

// attachSessionDriven is the doAttach path for a session-driven runtime
// (A3): it connects the human to the ENDPOINT'S OWN PTY. It never spawns a
// second interactive process — a hibernated (or live-but-endpoint-gone)
// instance is woken/resumed through the SAME activation path a turn uses
// (EnsureActive), and a live instance is attached to observationally.
func (d *Daemon) attachSessionDriven(conn *websocket.Conn, p transport.TerminalAttachPayload, row *InstanceRow) error {
	// Capability gate: the terminal surface exists only when the runtime
	// has a native TUI. Refuse BEFORE any attach bookkeeping (no
	// addAttach for a refused attach) — an honest "no terminal surface",
	// never a spawned stand-in process.
	if !d.sessionDriverFor(row).Capabilities().NativeTUI {
		return fmt.Errorf("instance %s runtime %s has no terminal surface (no native TUI); attach refused",
			p.InstanceID, row.Runtime)
	}
	switch row.Status {
	case "hibernated":
		// Wake/resume: the session is materialised (or cold-started when
		// it never was); a lost session blocks the instance (invariant F).
		if err := d.activateSessionForAttach(conn, row); err != nil {
			return err
		}
	case "idle":
		if d.sessions.PTYMaster(row.InstanceID) == nil {
			// Idle on paper but the endpoint is not live (a daemon restart
			// leaves the persisted status behind; the process cannot
			// survive it). (Re)activate — resume when materialised.
			if err := d.activateSessionForAttach(conn, row); err != nil {
				return err
			}
		}
		// Live endpoint: observational attach (the view was ensured at the
		// activation site — A5; ensure it idempotently).
		d.ensureEndpointView(row)
	case "working", "waking", "starting":
		// A turn is driving the live endpoint: attach observationally
		// (the view exists from the activation site; ensure idempotently).
		d.ensureEndpointView(row)
	default:
		// "blocked"/"failed"/"stopped" are already refused by doAttach;
		// any other status (e.g. "hibernating") is not attachable.
		return fmt.Errorf("instance %s is %s; attach refused", p.InstanceID, row.Status)
	}
	d.addAttach(p.InstanceID, p.SessionID)
	master := d.sessions.PTYMaster(row.InstanceID)
	if master == nil {
		d.removeAttach(p.InstanceID, p.SessionID)
		return fmt.Errorf("instance %s endpoint is not active; attach refused", p.InstanceID)
	}
	s, _, err := d.terminal.attachEndpoint(p.InstanceID, master)
	if err != nil {
		d.removeAttach(p.InstanceID, p.SessionID)
		return err
	}
	// The snapshot is sent right after the attach (durable command →
	// this worker), so any output produced since the last attach is
	// replayed before live frames for the new client (§11).
	data, lastSeq := d.terminal.snapshot(s)
	_ = d.send(conn, transport.MsgTerminalOutput, transport.TerminalOutputPayload{
		InstanceID:  p.InstanceID,
		SessionID:   p.SessionID,
		Data:        data,
		Snapshot:    true,
		LastSeq:     lastSeq,
		ConfigStale: d.configStaleFor(p.InstanceID),
	})
	return nil
}

// activateSessionForAttach (re)activates a session-driven instance's
// endpoint so a terminal attach has a live PTY to view. It is the SAME
// activation path a turn uses (prepareSession + EnsureActive) — no
// separate wake machinery, no second process.
//
// Outcomes:
//   - success: the session events are reported (started/resumed), the
//     instance is idle (a live endpoint, no turn in flight), and the view
//     is ensured at this activation site (A5/G8).
//   - ErrSessionLost: the stored session is unrecoverable — drop the local
//     reference and BLOCK the instance until a human explicitly restarts
//     (invariant F: never a silent fresh session).
//   - any other error: the attach is refused (the instance status is left
//     for the turn/hibernate paths to settle).
func (d *Daemon) activateSessionForAttach(conn *websocket.Conn, row *InstanceRow) error {
	spec := d.turnSpecFor(row, row.SessionID != "", "", "terminal")
	sess := d.prepareSession(row, spec)
	events := make(chan session.SessionEvent, 16)
	_, err := d.sessions.EnsureActive(d.turnCtx, sess, events)
	// The driver sends the activation events and returns when activation
	// settles (it does NOT close the channel — the caller owns the
	// lifecycle). Drain non-blockingly, then close.
drain:
	for {
		select {
		case ev := <-events:
			switch ev.Type {
			case session.EventSessionStarted, session.EventSessionResumed:
				d.reportSession(conn, row.InstanceID, ev.SessionID,
					ev.Type == session.EventSessionResumed)
				_ = d.state.SetInstanceStatus(row.InstanceID, "working", ev.SessionID)
			case session.EventSessionLost:
				// Surfaced via the error below (invariant F).
			}
		default:
			break drain
		}
	}
	close(events)
	if err != nil {
		if errors.Is(err, session.ErrSessionLost) {
			// The resume failed — do NOT silently start a fresh session.
			// Drop the local reference and block until a human explicitly
			// restarts (cold start). Same handling as the turn path.
			_ = d.state.SetInstanceSession(row.InstanceID, "")
			_ = d.state.SetInstanceStatus(row.InstanceID, "blocked", "")
			d.reportEndpointStatus(conn, row.InstanceID) // offline (blocked)
			d.Log.Warn("attach activation lost the session; instance blocked",
				"instance", row.InstanceID)
			return fmt.Errorf("session lost: no resumable session (instance blocked)")
		}
		d.Log.Warn("attach activation failed", "instance", row.InstanceID,
			"error", err.Error())
		return err
	}
	sessionID := row.SessionID
	if sess.NativeID != "" {
		sessionID = sess.NativeID
	}
	_ = d.state.SetInstanceStatus(row.InstanceID, "idle", sessionID)
	_ = d.send(conn, transport.MsgAgentStatus, map[string]any{
		"instanceId": row.InstanceID, "status": "idle",
	})
	d.reportEndpointStatus(conn, row.InstanceID) // online (attach woke it)
	d.Log.Info("attach activated endpoint (session-driven)", "instance", row.InstanceID,
		"session", sessionID)
	d.ensureEndpointView(row)
	return nil
}

// --- attach sessions (§35) ---------------------------------------------------

func (d *Daemon) addAttach(instanceID, sessionID string) {
	d.attachMu.Lock()
	defer d.attachMu.Unlock()
	if d.attaches[instanceID] == nil {
		d.attaches[instanceID] = map[string]time.Time{}
	}
	d.attaches[instanceID][sessionID] = time.Now()
}

// removeAttach drops an attach session and reports whether it was the
// last one for the instance.
func (d *Daemon) removeAttach(instanceID, sessionID string) bool {
	d.attachMu.Lock()
	defer d.attachMu.Unlock()
	sess := d.attaches[instanceID]
	delete(sess, sessionID)
	if len(sess) == 0 {
		delete(d.attaches, instanceID)
	}
	return len(sess) == 0
}

func (d *Daemon) attached(instanceID string) bool {
	d.attachMu.Lock()
	defer d.attachMu.Unlock()
	return len(d.attaches[instanceID]) > 0
}

// doAttach opens a terminal attach session (addendum §10/§11): it records
// the attach, starts the instance's PTY when not already running — the
// PTY start IS the wake of a hibernated instance (the interactive CLI
// resumes the stored session) — and then streams the bounded PTY snapshot
// so the (re)connecting client renders history before live output.
// Detach later is observational: the PTY keeps running (§10).
func (d *Daemon) doAttach(conn *websocket.Conn, p transport.TerminalAttachPayload) error {
	row, ok, err := d.state.GetInstance(p.InstanceID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unknown instance %s", p.InstanceID)
	}
	switch row.Status {
	case "blocked", "failed", "stopped":
		return fmt.Errorf("instance %s is %s; attach refused", p.InstanceID, row.Status)
	}
	// Phase 3 (A3): a session-driven runtime's terminal is the ENDPOINT'S
	// OWN PTY. Attach connects the human to it — waking/resuming the
	// session if the endpoint is not live, and attaching observationally
	// if it is — and NEVER spawns a second interactive process. The
	// legacy ClassPTY path below is unchanged for non-session runtimes.
	if d.sessionDriverFor(row) != nil {
		return d.attachSessionDriven(conn, p, row)
	}
	d.addAttach(p.InstanceID, p.SessionID)

	s, err := d.terminal.start(p.InstanceID, row.SessionID != "")
	if err != nil {
		d.removeAttach(p.InstanceID, p.SessionID)
		return err
	}
	// Wake semantics: a hibernated instance becomes awake (idle) once its
	// interactive process is running. A busy instance simply keeps its
	// turn (process-per-turn) while the PTY runs alongside it.
	if row.Status == "hibernated" {
		_ = d.state.SetInstanceStatus(p.InstanceID, "idle", row.SessionID)
		_ = d.send(conn, transport.MsgAgentStatus, map[string]any{
			"instanceId": p.InstanceID, "status": "idle",
		})
		d.Log.Info("attach wakes hibernated instance (pty started)", "instance", p.InstanceID)
	}
	// The snapshot is sent right after the attach (durable command →
	// this worker), so any output produced since the last attach is
	// replayed before live frames for the new client (§11).
	data, lastSeq := d.terminal.snapshot(s)
	_ = d.send(conn, transport.MsgTerminalOutput, transport.TerminalOutputPayload{
		InstanceID:  p.InstanceID,
		SessionID:   p.SessionID,
		Data:        data,
		Snapshot:    true,
		LastSeq:     lastSeq,
		ConfigStale: d.configStaleFor(p.InstanceID),
	})
	return nil
}

// doDetach closes an attach session. Detach is observational — the PTY
// keeps running (§10). When it was the LAST attach, the instance returns
// to normal hibernation only if no PTY is active (§35: do not hibernate
// underneath an attached user or a live terminal).
func (d *Daemon) doDetach(conn *websocket.Conn, p transport.DetachTerminalPayload) error {
	last := d.removeAttach(p.InstanceID, p.SessionID)
	if !last {
		// Other clients still hold this instance's shared PTY: restore one
		// of their geometries — the shared size would otherwise stick
		// with the client that just left. hasSession (not active): a
		// session-driven instance's endpoint VIEW also has a shared size
		// to restore for its surviving clients (Phase 3).
		if d.terminal.hasSession(p.InstanceID) {
			d.terminal.reapplySize(p.InstanceID, p.SessionID)
		}
		return nil
	}
	if d.terminal.active(p.InstanceID) {
		// The live PTY keeps the instance awake; its exit (or an explicit
		// terminal stop) is what hibernates it.
		d.Log.Info("last attach closed; pty keeps the instance awake",
			"instance", p.InstanceID)
		return nil
	}
	row, ok, err := d.state.GetInstance(p.InstanceID)
	if err != nil || !ok {
		return nil
	}
	if d.busy(p.InstanceID) {
		// The finishing turn sees no active attach and will hibernate.
		return nil
	}
	if row.Status == "idle" {
		// Session-driven (Phase 2): the persistent endpoint is still LIVE
		// — hibernating means stopping it (session preserved), not just
		// writing the status. Same trigger, same wire shape (reason
		// attach_closed).
		if d.sessionDriverFor(row) != nil {
			return d.hibernateInstance(conn, p.InstanceID, "attach_closed")
		}
		_ = d.state.SetInstanceStatus(p.InstanceID, "hibernated", row.SessionID)
		_ = d.send(conn, transport.MsgAgentHibernated, map[string]any{
			"instanceId": p.InstanceID, "sessionId": row.SessionID,
			// No PTY is involved (or it is gone): other sessions on this
			// instance must NOT be torn down by this hibernation.
			"reason": "attach_closed",
		})
		d.reportEndpointStatus(conn, p.InstanceID) // offline (hibernated)
		d.Log.Info("last attach closed; instance hibernated", "instance", p.InstanceID)
	}
	return nil
}

// doTerminalStop kills the instance's PTY (explicit user stop; instance
// stop/restart/forget also call terminal.stop directly). Idempotent: a
// second stop is a clean no-op. When the instance is idle, it hibernates —
// the terminal is gone, so the keep-awake reason is gone too.
func (d *Daemon) doTerminalStop(conn *websocket.Conn, p transport.TerminalStopPayload) error {
	d.terminal.stop(p.InstanceID)
	row, ok, err := d.state.GetInstance(p.InstanceID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if d.busy(p.InstanceID) {
		return nil // the finishing turn settles the status
	}
	if row.Status == "idle" {
		// Session-driven (Phase 2): the persistent endpoint is still LIVE
		// — hibernating means stopping it (session preserved), not just
		// writing the status. Same trigger, same wire shape (reason
		// stopped).
		if d.sessionDriverFor(row) != nil {
			return d.hibernateInstance(conn, p.InstanceID, "stopped")
		}
		_ = d.state.SetInstanceStatus(p.InstanceID, "hibernated", row.SessionID)
		_ = d.send(conn, transport.MsgAgentHibernated, map[string]any{
			"instanceId": p.InstanceID, "sessionId": row.SessionID,
			// The stop endpoint already told its clients "stopped".
			"reason": "stopped",
		})
		d.reportEndpointStatus(conn, p.InstanceID) // offline (hibernated)
		d.Log.Info("terminal stopped; instance hibernated", "instance", p.InstanceID)
	}
	return nil
}

// doTerminalSnapshot re-emits the PTY snapshot frame for an attach
// session (addendum §11): the server requests it when a client connects
// after live output has already flowed, so the late client gets a fresh,
// bounded screen instead of a stale one. No frame when the PTY is not
// running — the session's teardown owns the waiting client.
func (d *Daemon) doTerminalSnapshot(conn *websocket.Conn, p transport.TerminalSnapshotPayload) error {
	s := d.terminal.get(p.InstanceID)
	if s == nil {
		return nil
	}
	data, lastSeq := d.terminal.snapshot(s)
	_ = d.send(conn, transport.MsgTerminalOutput, transport.TerminalOutputPayload{
		InstanceID:  p.InstanceID,
		SessionID:   p.SessionID,
		Data:        data,
		Snapshot:    true,
		LastSeq:     lastSeq,
		ConfigStale: d.configStaleFor(p.InstanceID),
	})
	return nil
}

func (d *Daemon) reportSession(conn *websocket.Conn, instanceID, sessionID string, resumed bool) {
	_ = d.send(conn, transport.MsgRuntimeSession, map[string]any{
		"instanceId":      instanceID,
		"sessionId":       sessionID,
		"resumeSupported": true,
		"state":           "active",
		"resumed":         resumed,
	})
}

// sendTurn emits a turn lifecycle event with the shared turn id.
func (d *Daemon) sendTurn(conn *websocket.Conn, msgType string, spec agentruntime.TurnSpec,
	sessionID string, inTok, outTok, cachedTok *int, model, failDetail string, retryAt *string) {
	payload := map[string]any{
		"turnId":     spec.TurnID,
		"instanceId": spec.InstanceID,
		"sessionId":  sessionID,
	}
	switch msgType {
	case transport.MsgRuntimeTurnStarted:
		payload["inputKind"] = spec.InputKind
		payload["inputSummary"] = spec.Input
	case transport.MsgRuntimeTurnCompleted:
		payload["model"] = model
		payload["inputTokens"] = inTok
		payload["outputTokens"] = outTok
		payload["cachedTokens"] = cachedTok
	case transport.MsgRuntimeTurnFailed:
		if i := strings.IndexByte(failDetail, ':'); i >= 0 {
			payload["kind"] = failDetail[:i]
			payload["error"] = failDetail[i+1:]
		} else {
			payload["kind"] = "unknown"
			payload["error"] = failDetail
		}
		// retryAt is provider-provided only; never guessed.
		if retryAt != nil {
			payload["retryAt"] = *retryAt
		}
	}
	_ = d.send(conn, msgType, payload)
}

// sendInteraction emits a normalized native-interaction observation
// (interaction.started / interaction.resolved) to the control plane. The
// pagnet-side interaction id is minted here and cached per runtime-native
// id (interactionIDs), so the later resolution reuses the same id — the
// control plane's CreateInteraction is idempotent on it. The vendor payload
// is passed through opaque (never parsed).
func (d *Daemon) sendInteraction(conn *websocket.Conn, msgType string, spec agentruntime.TurnSpec,
	sessionID, runtime string, ie *agentruntime.InteractionEvent, ids map[string]string) {
	key := ie.NativeInteractionID
	if key == "" {
		// The runtime did not name the interaction: a stable per-turn key
		// still correlates the started/resolved pair.
		key = "\x00unnamed"
	}
	id, ok := ids[key]
	if !ok {
		id = domain.NewID().String()
		ids[key] = id
	}
	corr := ie.NativeInteractionID
	payload := transport.InteractionEventPayload{
		InteractionID:       id,
		InstanceID:          spec.InstanceID,
		SessionID:           sessionID,
		Runtime:             runtime,
		NativeInteractionID: ie.NativeInteractionID,
		Kind:                ie.Kind,
		Summary:             ie.Summary,
		NativePayload:       ie.NativePayload,
		CorrelationID:       corr,
		Resolved:            ie.Resolved,
		Decision:            ie.Decision,
		Answer:              ie.Answer,
	}
	// E2EE (plan §12.3): on an active private network the interaction's
	// protected detail (summary + native payload + answer) crosses only as an
	// envelope; kind + state + ids stay plaintext. The interaction id (minted
	// above) is the object id, so the started/resolved pair share it.
	if row, ok, _ := d.state.GetInstance(spec.InstanceID); ok && row.NetworkID != "" {
		if st, ok := d.cryptoManager().NetworkCrypto(row.NetworkID); ok && st.Status == "active" && st.EpochID != "" {
			sender := row.AgentName
			if sender == "" {
				sender = row.InstanceID
			}
			plain := ie.Summary
			if len(ie.NativePayload) > 0 {
				plain += "\n" + string(ie.NativePayload)
			}
			if ie.Answer != "" {
				plain += "\nanswer: " + ie.Answer
			}
			if env, aad, err := d.encryptProtected(st, e2ee.ObjectTypeRuntimeInteraction, id, sender, "", plain); err == nil {
				payload.Summary = ""
				payload.NativePayload = nil
				payload.Answer = ""
				payload.DetailEnvelope = &env
				payload.DetailAAD = &aad
			} else {
				d.Log.Warn("interaction detail encrypt failed; observation dropped",
					"instance", spec.InstanceID, "err", err)
				return
			}
		}
	}
	_ = d.send(conn, msgType, payload)
}

// --- small platform helpers ---------------------------------------------------
// readLoadAvg / readMemInfo are platform-specific (sysinfo_linux.go,
// sysinfo_darwin.go, sysinfo_other.go).

func readDiskFree(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	// Bsize is int64 on Linux but uint32 on Darwin — normalize explicitly
	// so the daemon cross-compiles (make release).
	return int64(st.Bavail) * int64(st.Bsize), nil
}
