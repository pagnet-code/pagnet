package proc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/pagnet-code/pagnet/internal/sandbox"
)

// Operational conditions (§54): clean, machine-readable refusal errors.
// The daemon surfaces them as turn-failure details; they are NEVER
// silently retried by the daemon itself.
var (
	// ErrHostPressure: the host is at (or near) its process limit, or a
	// launch failed with EAGAIN/EMFILE/ENFILE. Launch refused.
	ErrHostPressure = errors.New("host_resource_pressure")
	// ErrLimitRefused: a pagnet-owned limit (active turns, owned
	// processes, circuit) refused the launch.
	ErrLimitRefused = errors.New("runtime_launch_refused")
	// ErrInstanceBusy: the instance already has an active turn (or PTY
	// session) — the per-instance exclusivity invariant (§27).
	ErrInstanceBusy = errors.New("instance_busy")
	// ErrShuttingDown: the supervisor is shutting down; no new launches.
	ErrShuttingDown = errors.New("supervisor shutting down")
	// ErrMarkerUnavailable: the platform cannot read another process's
	// environment (macOS), so marker-based ownership proof is impossible.
	ErrMarkerUnavailable = errors.New("process environment marker not readable on this platform")
	// ErrProcessUnkillable: the termination sequence completed but the
	// process group could NOT be killed (SIGKILL failed with a non-ESRCH
	// error, e.g. EPERM — observed live on macOS). The process is still
	// ALIVE: the supervisor keeps its ownership record (it does not
	// unregister), and the caller must settle into an honest failed
	// state — never assume the process is gone, and never wait
	// unboundedly for its exit.
	ErrProcessUnkillable = errors.New("process could not be killed")
	// ErrExitNotObserved: a bounded wait (WaitCtx/WaitDeadline) expired
	// before the process's exit was published. The process is still
	// alive (or its reap is still pending) and the supervisor keeps
	// tracking it.
	ErrExitNotObserved = errors.New("exit not observed within deadline")
	// ErrSandboxUnavailable: the launch was refused because the filesystem
	// sandbox (S2) could not be applied — on Linux there is NO fallback to
	// an unsandboxed launch (H3, fail closed). Returned when the platform
	// requires a sandbox and the spec is missing, the kernel has no
	// Landlock, or the wrapper cannot be prepared.
	ErrSandboxUnavailable = errors.New("sandbox_unavailable")
)

// IsResourcePressureError reports whether a launch error indicates host
// resource pressure (EAGAIN/EMFILE/ENFILE and friends, §34). These must
// never trigger an immediate retry storm.
func IsResourcePressureError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.ENOMEM) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.EPERM)
}

// Class is the process class the supervisor manages.
type Class int

const (
	// ClassTurn is a process-per-turn runtime process (short-lived, one
	// per active turn, isolated process group via Setpgid).
	ClassTurn Class = iota
	// ClassPTY is a long-lived interactive PTY session (the terminal
	// attach feature; isolated session via Setsid, survives turns and
	// detaches).
	ClassPTY
	// ClassEndpoint is a long-lived persistent runtime endpoint (the
	// runtime-lifecycle refactor): one per instance, isolated process
	// group via Setpgid, NOT subject to the per-turn semaphore. It
	// survives logical turns and is hibernated/woken by the session
	// core, never killed by a turn ending.
	//
	// Phase 3 (terminal session unification): launched WITH a PTYSize,
	// the endpoint OWNS its TUI PTY — the PTY slave is its controlling
	// terminal (the HUMAN plane; the runtime's TUI renders there and
	// reads human lines from it) while the caller's stdin/stdout pipes
	// remain the MACHINE plane (the JSONL control channel). The attrs
	// then use Setsid+Setctty with Ctty = the slave fd (see
	// SessionAttrsFor). Launched WITHOUT a PTYSize, the class keeps its
	// pre-Phase-3 shape byte-for-byte (Setpgid, no PTY, no controlling
	// terminal).
	ClassEndpoint
)

func (c Class) String() string {
	switch c {
	case ClassPTY:
		return "pty"
	case ClassEndpoint:
		return "endpoint"
	default:
		return "turn"
	}
}

// Key identifies one managed process: (AgentInstance, Turn). PTY
// sessions use the reserved TurnID "pty" (one per instance).
type Key struct {
	InstanceID string
	TurnID     string
}

// PTYTurnID is the reserved TurnID of an instance's PTY session.
const PTYTurnID = "pty"

// LaunchRequest describes one process launch.
type LaunchRequest struct {
	InstanceID string
	TurnID     string // "" = minted; PTYTurnID for PTY sessions
	Runtime    string
	Class      Class
	// Cmd is fully built by the caller (args, Dir, Env, and — for turn
	// classes — the stdin/stdout pipes). The supervisor owns the Start,
	// the process group, and the lifecycle from here.
	Cmd *exec.Cmd
	// PTYSize is the initial winsize for ClassPTY launches, and — for
	// ClassEndpoint launches — the marker that the endpoint OWNS its TUI
	// PTY (Phase 3 terminal session unification): a non-nil PTYSize on a
	// ClassEndpoint makes the PTY slave the endpoint's controlling
	// terminal (the human plane) while Cmd.Stdin/Stdout stay the machine
	// plane. A nil PTYSize on a ClassEndpoint keeps the pre-Phase-3
	// shape (no PTY, no controlling terminal).
	PTYSize *pty.Winsize
	// PTYStdio (ClassEndpoint only, requires a non-nil PTYSize) selects
	// the stdio-to-tty launch shape (Phase 4, Qwen Dual Output): the
	// child's stdin/stdout/stderr ARE the PTY slave — the runtime's TUI
	// renders to the PTY (stdout) and reads human input from it (stdin).
	// The machine plane must then be out-of-band (sidecar FILES, never
	// pipes): a driver that sets PTYStdio must NOT wire Cmd.Stdin/Stdout
	// to pipes (the supervisor overwrites them with the slave).
	//
	// This is the OPPOSITE of the Phase-3 pipes shape (PTYSize set,
	// PTYStdio false): there the child's stdio stays the machine pipes
	// and the PTY slave is an extra controlling-tty fd. The two shapes
	// share the same session-leader topology (Setsid, pgid == pid) and
	// the same single-handle / single-registry-entry guarantee.
	PTYStdio bool
	// Marker is the full ownership-marker env pair (e.g.
	// "PAGNET_TURN_ID=<id>") that is ALREADY in Cmd.Env; it is stored in
	// the ownership record as the restart-reconciliation proof (§42).
	Marker string
	// Sandbox is the per-instance filesystem allowlist (S2). When set and
	// the platform requires sandboxing (Linux), the supervisor rewrites
	// Cmd to launch through the sandbox wrapper (single policy point,
	// H2) BEFORE the Start — one wrap for every class (turn, endpoint,
	// PTY). nil on a platform that requires a sandbox is refused
	// (fail closed, H3); nil on a non-sandboxing platform is fine.
	Sandbox *sandbox.Spec
}

// Exit is the published result of one managed process (delivered exactly
// once on the handle's Exit channel).
type Exit struct {
	// Err is cmd.Wait()'s result (nil = clean exit 0).
	Err error
	// Reason: "exited" (natural) or "terminated:<reason>".
	Reason string
	// Forced is true when SIGKILL was required.
	Forced bool
}

// Config is the supervisor configuration (env-overridable; see
// EnvConfig). Zero fields take safe defaults.
type Config struct {
	// StateDir is where ownership records live ("" = records disabled,
	// reconciliation is a no-op).
	StateDir string
	// MaxActiveTurns: global ceiling of simultaneously active TURN
	// processes (the launch semaphore, §29).
	MaxActiveTurns int
	// TurnProcessesWarn / TurnProcessesHard: per-turn owned-process
	// thresholds (§31). Hard crossing terminates the turn group.
	TurnProcessesWarn int
	TurnProcessesHard int
	// OwnedProcessesHard: global owned-process ceiling across all active
	// turns (§32). Reaching it refuses new launches.
	OwnedProcessesHard int
	// HostPressurePct: refuse new launches at this percentage of the
	// effective soft RLIMIT_NPROC (0 = disabled, §33).
	HostPressurePct int
	// TermGrace: TERM → grace → KILL window for group termination (§23).
	TermGrace time.Duration
	// ReapWaitBound: how long a lifecycle caller (Handle.Close, the
	// launch record-failure path) waits for the supervisor-owned reap to
	// publish the exit AFTER requesting termination. A process that
	// cannot be killed (SIGKILL → EPERM) must not wedge the caller:
	// the wait expires, the caller settles into an honest failed state,
	// and the reaper keeps waiting in the background while the
	// supervisor keeps tracking the process. For a killable process the
	// reap completes in milliseconds, far inside this bound.
	ReapWaitBound time.Duration
	// BackoffMin/BackoffMax: exponential backoff bounds after
	// resource-pressure launch failures (§35).
	BackoffMin time.Duration
	BackoffMax time.Duration
	// CircuitFailures/CircuitWindow/CircuitBlock: the launch circuit
	// breaker (§35).
	CircuitFailures int
	CircuitWindow   time.Duration
	CircuitBlock    time.Duration
	// MonitorInterval: owned-process monitoring cadence (0 = 2s).
	MonitorInterval time.Duration
	// Clock is injectable for tests (no wall-clock waiting).
	Clock func() time.Time

	// processLimitFn / userProcessCountFn are test seams for the host
	// pressure guard (§33): nil = the platform implementation. They let a
	// test exercise the refusal logic deterministically without mutating
	// the host's RLIMIT_NPROC or spawning thousands of processes.
	processLimitFn     func() int
	userProcessCountFn func() (int, error)

	// countOwnedFn / groupLiveMemberFn are test seams for the
	// fail-closed-on-UNKNOWN enumeration paths (a failed process
	// enumeration is UNKNOWN, never EMPTY): nil = the platform
	// ...Err implementation. They let a test exercise the refusal and
	// reclaim-skip logic deterministically without breaking the host's
	// /proc or kern.proc.
	countOwnedFn      func(map[int]bool) (int, error)
	groupLiveMemberFn func(int) (bool, error)

	// signalGroupFn is a test seam for the managed-process group-kill
	// paths (abort, terminateGroup): nil = the platform SignalGroup. It
	// lets a test simulate an UNKILLABLE process group (the OS returns
	// EPERM on SIGKILL — the live macOS condition) deterministically,
	// without privileges or a broken host.
	signalGroupFn func(pgid int, sig syscall.Signal) error

	// SandboxWrapper is the executable that implements the sandbox
	// wrapper (the pagnet binary itself, run as its hidden
	// `sandbox-exec` subcommand, S2). "" = os.Executable(). Used only on
	// platforms where sandbox.MustSandbox() is true.
	SandboxWrapper string
	// RequireSandbox makes the supervisor refuse (fail closed, H3) any
	// launch that arrives without a Sandbox spec on a sandbox-requiring
	// platform (Linux). The daemon sets this: every managed process on
	// Linux must be sandboxed, and a spec-less launch is a caller bug,
	// never a silently-unsandboxed launch.
	RequireSandbox bool
}

// DefaultConfig returns the safe defaults (§29/§31/§32/§33/§35).
func DefaultConfig() Config {
	return Config{
		MaxActiveTurns:     4,
		TurnProcessesWarn:  64,
		TurnProcessesHard:  128,
		OwnedProcessesHard: 256,
		HostPressurePct:    80,
		TermGrace:          5 * time.Second,
		ReapWaitBound:      10 * time.Second,
		BackoffMin:         time.Second,
		BackoffMax:         30 * time.Second,
		CircuitFailures:    5,
		CircuitWindow:      60 * time.Second,
		CircuitBlock:       60 * time.Second,
		MonitorInterval:    2 * time.Second,
		Clock:              time.Now,
	}
}

// EnvConfig returns a Config populated from the PAGNET_* environment
// (env only — no DB, no files). Unset/invalid values keep the defaults.
func EnvConfig() Config {
	c := DefaultConfig()
	c.StateDir = os.Getenv("PAGNET_STATE_DIR")
	if v := envInt("PAGNET_MAX_ACTIVE_TURNS"); v > 0 {
		c.MaxActiveTurns = v
	}
	if v := envInt("PAGNET_TURN_PROCESSES_WARN"); v > 0 {
		c.TurnProcessesWarn = v
	}
	if v := envInt("PAGNET_TURN_PROCESSES_HARD"); v > 0 {
		c.TurnProcessesHard = v
	}
	if v := envInt("PAGNET_OWNED_PROCESSES_HARD"); v > 0 {
		c.OwnedProcessesHard = v
	}
	if v := envInt("PAGNET_HOST_PRESSURE_PCT"); v >= 0 {
		c.HostPressurePct = v
	}
	if v := envDuration("PAGNET_TURN_TERM_GRACE"); v > 0 {
		c.TermGrace = v
	}
	if v := envDuration("PAGNET_LAUNCH_BACKOFF_MIN"); v > 0 {
		c.BackoffMin = v
	}
	if v := envDuration("PAGNET_LAUNCH_BACKOFF_MAX"); v > 0 {
		c.BackoffMax = v
	}
	if v := envInt("PAGNET_LAUNCH_CIRCUIT_FAILURES"); v > 0 {
		c.CircuitFailures = v
	}
	if v := envDuration("PAGNET_LAUNCH_CIRCUIT_WINDOW"); v > 0 {
		c.CircuitWindow = v
	}
	if v := envDuration("PAGNET_LAUNCH_CIRCUIT_BLOCK"); v > 0 {
		c.CircuitBlock = v
	}
	return c
}

func envInt(key string) int {
	v := os.Getenv(key)
	if v == "" {
		return 0
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return 0
	}
	return n
}

func envDuration(key string) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return 0
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
		return time.Duration(n) * time.Second
	}
	return 0
}

// Lifecycle is the process-supervision surface the runtime adapters and
// the terminal manager use. The Supervisor implements it; adapters hold
// a Lifecycle so they can run standalone (their own private supervisor)
// or under the daemon's central one.
type Lifecycle interface {
	// Launch starts (or reconciles an already-started) managed process.
	// It returns the SAME handle for a duplicate (instanceID, turnID)
	// request — a duplicate never spawns a second process (§27).
	Launch(ctx context.Context, req LaunchRequest) (*Handle, error)
	// Stop terminates the instance's active turn (no-op when none).
	Stop(instanceID string) error
	// PID is the instance's active turn process id (nil when none).
	PID(instanceID string) *int
}

// EndpointLifecycle is the process-supervision surface for PERSISTENT
// runtime endpoints (the runtime-lifecycle refactor): long-lived, one per
// instance, process-group isolated, hibernated/woken by the session core
// rather than killed by a turn ending. The Supervisor implements it;
// persistent runtime drivers hold it (type-asserted from a Lifecycle,
// which the Supervisor always satisfies).
type EndpointLifecycle interface {
	// Launch starts (or reconciles an already-started) managed process.
	Launch(ctx context.Context, req LaunchRequest) (*Handle, error)
	// StopEndpoint terminates the instance's live endpoint (no-op when
	// none). It runs the standard TERM → grace → KILL sequence on the
	// endpoint's process group and returns once the signal sequence
	// completes — it does NOT wait for the process's exit (the
	// supervisor's reaper owns the reap). It returns an error wrapping
	// ErrProcessUnkillable when the group could not be killed (the
	// process is still alive and stays tracked); nil otherwise.
	StopEndpoint(instanceID string) error
	// EndpointPID is the instance's live endpoint process id (nil when
	// no endpoint is live).
	EndpointPID(instanceID string) *int
}

// Supervisor is the central turn-process supervisor (§20): one registry,
// one launch gate, one cleanup path, one set of counters.
type Supervisor struct {
	admission sync.RWMutex

	cfg Config
	log *slog.Logger
	now func() time.Time

	// Host-pressure guard sources (§33); resolved from the Config seams
	// (or the platform implementation) at construction.
	processLimitFn     func() int
	userProcessCountFn func() (int, error)

	// Fail-closed-on-UNKNOWN enumeration sources; resolved from the
	// Config seams (or the platform ...Err implementation) at
	// construction. A non-nil error from either means the enumeration
	// FAILED: the result is UNKNOWN, never empty.
	countOwnedFn      func(map[int]bool) (int, error)
	groupLiveMemberFn func(int) (bool, error)

	// Group-kill source for the managed-process paths (abort,
	// terminateGroup); resolved from the Config seam (or the platform
	// SignalGroup) at construction.
	signalGroupFn func(pgid int, sig syscall.Signal) error

	mu             sync.Mutex
	turns          map[Key]*managedTurn
	byInstance     map[string]*managedTurn
	ptyByInst      map[string]*managedTurn
	endpointByInst map[string]*managedTurn
	shuttingDown   bool

	sem chan struct{} // global turn-launch semaphore (§29)

	circMu        sync.Mutex
	circFailures  []time.Time
	circOpenUntil time.Time

	backoffMu    sync.Mutex
	backoffUntil time.Time
	backoffShift uint

	stopOnce    sync.Once
	stoppedOnce sync.Once
	stopped     chan struct{}

	monitorDone chan struct{}

	// Low-cardinality lifecycle counters (§43). IDs never appear in
	// these — they belong in structured logs.
	launchTotal       atomic.Int64
	launchFailedTotal atomic.Int64
	cleanupTotal      atomic.Int64
	forceKillTotal    atomic.Int64
	orphanReconciled  atomic.Int64
	refusedPressure   atomic.Int64
	refusedLimit      atomic.Int64
	explosionTotal    atomic.Int64
}

// NewSupervisor builds a supervisor and starts its monitor.
func NewSupervisor(cfg Config, log *slog.Logger) *Supervisor {
	if log == nil {
		log = slog.Default()
	}
	d := DefaultConfig()
	if cfg.MaxActiveTurns == 0 {
		cfg.MaxActiveTurns = d.MaxActiveTurns
	}
	if cfg.TurnProcessesWarn == 0 {
		cfg.TurnProcessesWarn = d.TurnProcessesWarn
	}
	if cfg.TurnProcessesHard == 0 {
		cfg.TurnProcessesHard = d.TurnProcessesHard
	}
	if cfg.OwnedProcessesHard == 0 {
		cfg.OwnedProcessesHard = d.OwnedProcessesHard
	}
	if cfg.HostPressurePct == 0 {
		cfg.HostPressurePct = d.HostPressurePct
	}
	if cfg.TermGrace <= 0 {
		cfg.TermGrace = d.TermGrace
	}
	if cfg.ReapWaitBound <= 0 {
		cfg.ReapWaitBound = d.ReapWaitBound
	}
	if cfg.BackoffMin <= 0 {
		cfg.BackoffMin = d.BackoffMin
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = d.BackoffMax
	}
	if cfg.CircuitFailures <= 0 {
		cfg.CircuitFailures = d.CircuitFailures
	}
	if cfg.CircuitWindow <= 0 {
		cfg.CircuitWindow = d.CircuitWindow
	}
	if cfg.CircuitBlock <= 0 {
		cfg.CircuitBlock = d.CircuitBlock
	}
	if cfg.MonitorInterval <= 0 {
		cfg.MonitorInterval = d.MonitorInterval
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	pl := cfg.processLimitFn
	if pl == nil {
		pl = ProcessLimit
	}
	upc := cfg.userProcessCountFn
	if upc == nil {
		upc = UserProcessCount
	}
	co := cfg.countOwnedFn
	if co == nil {
		co = CountOwnedErr
	}
	glm := cfg.groupLiveMemberFn
	if glm == nil {
		glm = GroupHasLiveMemberErr
	}
	sg := cfg.signalGroupFn
	if sg == nil {
		sg = SignalGroup
	}
	s := &Supervisor{
		cfg:                cfg,
		log:                log,
		now:                cfg.Clock,
		turns:              map[Key]*managedTurn{},
		byInstance:         map[string]*managedTurn{},
		ptyByInst:          map[string]*managedTurn{},
		endpointByInst:     map[string]*managedTurn{},
		sem:                make(chan struct{}, cfg.MaxActiveTurns),
		stopped:            make(chan struct{}),
		monitorDone:        make(chan struct{}),
		processLimitFn:     pl,
		userProcessCountFn: upc,
		countOwnedFn:       co,
		groupLiveMemberFn:  glm,
		signalGroupFn:      sg,
	}
	go s.monitor()
	return s
}

// Log exposes the supervisor's logger (tests).
func (s *Supervisor) Log() *slog.Logger { return s.log }

// --- launch -----------------------------------------------------------------

// Launch implements Lifecycle. See the Lifecycle docs for the dedup and
// exclusivity guarantees. The full guard order (§29: acquire the slot
// BEFORE process creation):
//
//	registry dedup → instance exclusivity → turn semaphore →
//	launch circuit → pressure backoff → host pressure →
//	owned-process ceiling → process start → register → record
func (s *Supervisor) Launch(ctx context.Context, req LaunchRequest) (*Handle, error) {
	release := s.AdmitWork()
	defer release()
	if req.Cmd == nil {
		return nil, errors.New("proc: Launch requires a Cmd")
	}
	if req.InstanceID == "" {
		return nil, errors.New("proc: Launch requires an InstanceID")
	}
	if req.TurnID == "" {
		if req.Class == ClassPTY {
			req.TurnID = PTYTurnID
		} else {
			req.TurnID = fmt.Sprintf("turn-%d", s.now().UnixNano())
		}
	}
	key := Key{InstanceID: req.InstanceID, TurnID: req.TurnID}

	// Register BEFORE starting: a concurrent duplicate of the same key
	// must see the in-flight entry and reconcile to it, never spawn a
	// second process (§27).
	s.mu.Lock()
	if s.shuttingDown {
		s.mu.Unlock()
		return nil, ErrShuttingDown
	}
	if t, ok := s.turns[key]; ok {
		s.mu.Unlock()
		s.log.Debug("launch dedup: reconciling to existing process",
			"instance", key.InstanceID, "turn", key.TurnID)
		return &Handle{t: t}, nil
	}
	switch req.Class {
	case ClassTurn:
		if t, ok := s.byInstance[key.InstanceID]; ok {
			s.mu.Unlock()
			s.refusedLimit.Add(1)
			return nil, fmt.Errorf("%w: instance %s already has an active turn (%s)",
				ErrInstanceBusy, key.InstanceID, t.TurnID)
		}
		select {
		case s.sem <- struct{}{}:
		default:
			s.mu.Unlock()
			s.refusedLimit.Add(1)
			s.log.Warn("launch refused: max active turns reached",
				"instance", key.InstanceID, "limit", s.cfg.MaxActiveTurns)
			return nil, fmt.Errorf("%w: max active turns reached (%d)",
				ErrLimitRefused, s.cfg.MaxActiveTurns)
		}
	case ClassPTY:
		if _, ok := s.ptyByInst[key.InstanceID]; ok {
			s.mu.Unlock()
			s.refusedLimit.Add(1)
			return nil, fmt.Errorf("%w: instance %s already has a live PTY session",
				ErrInstanceBusy, key.InstanceID)
		}
	case ClassEndpoint:
		// One live endpoint per instance (exclusivity). Endpoints are
		// long-lived: they do NOT take a turn-semaphore token (that would
		// cap resident endpoints at MaxActiveTurns, which is a per-TURN
		// ceiling, not a residency ceiling — addendum §20).
		//
		// §20 PROCESS SAFETY LIMITS — endpoint residency (Phase 2
		// decision, documented per the plan's "document any new ceiling"):
		//
		//   - MaxActiveTurns is LOGICAL TURN CONCURRENCY only. It bounds
		//     how many process-per-turn launches run at once; it is NOT a
		//     residency ceiling and must never be read as "maximum total
		//     AgentInstances that may remain resident forever".
		//   - Endpoint RESIDENCY is bounded naturally here: one endpoint
		//     per instance (the exclusivity check below), and instances
		//     are the unit the control plane creates/forgets. There is no
		//     unbounded per-daemon endpoint growth beyond the instance
		//     count.
		//   - NO configurable resident-endpoint limit is added (plan:
		//     "Add a configurable resident-endpoint limit only if
		//     necessary"). It is not necessary: per-instance exclusivity
		//     already bounds residency, and the OS safety nets below still
		//     apply to endpoints (they are owned processes in the same
		//     registry). If a future deployment needs a hard cap, THIS
		//     switch case is where it lives (a count of endpointByInst
		//     against a config ceiling, refused with ErrLimitRefused).
		//   - The OS safety nets are PRESERVED for endpoints: the global
		//     owned-process hard ceiling, the host-pressure guard, and the
		//     monitor's descendant-explosion detection all count endpoint
		//     groups (they are in the turns registry).
		//   - "Prefer hibernating an eligible IDLE endpoint over refusing
		//     work" (plan §20) is a FUTURE policy knob, not implemented:
		//     today a launch refused under pressure/ceiling reports its
		//     distinct operational kind (the daemon's
		//     classifyTurnError) and the control plane re-sends; the
		//     hibernate-to-make-room policy would hook in at this refusal
		//     site.
		if _, ok := s.endpointByInst[key.InstanceID]; ok {
			s.mu.Unlock()
			s.refusedLimit.Add(1)
			return nil, fmt.Errorf("%w: instance %s already has a live endpoint",
				ErrInstanceBusy, key.InstanceID)
		}
	}
	t := &managedTurn{
		s:             s,
		Key:           key,
		Class:         req.Class,
		Runtime:       req.Runtime,
		Marker:        req.Marker,
		cmd:           req.Cmd,
		startedAt:     s.now(),
		exitCh:        make(chan Exit, 1),
		termDone:      make(chan struct{}),
		launchSettled: make(chan struct{}),
	}
	defer close(t.launchSettled)
	s.turns[key] = t
	switch req.Class {
	case ClassTurn:
		s.byInstance[key.InstanceID] = t
	case ClassPTY:
		s.ptyByInst[key.InstanceID] = t
	case ClassEndpoint:
		s.endpointByInst[key.InstanceID] = t
	}
	s.mu.Unlock()

	fail := func(err error) (*Handle, error) {
		s.unregister(t)
		s.launchFailedTotal.Add(1)
		t.finishLaunchError(err)
		return nil, err
	}

	// Launch circuit: recent repeated failures block new launches (§35).
	if until, open := s.circuitOpen(); open {
		err := fmt.Errorf("%w: launch circuit open (recent repeated failures), retry after %s",
			ErrLimitRefused, until.Sub(s.now()).Round(time.Second))
		s.refusedLimit.Add(1)
		return fail(err)
	}
	// Pressure backoff: after a resource-pressure failure, wait before
	// the next attempt (exponential, §34/§35).
	if wait, active := s.backoffActive(); active {
		err := fmt.Errorf("%w: launch backoff active (resource pressure), retry after %s",
			ErrHostPressure, wait.Round(time.Millisecond))
		s.refusedPressure.Add(1)
		return fail(err)
	}
	// Host process pressure (§33): observe only, never raise limits.
	if err := s.pressureCheck(); err != nil {
		s.refusedPressure.Add(1)
		s.log.Warn("launch refused: host process pressure",
			"instance", key.InstanceID, "err", err)
		return fail(err)
	}
	// Global owned-process ceiling (§32).
	if n, err := s.ownedSnapshot(); err != nil {
		// UNKNOWN enumeration: the owned count is not "0" — launching
		// against an unverifiable ceiling is exactly the fail-open this
		// guard exists to prevent. Refuse (on a healthy machine the
		// enumeration succeeds, so this only bites when the platform's
		// process view is actually broken).
		s.refusedLimit.Add(1)
		s.log.Warn("launch refused: owned-process enumeration failed (unknown count)",
			"instance", key.InstanceID, "err", err)
		return fail(fmt.Errorf("%w: owned-process enumeration failed: %v",
			ErrLimitRefused, err))
	} else if n >= s.cfg.OwnedProcessesHard {
		err := fmt.Errorf("%w: owned processes %d at/above ceiling %d",
			ErrLimitRefused, n, s.cfg.OwnedProcessesHard)
		s.refusedLimit.Add(1)
		s.log.Warn("launch refused: owned-process ceiling",
			"instance", key.InstanceID, "owned", n, "limit", s.cfg.OwnedProcessesHard)
		return fail(err)
	}

	// Filesystem sandbox (S2) — the single policy point: every class
	// (turn, endpoint, PTY) is wrapped here, before the Start. On Linux
	// the launch FAILS CLOSED if the sandbox cannot be applied (H3):
	// spec-less launch, no Landlock, or a wrapper that cannot be
	// prepared. On platforms without Landlock (H5) nothing is wrapped —
	// the launch proceeds non-isolated and the platform is reported as
	// unsupported.
	if sandbox.MustSandbox() {
		if req.Sandbox == nil {
			if s.cfg.RequireSandbox {
				s.log.Error("launch refused: sandbox spec missing (fail closed)",
					"instance", key.InstanceID, "turn", key.TurnID, "runtime", req.Runtime)
				return fail(fmt.Errorf("%w: refusing to launch: sandbox could not be applied — launch carries no sandbox spec (fail closed)",
					ErrSandboxUnavailable))
			}
		} else {
			if !sandboxAvailable() {
				s.log.Error("launch refused: Landlock unavailable (fail closed)",
					"instance", key.InstanceID, "turn", key.TurnID, "runtime", req.Runtime,
					"kernel", sandbox.KernelRelease())
				return fail(fmt.Errorf("%w: refusing to launch: sandbox could not be applied — kernel %s requires Landlock ABI3 or newer with truncation protection (normally Linux 6.2+ with Landlock enabled; fail closed)",
					ErrSandboxUnavailable, sandbox.KernelRelease()))
			}
			if err := wrapSandboxed(&req, s.cfg.SandboxWrapper); err != nil {
				s.log.Error("launch refused: sandbox wrap failed (fail closed)",
					"instance", key.InstanceID, "turn", key.TurnID, "runtime", req.Runtime,
					"err", err)
				return fail(fmt.Errorf("%w: refusing to launch: sandbox could not be applied — %v (fail closed)",
					ErrSandboxUnavailable, err))
			}
		}
	}

	// Start the process (the supervisor is the single Start owner).
	var startErr error
	switch req.Class {
	case ClassPTY:
		ws := req.PTYSize
		if ws == nil {
			ws = &pty.Winsize{Rows: 24, Cols: 80}
		}
		var master *os.File
		master, startErr = startPollablePTY(req.Cmd, ws)
		t.ptyMaster.Store(master)
	case ClassEndpoint:
		if req.PTYSize != nil {
			// PTY-owning endpoint (Phase 3 terminal session unification,
			// topology A1): the endpoint OWNS its TUI PTY. The pair is
			// opened HERE and cmd.Start() is called directly — never
			// pty.StartWithAttrs/StartWithSize (gotcha G1): creack/pty's
			// StartWith* OVERWRITE c.SysProcAttr (dropping the Pdeathsig
			// backstop) and leave Ctty = 0, which is only valid when the
			// slave is wired to fd 0. Two launch shapes share this path:
			//
			//   - pipes (PTYStdio false, Phase 3): the child's stdio stays
			//     the MACHINE plane (the JSONL control channel — untouched)
			//     and the PTY slave is an EXTRA controlling-tty fd (the
			//     human plane). The slave must be a valid fd in the CHILD:
			//     Go validates Ctty against the child's fd list, and the
			//     kernel's TIOCSCTTY needs an open fd. os.File fds are
			//     CLOEXEC, so the slave is passed as the LAST extra file
			//     (child fd 3 + any caller extras) and Ctty points at that
			//     child fd. Ctty = 0 here would point at the machine pipe,
			//     which is not a tty — TIOCSCTTY fails and the launch dies.
			//
			//   - stdio-to-tty (PTYStdio true, Phase 4 / Qwen Dual Output):
			//     the child's stdin/stdout/stderr ARE the PTY slave — the
			//     TUI renders to the PTY (stdout) and reads human input
			//     from it (stdin). The machine plane is out-of-band
			//     (sidecar files), never pipes. The slave is wired to
			//     child fd 0, so Ctty = 0 (the slave) is CORRECT here —
			//     the G1 hazard does not apply because fd 0 IS the tty.
			ws := req.PTYSize
			master, slave, openErr := pty.Open()
			if openErr == nil {
				original := master
				master, openErr = pollablePTYMaster(original)
				if openErr != nil {
					_ = original.Close()
					_ = slave.Close()
				}
			}
			if openErr != nil {
				startErr = openErr
			} else {
				_ = pty.Setsize(master, ws)
				if req.PTYStdio {
					req.Cmd.Stdin = slave
					req.Cmd.Stdout = slave
					req.Cmd.Stderr = slave
					req.Cmd.SysProcAttr = SessionAttrsFor(0)
					startErr = req.Cmd.Start()
					// The parent keeps only the master; the child holds
					// the slave as its stdio + controlling terminal.
					_ = slave.Close()
				} else {
					ctty := 3 + len(req.Cmd.ExtraFiles)
					req.Cmd.ExtraFiles = append(req.Cmd.ExtraFiles, slave)
					req.Cmd.SysProcAttr = SessionAttrsFor(ctty)
					startErr = req.Cmd.Start()
					// The parent keeps only the master; the child holds
					// the slave as its controlling terminal (inherited
					// extra fd).
					_ = slave.Close()
				}
				if startErr == nil {
					t.ptyMaster.Store(master)
				} else {
					_ = master.Close()
				}
			}
		} else {
			// No PTY (the pre-Phase-3 endpoint shape): byte-identical to
			// today — group-isolated, no controlling terminal.
			req.Cmd.SysProcAttr = GroupAttrs()
			startErr = req.Cmd.Start()
		}
	default:
		req.Cmd.SysProcAttr = GroupAttrs()
		startErr = req.Cmd.Start()
	}
	if startErr != nil {
		if m := t.ptyMaster.Swap(nil); m != nil {
			_ = m.Close()
		}
		var err error
		if IsResourcePressureError(startErr) {
			s.recordPressureFailure()
			err = fmt.Errorf("%w: %v", ErrHostPressure, startErr)
		} else {
			s.recordFailure()
			err = startErr
		}
		s.log.Error("runtime launch failed",
			"instance", key.InstanceID, "turn", key.TurnID,
			"runtime", req.Runtime, "err", startErr)
		return fail(err)
	}

	t.pid.Store(int32(req.Cmd.Process.Pid))
	t.pgid.Store(t.pid.Load()) // the child is its own group/session leader
	if id, err := StartIdentity(int(t.pid.Load())); err == nil {
		t.identity = id
	}
	t.state.Store(stRunning)
	s.launchTotal.Add(1)
	s.resetBackoff()
	s.log.Info("process launched",
		"instance", key.InstanceID, "turn", key.TurnID,
		"runtime", req.Runtime, "class", req.Class,
		"pid", t.pid.Load(), "pgid", t.pgid.Load())

	// The supervisor owns the reap lifecycle: this dedicated reaper is
	// the SINGLE cmd.Wait owner for the child (launched exactly once,
	// here, after a successful start). It blocks in cmd.Wait until the
	// child exits, then reclaims escaped descendants and publishes the
	// exit exactly once (finish → cleanup). Callers never reap — they
	// observe the published exit (Handle.Wait / WaitCtx / WaitDeadline),
	// so a stuck or unkillable child can wedge the reaper (a
	// background goroutine that holds no lock) but never a lifecycle
	// caller.
	go t.reapOwner()

	// The durable ownership record + restart reconciliation are the
	// PRIMARY orphan-recovery mechanism (§39): the record is the ONLY
	// cross-restart memory of this tree, and a daemon crash between
	// Start and a durable record would leave a live tree that Reconcile
	// can never prove ours — and therefore can never reclaim. (The
	// Linux PDEATHSIG backstop only shrinks the direct-child part of
	// this window; it is not what makes this safe.) Fail closed:
	// terminate the tree we just started rather than run a process we
	// cannot own.
	if err := s.writeRecord(t); err != nil {
		s.log.Error("ownership record write failed; failing launch (unrecorded process = unowned process)",
			"instance", key.InstanceID, "turn", key.TurnID, "err", err)
		if terr := t.Terminate("ownership_record_failed"); terr != nil {
			s.log.Error("ownership record write failed and the process could not be killed; supervisor keeps tracking it",
				"instance", key.InstanceID, "turn", key.TurnID, "err", terr)
		}
		// The reaper (started above) owns the reap: it unregisters the
		// turn and releases the slot exactly once. The fail() helper
		// must NOT also run — it would release the slot a second time
		// (stealing another turn's semaphore token). The wait is
		// BOUNDED: an unkillable process must not wedge Launch (the
		// caller may hold the activation lock); when it expires the
		// reaper keeps waiting in the background and the supervisor
		// keeps tracking the process.
		if !t.waitForExitBounded(s.cfg.ReapWaitBound) {
			s.log.Error("ownership record write failed; process not reaped within the wait bound; supervisor keeps tracking it",
				"instance", key.InstanceID, "turn", key.TurnID, "pgid", t.pgid.Load())
		}
		s.launchFailedTotal.Add(1)
		return nil, fmt.Errorf("ownership record: %w", err)
	}

	t.ownershipPublished = true

	// Context watcher: cancellation terminates the GROUP (not just the
	// direct child). The reaper reaps; this watcher only requests
	// termination.
	go func() {
		select {
		case <-ctx.Done():
			t.Terminate("context canceled")
		case <-t.exitCh:
		}
	}()

	return &Handle{t: t}, nil
}

// sandboxAvailable is the Landlock-availability probe the launch gate
// consults (a test seam: the launch tests fake it to exercise the
// fail-closed refusal branch without a kernel that lacks Landlock).
var sandboxAvailable = sandbox.Available

// wrapSandboxed rewrites req.Cmd in place so the SUPERVISOR-STARTED process
// is the sandbox wrapper: <wrapper> sandbox-exec [--rw p]* [--ro p]*
// [--sock p]* -- <target> <args...>. The wrapper applies the sandbox to
// itself and execs the target IN PLACE (H1): the PID the supervisor started
// (and records, reaps, and S1 binds) is the runtime's PID — no grandchild.
// It fails closed on anything unusual: a relative target, a missing or
// invalid wrapper executable, or a non-normalizable spec.
func wrapSandboxed(req *LaunchRequest, wrapper string) error {
	if err := req.Sandbox.Normalize(); err != nil {
		return fmt.Errorf("sandbox spec: %w (fail closed)", err)
	}
	w := wrapper
	if w == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("sandbox wrapper (os.Executable): %w (fail closed)", err)
		}
		w = exe
	}
	if st, err := os.Stat(w); err != nil {
		return fmt.Errorf("sandbox wrapper %s: %w (fail closed)", w, err)
	} else if st.IsDir() {
		return fmt.Errorf("sandbox wrapper %s is a directory (fail closed)", w)
	}
	target := req.Cmd.Path
	if target == "" {
		target = req.Cmd.Args[0]
	}
	if !filepath.IsAbs(target) {
		// A relative target would resolve against an unknowable CWD after
		// the wrapper execs — refuse rather than guess (fail closed).
		return fmt.Errorf("sandbox target %q is not an absolute path (fail closed)", target)
	}
	req.Cmd.Path = w
	req.Cmd.Args = append([]string{w, sandbox.Subcommand},
		sandbox.WrapperArgs(req.Sandbox, target, req.Cmd.Args[1:])...)
	return nil
}

// failLaunch cleanup for a process that never started: publish the exit
// so duplicate-handle consumers observe the failure, and release.
func (t *managedTurn) finishLaunchError(err error) {
	t.state.Store(stFinished)
	t.reaped.Store(true) // no process to reap: the lifecycle is complete
	t.exitOnce.Do(func() {
		t.exitCh <- Exit{Err: err, Reason: "launch_failed"}
		close(t.exitCh)
	})
	t.s.releaseSlot(t.Class)
}

// --- registry / release ------------------------------------------------------

func (s *Supervisor) unregister(t *managedTurn) {
	s.mu.Lock()
	if cur, ok := s.turns[t.Key]; ok && cur == t {
		delete(s.turns, t.Key)
	}
	switch t.Class {
	case ClassTurn:
		if cur, ok := s.byInstance[t.InstanceID]; ok && cur == t {
			delete(s.byInstance, t.InstanceID)
		}
	case ClassPTY:
		if cur, ok := s.ptyByInst[t.InstanceID]; ok && cur == t {
			delete(s.ptyByInst, t.InstanceID)
		}
	case ClassEndpoint:
		if cur, ok := s.endpointByInst[t.InstanceID]; ok && cur == t {
			delete(s.endpointByInst, t.InstanceID)
		}
	}
	s.mu.Unlock()
}

func (s *Supervisor) releaseSlot(class Class) {
	if class != ClassTurn {
		return
	}
	select {
	case <-s.sem:
	default:
	}
}

// cleanup runs from the owner's finish: registry removal, slot release,
// record removal, counter.
func (s *Supervisor) cleanup(t *managedTurn) {
	s.unregister(t)
	s.releaseSlot(t.Class)
	s.removeRecord(t)
	s.cleanupTotal.Add(1)
}

// --- handle ------------------------------------------------------------------

// Handle is the caller's view of one managed process. It deliberately
// does not expose *exec.Cmd: callers request termination and observe the
// exit; they never reap (§25: single Wait owner).
type Handle struct {
	t *managedTurn
}

// PID is the direct child's pid (0 before start).
func (h *Handle) PID() int { return int(h.t.pid.Load()) }

// PGID is the process group id (== pid: the child is the group leader).
func (h *Handle) PGID() int { return int(h.t.pgid.Load()) }

// Exit returns the exit channel (closed exactly once after the
// supervisor's reaper reaps the process).
func (h *Handle) Exit() <-chan Exit { return h.t.exitCh }

// PTY is the PTY master (ClassPTY handles and PTY-owning ClassEndpoint
// handles; nil for turns and PTY-less endpoints). The master is owned
// by the handle: it is closed at handle cleanup, and callers (the
// terminal view, Phase 3) hold it as a VIEW and never close it.
func (h *Handle) PTY() *os.File { return h.t.ptyMaster.Load() }

// Wait blocks until the process's exit is published and returns its
// error (nil = clean exit 0). The supervisor's dedicated reaper owns
// the single cmd.Wait; Wait only observes the published exit, so it is
// safe from ANY goroutine and any number of times (idempotent: after
// the first return it returns the stored result immediately).
//
// Wait is UNBOUNDED: a stuck or unkillable child (SIGKILL → EPERM) keeps
// the reaper blocked, and with it every Wait caller. A lifecycle path
// that must not block forever (activation, stop, cleanup) must use
// WaitCtx or WaitDeadline instead — the reaper keeps running in the
// background either way, and the supervisor keeps tracking the process.
func (h *Handle) Wait() error {
	h.t.waitForExit()
	return h.t.exit().Err
}

// WaitCtx waits for the process's exit with a bound: it returns the
// published exit (err == nil) when the reaper publishes it before ctx
// is done, and (Exit{}, an error wrapping ErrExitNotObserved and
// ctx.Err()) when the bound expires first.
//
// A timeout is an HONEST observation, not a result: the process is
// still alive (or its reap still pending), the supervisor keeps
// tracking it, and the caller must settle into a failed state — it
// must not assume the process is gone. The reap itself is unaffected:
// the reaper continues in the background and publishes the exit when
// the process actually dies.
func (h *Handle) WaitCtx(ctx context.Context) (Exit, error) {
	select {
	case <-h.t.exitCh:
		return h.t.exit(), nil
	case <-ctx.Done():
		return Exit{}, fmt.Errorf("%w: %w", ErrExitNotObserved, ctx.Err())
	}
}

// WaitDeadline is WaitCtx with a plain duration deadline.
func (h *Handle) WaitDeadline(d time.Duration) (Exit, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return h.WaitCtx(ctx)
}

// Abort is the deliberate fast abort (e.g. a session mismatch): SIGKILL
// the whole group immediately, no TERM grace. The reaper reaps the
// group after it dies; observe the exit with Wait/WaitCtx/WaitDeadline.
// If the group cannot be killed (EPERM), the failure is logged with the
// process identity; the supervisor keeps tracking it.
func (h *Handle) Abort(reason string) {
	h.t.abort(reason)
}

// Terminate requests group termination from ANY goroutine (Stop,
// shutdown, monitor, ctx watcher): SIGTERM the group, wait the grace,
// SIGKILL survivors. It returns once the signal sequence completes —
// it NEVER waits for the process's exit (the reaper owns the reap), so
// it is bounded by the grace window even for an unkillable process.
// Idempotent: concurrent and repeated callers get the same result.
//
// The result is honest: nil when the group is dead (or was already
// dead), an error wrapping ErrProcessUnkillable when the group could
// NOT be killed (the process is still alive and the supervisor keeps
// tracking it).
func (h *Handle) Terminate(reason string) error {
	return h.t.Terminate(reason)
}

// Close is the defer-safe finalizer: when the reap is not complete yet
// (early return, panic unwind), it aborts the group (SIGKILL, no TERM
// grace) and waits for the reaper to publish the exit. After a normal
// Wait it is a no-op.
//
// The wait is BOUNDED (Config.ReapWaitBound): a process that cannot be
// killed (SIGKILL → EPERM) must not wedge the caller — Close returns
// when the bound expires, the reaper keeps waiting in the background,
// and the supervisor keeps tracking the process. For a killable
// process the reap completes in milliseconds, far inside the bound, so
// the observable behavior is unchanged.
func (h *Handle) Close() {
	if h.t.reaped.Load() {
		return
	}
	h.t.abort("close")
	if !h.t.waitForExitBounded(h.t.s.cfg.ReapWaitBound) {
		h.t.s.log.Error("close: process not reaped within the wait bound; supervisor keeps tracking it (reap continues in the background)",
			"instance", h.t.InstanceID, "turn", h.t.TurnID,
			"pid", h.t.pid.Load(), "pgid", h.t.pgid.Load(),
			"runtime", h.t.Runtime, "bound", h.t.s.cfg.ReapWaitBound)
	}
}

// --- managed turn ------------------------------------------------------------

const (
	stStarting = iota
	stRunning
	stStopping
	stFinished
)

type managedTurn struct {
	s *Supervisor
	Key
	Class   Class
	Runtime string
	Marker  string

	cmd *exec.Cmd
	// ptyMaster is atomic: Launch stores it (before the handle is
	// published) and finish() swaps it to nil (after the process exits)
	// from the owner's reap goroutine, while Handle.PTY() reads it from
	// other goroutines (the terminal view, Phase 3). A plain *os.File
	// would be a data race (caught by -race).
	ptyMaster atomic.Pointer[os.File]
	// pid/pgid are atomic: Launch writes them (after the process starts,
	// outside s.mu) and the monitor + Handle.PID/PGID read them from other
	// goroutines without s.mu. A plain int would be a data race (caught by
	// -race). The value is set once and never changed, so a single atomic
	// store/load is sufficient.
	pid                atomic.Int32
	pgid               atomic.Int32
	launchSettled      chan struct{}
	ownershipPublished bool
	identity           string
	startedAt          time.Time

	state atomic.Int32
	// reaped: the process's lifecycle is COMPLETE — the reaper has
	// reaped the child and published the exit (finish), or the launch
	// failed before the process started (finishLaunchError). Close uses
	// it to decide whether there is still work to do.
	reaped atomic.Bool
	// reapOwned: the dedicated reaper (reapOwner) has taken ownership of
	// the single cmd.Wait. Launched exactly once from Launch; the CAS is
	// a defensive backstop that a double launch can never double-reap
	// (a second cmd.Wait would error, and a second finish would
	// double-release the turn slot).
	reapOwned  atomic.Bool
	forced     atomic.Bool
	warnedProc atomic.Bool

	exitOnce sync.Once
	exitCh   chan Exit
	exitErr  error

	termOnce   sync.Once
	termDone   chan struct{}
	termReason atomic.Value // string
	// termErr: the honest result of the termination sequence (nil = the
	// group is dead or was already dead; non-nil = it could not be
	// killed). Written by terminateSequence BEFORE close(termDone) and
	// read by Terminate AFTER <-termDone — the channel close is the
	// happens-before edge, so no extra synchronization is needed.
	termErr error
}

// reapOwner is the supervisor's dedicated reaper for one managed
// process: the SINGLE cmd.Wait owner (§25). It is launched exactly
// once, from Launch, after a successful start — the supervisor owns the
// reap lifecycle, and callers never reap: they observe the published
// exit (Handle.Wait / WaitCtx / WaitDeadline). Because the reap lives in
// this background goroutine (which holds no runtime/session lock), a
// stuck or unkillable child (SIGKILL → EPERM) can wedge the reaper but
// never a lifecycle caller.
//
// The reap is the single finalize: reclaim any group members that
// outlived the turn, then reap the direct child exactly once. §19/§24:
// when the turn is no longer executing there must be no forgotten runtime
// process tree — a runtime that exits cleanly can still leave descendants
// behind (MCP bridges, shells, helpers), and those are the leak.
//
// The reclaim is anchored against the PID-reuse race by one check on each
// side of the reap (E2E82 hibernate/wake P0: a rep hibernates, a new turn
// launches milliseconds later, and the previous turn's termination lands
// on the new turn's still-starting process):
//
//  1. Pre-reap: the direct child is the group leader (pgid == its pid),
//     and while it is UNREAPED no other process can hold this pgid — a
//     process becomes a group leader with pgid == its pid only once that
//     pid is free, and the pid is free only after the reap. So while the
//     child is unreaped, any live group member is this turn's own
//     descendant. The check fires ONLY when the child has already EXITED
//     (zombie, ProcessIsZombie): if the child is still alive, the group
//     is the RUNNING turn itself — the reaper may legitimately Wait on a
//     live turn, and the Wait must block, not terminate it. Firing here
//     on a live child would kill the running turn (the 2026-09-16
//     TestProcessExplosion regression: an early Wait killed the
//     just-launched group before the monitor's explosion tick).
//  2. Post-reap: the child's pid is now released, so the pgid is no
//     longer anchored — a new turn may have already reused it. Live
//     survivors (possible when the child exited DURING an early Wait,
//     after check 1 skipped it because the child was alive) are
//     reclaimed only when no process currently holds the pgid number: a
//     group with that pgid must be led by a process with exactly that
//     pid, so an unheld number proves the survivors are this turn's own
//     descendants. A held number means the pid was reused by an
//     unrelated new turn — NEVER kill it (the E2E82 danger case).
//
// Both checks are zombie-aware (GroupHasLiveMember, not the signal-0
// GroupAlive): a zombie is dead and cannot be signaled into dying, so a
// clean completion with no survivors skips the termination entirely and
// returns immediately (no grace wait).
//
// Both checks are also UNKNOWN-aware (GroupHasLiveMemberErr, not the
// plain GroupHasLiveMember): a FAILED process enumeration is UNKNOWN,
// never EMPTY. When the enumeration errors, the "no live member"
// conclusion is unverifiable and the reclaim does NOT fire — it skips
// and logs. A skipped reclaim is at most a bounded leak (the post-reap
// GroupAlive verification in finish, a signal-0 probe that does not
// depend on enumeration, still catches and logs it); a false kill of a
// live group is not. This is the fix for the darwin CI false-kill
// hazard: kern.proc.all failing on the runner used to read as "empty".
//
// Edge cases:
//   - Handle.Close / launch-failure paths: abort()/Terminate() has
//     signaled the group but the child may still be ALIVE at the pre-reap
//     check. Check 1 then skips; the child dies from the in-flight group
//     signal, cmd.Wait reaps it, and check 2 reclaims anything that
//     still survives.
//   - Normal path: the child has already exited (zombie) by the time the
//     reaper's cmd.Wait returns, so the post-reap check sees only true
//     descendants; if the child was already a zombie when the reaper
//     started (a very short-lived process), the pre-reap check fires
//     instead.
//
// Single-owner by construction: Launch starts exactly one reaper per
// managed process; the reapOwned CAS is a defensive backstop that a
// double launch can never double-reap (a second cmd.Wait would error,
// and a second finish would double-release the turn slot).
func (t *managedTurn) reapOwner() {
	if !t.reapOwned.CompareAndSwap(false, true) {
		return // defensive: the single cmd.Wait is already owned
	}
	pid := int(t.pid.Load())
	pgid := int(t.pgid.Load())
	// Pre-reap descendant reclaim (anchored on the unreaped child; only
	// when the child has already exited — a live child means a running
	// turn, and this Wait must block, not terminate it).
	if pgid > 0 && ProcessIsZombie(pid) {
		live, err := t.s.groupLiveMemberFn(pgid)
		switch {
		case err != nil:
			// UNKNOWN enumeration: a failed pass is never EMPTY — the
			// group's state is unverifiable, so the reclaim must NOT
			// fire. A skipped reclaim is at most a bounded leak the
			// post-reap GroupAlive verification (signal-0, not
			// enumeration) still catches; a false kill is not.
			t.s.log.Warn("pre-reap reclaim skipped: group state unknown (enumeration failed)",
				"instance", t.InstanceID, "turn", t.TurnID, "pgid", pgid, "err", err)
		case live:
			t.s.log.Warn("reclaiming descendants that outlived the turn",
				"instance", t.InstanceID, "turn", t.TurnID, "pgid", pgid)
			t.terminateGroup()
		}
	}
	// Reap the direct child WITHOUT closing its I/O pipes. cmd.Wait()
	// would close parentIOPipes (the StdoutPipe/StderrPipe read ends) the
	// moment the child exits — but this reaper runs in the background,
	// CONCURRENTLY with the driver's stdout reads. Closing the pipe mid-
	// read makes the driver's next read fail with "file already closed"
	// instead of EOF (the opencode mid-turn-death regression). In the
	// pre-reap-owner design the driver WAS the cmd.Wait owner and called
	// it only after draining, so the close always followed the reads.
	//
	// cmd.Process.Wait() performs the same single waitpid (the child is
	// reaped exactly once) and returns the same exit status, but leaves
	// the pipes open: the driver finishes draining and closes what it
	// owns, and the remaining parent ends are released when the cmd is
	// garbage-collected after the turn is unregistered. The exit status
	// is converted exactly as cmd.Wait() does (nil on success, an
	// *exec.ExitError on a non-zero exit).
	state, waitErr := t.cmd.Process.Wait()
	if waitErr == nil && !state.Success() {
		waitErr = &exec.ExitError{ProcessState: state}
	}
	// Post-reap descendant reclaim (early-Wait case: the child exited
	// during the Wait above). Fire only when the pgid number is unheld —
	// a held number is a pid reused by an unrelated new turn (E2E82):
	// never kill.
	if pgid > 0 && !ProcessAlive(pgid) {
		live, err := t.s.groupLiveMemberFn(pgid)
		switch {
		case err != nil:
			// UNKNOWN enumeration: the "no live member" conclusion is
			// unverifiable, so the reclaim must NOT fire (the
			// false-kill-on-broken-enumeration hazard). Same bounded-leak
			// trade-off as the pre-reap check.
			t.s.log.Warn("post-reap reclaim skipped: group state unknown (enumeration failed)",
				"instance", t.InstanceID, "turn", t.TurnID, "pgid", pgid, "err", err)
		case live:
			t.s.log.Warn("reclaiming descendants that outlived the turn (post-reap)",
				"instance", t.InstanceID, "turn", t.TurnID, "pgid", pgid)
			// Best-effort reclaim: a kill failure (EPERM) is logged
			// inside terminateGroup; the reap of the direct child
			// proceeds regardless (the post-reap GroupAlive
			// verification in finish catches any survivor).
			t.terminateGroup()
		}
	}
	t.finish(waitErr)
}

func (t *managedTurn) exit() Exit {
	reason := "exited"
	if r, _ := t.termReason.Load().(string); r != "" {
		reason = "terminated:" + r
	}
	return Exit{Err: t.exitErr, Reason: reason, Forced: t.forced.Load()}
}

// waitForExit blocks until the reaper publishes the exit (unbounded).
func (t *managedTurn) waitForExit() {
	<-t.exitCh
}

// waitForExitBounded reports whether the reaper published the exit
// within d. It is the bounded observation the lifecycle callers use
// (Close, the launch record-failure path) so an unkillable process can
// never wedge them.
func (t *managedTurn) waitForExitBounded(d time.Duration) bool {
	select {
	case <-t.exitCh:
		return true
	case <-time.After(d):
		return false
	}
}

// finish publishes the exit exactly once and releases the turn. It runs
// in the reaper (the single cmd.Wait owner) — or, for a launch that
// never started, in finishLaunchError — so the reap, the exit
// publication, and the cleanup each happen exactly once.
func (t *managedTurn) finish(waitErr error) Exit {
	t.reaped.Store(true)
	t.exitErr = waitErr
	t.state.Store(stFinished)
	exit := t.exit()
	// Cleanup (unregister, slot release, record removal, counter) runs
	// BEFORE the exit is published. Callers observe the published exit
	// (Wait / WaitCtx / WaitDeadline / WaitForStop) and must see the
	// process fully cleaned up at the moment they observe it — the
	// registry entry gone and the slot released. This preserves the
	// pre-reap-owner observable ordering: after the exit is observed,
	// the process is no longer tracked. (Publishing first would let an
	// observer read a stale registry entry in the gap before cleanup.)
	t.s.cleanup(t)
	// PTY master backstop close (cmd.Wait already closed it via the
	// descriptor cleanup; this covers the launch-failure path).
	if m := t.ptyMaster.Swap(nil); m != nil {
		_ = m.Close()
	}
	t.exitOnce.Do(func() {
		t.exitCh <- exit
		close(t.exitCh)
	})
	// Post-reap group verification (§23): the direct child is reaped, so
	// any survivor is an escaped descendant — log it, never chase it by
	// name (§41/§56).
	if pgid := int(t.pgid.Load()); pgid > 0 && GroupAlive(pgid) {
		t.s.log.Warn("process group still alive after turn exit (escaped descendants)",
			"instance", t.InstanceID, "turn", t.TurnID, "pgid", pgid)
	}
	return exit
}

// abort: immediate group KILL (fast path — Close, Handle.Abort).
// If the KILL fails with a non-ESRCH error (EPERM: the process cannot
// be killed), the failure is logged with the full process identity and
// the supervisor keeps tracking the process — the reaper stays blocked
// in cmd.Wait in the background, and the caller's bounded wait
// (waitForExitBounded) settles the lifecycle honestly.
func (t *managedTurn) abort(reason string) {
	if t.state.Load() == stFinished {
		return
	}
	t.state.Store(stStopping)
	if t.termReason.Load() == nil {
		t.termReason.Store(reason)
	}
	if pgid := int(t.pgid.Load()); pgid > 0 {
		if err := t.s.signalGroupFn(pgid, syscall.SIGKILL); err != nil && !errors.Is(err, ErrGroupGone) {
			t.s.log.Error("process could not be killed",
				"instance", t.InstanceID, "turn", t.TurnID,
				"pid", t.pid.Load(), "pgid", pgid,
				"runtime", t.Runtime, "reason", reason, "err", err)
		}
		t.forced.Store(true)
		t.s.forceKillTotal.Add(1)
	}
}

// Terminate: external TERM → grace → KILL sequence (idempotent; the
// first caller runs it, the rest wait for it). It returns the honest
// result of the sequence: nil when the group is dead (or was already
// dead), an error wrapping ErrProcessUnkillable when the group could
// NOT be killed (the process is still alive and stays tracked). It
// never waits for the process's exit — the reaper owns the reap.
func (t *managedTurn) Terminate(reason string) error {
	t.termOnce.Do(func() {
		go t.terminateSequence(reason)
	})
	<-t.termDone
	return t.termErr
}

func (t *managedTurn) terminateSequence(reason string) {
	defer close(t.termDone)
	if t.state.Load() == stFinished {
		return // already dead: the termination "succeeded" (no-op)
	}
	t.state.Store(stStopping)
	if t.termReason.Load() == nil {
		t.termReason.Store(reason)
	}
	t.s.log.Info("terminating process group",
		"instance", t.InstanceID, "turn", t.TurnID,
		"pgid", t.pgid.Load(), "reason", reason)
	// The honest result of the sequence (nil = group dead; non-nil =
	// could not be killed). Stored before close(termDone) — the close
	// is the happens-before edge for Terminate's read.
	t.termErr = t.terminateGroup()
	// The reaper reaps after the group dies; do not wait on the exit
	// here (waiting on the exitCh would deadlock the abort path).
}

// terminateGroup runs TERM → grace → KILL on the process group, polling
// for ACTUAL group death instead of a fixed sleep: a group whose members
// all die on TERM returns well before the grace, and an already-dead
// group returns immediately.
//
// The poll uses GroupHasLiveMemberErr (zombie-aware, error-surfacing),
// NOT GroupAlive (signal-0): a zombie is a dead process awaiting reap
// and cannot be signaled into dying. The turn's direct child is
// typically a zombie at this point (it exited, and the owner reaps it
// via cmd.Wait AFTER this returns) — waiting on it would burn the full
// grace window for nothing (the 2026-09-15 5s-per-cycle leak-test
// regression). Only LIVE descendants (shells, MCP bridges, helpers) are
// worth waiting for.
//
// The poll is also UNKNOWN-aware: a FAILED enumeration is treated as
// "still alive", never as "dead". A termination that cannot be verified
// as complete must escalate to KILL at the deadline — exiting early on
// an unverifiable "dead" would leave a live group behind (the same
// UNKNOWN-never-EMPTY invariant as the reclaim and ceiling paths).
//
// Idempotent and safe to run concurrently from the external Terminate
// path and the reaper's post-reap descendant reclaim (signaling a dead
// group is a no-op; the forced flag is atomic).
//
// The result is honest: nil when the group is verified dead (or the
// KILL succeeded), an error wrapping ErrProcessUnkillable when the
// final KILL failed with a non-ESRCH error (e.g. EPERM — the OS
// refuses to kill the group; observed live on macOS). In that case the
// failure is logged with the full process identity, and the caller
// (Terminate) surfaces it so the higher-level lifecycle settles into a
// failed state — the process is NOT assumed gone, and the supervisor
// keeps tracking it.
func (t *managedTurn) terminateGroup() error {
	pgid := int(t.pgid.Load())
	if pgid <= 0 {
		return nil
	}
	if err := t.s.signalGroupFn(pgid, syscall.SIGTERM); err != nil && !errors.Is(err, ErrGroupGone) {
		t.s.log.Warn("group TERM failed", "pgid", pgid, "err", err)
	}
	deadline := t.s.now().Add(t.s.cfg.TermGrace)
	for t.s.now().Before(deadline) {
		live, err := t.s.groupLiveMemberFn(pgid)
		if err == nil && !live {
			return nil // group verified dead
		}
		// live, or UNKNOWN (enumeration failed): keep waiting.
		time.Sleep(50 * time.Millisecond)
	}
	live, err := t.s.groupLiveMemberFn(pgid)
	if err != nil || live {
		// still live, or UNKNOWN at the deadline: KILL (fail closed).
		if killErr := t.s.signalGroupFn(pgid, syscall.SIGKILL); killErr == nil {
			t.forced.Store(true)
			t.s.forceKillTotal.Add(1)
			return nil
		} else if !errors.Is(killErr, ErrGroupGone) {
			// The OS refused the KILL (EPERM or another non-ESRCH
			// error): the process is still alive. Log the full
			// identity and report the honest failure — never pretend
			// the process is gone.
			t.s.log.Error("process could not be killed",
				"instance", t.InstanceID, "turn", t.TurnID,
				"pid", t.pid.Load(), "pgid", pgid,
				"runtime", t.Runtime, "err", killErr)
			return fmt.Errorf("%w: pid=%d pgid=%d runtime=%s instance=%s: %v",
				ErrProcessUnkillable, t.pid.Load(), pgid, t.Runtime, t.InstanceID, killErr)
		}
	}
	return nil
}

// --- Stop / PID (Lifecycle) ---------------------------------------------------

// Stop terminates the instance's active turn (§24: explicit stop). It
// runs the standard TERM → grace → KILL sequence and returns once the
// signal sequence completes — it does NOT wait for the reap (the
// reaper owns it; WaitForStop observes the bounded reap). It returns an
// error wrapping ErrProcessUnkillable when the turn's group could not
// be killed (the process is still alive and stays tracked).
func (s *Supervisor) Stop(instanceID string) error {
	s.mu.Lock()
	t := s.byInstance[instanceID]
	s.mu.Unlock()
	if t == nil {
		return nil
	}
	return t.Terminate("stopped")
}

// WaitForStop waits (up to timeout) for the instance's active turn to be
// fully reaped and unregistered (external audit F-004). Stop is async:
// Terminate initiates the kill, and the reaper's reap (which unregisters
// the turn from byInstance) follows independently. A Stop→immediate-Start
// that does not wait would race the reap and hit ErrInstanceBusy while the
// old turn is still registered. Returns true when the turn is gone (or was
// never there); false when the reap did not complete in time (including
// an unkillable process — the caller settles into a failed state).
func (s *Supervisor) WaitForStop(instanceID string, timeout time.Duration) bool {
	s.mu.Lock()
	t := s.byInstance[instanceID]
	s.mu.Unlock()
	if t == nil {
		return true
	}
	select {
	case <-t.exitCh:
	case <-time.After(timeout):
		return false
	}
	// The reaper unregisters the turn (cleanup) BEFORE publishing the
	// exit (same goroutine), so byInstance is already cleared when the
	// exit is observed. The short re-poll is a defensive confirmation.
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		gone := s.byInstance[instanceID] == nil
		s.mu.Unlock()
		if gone {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

// PID reports the instance's active turn pid (nil when none).
func (s *Supervisor) PID(instanceID string) *int {
	s.mu.Lock()
	t := s.byInstance[instanceID]
	s.mu.Unlock()
	if t == nil || t.pid.Load() == 0 {
		return nil
	}
	p := int(t.pid.Load())
	return &p
}

// StopPTY terminates the instance's PTY session (no-op when none). It
// runs the standard TERM → grace → KILL sequence and returns once the
// signal sequence completes — it does NOT wait for the reap (the reaper
// owns it). It returns an error wrapping ErrProcessUnkillable when the
// session's group could not be killed (the process is still alive and
// stays tracked).
func (s *Supervisor) StopPTY(instanceID string) error {
	s.mu.Lock()
	t := s.ptyByInst[instanceID]
	s.mu.Unlock()
	if t == nil {
		return nil
	}
	return t.Terminate("stopped")
}

// StopEndpoint terminates the instance's live persistent endpoint (no-op
// when none). It runs the standard TERM → grace → KILL sequence on the
// endpoint's process group and returns once the signal sequence
// completes; the reaper's reap follows independently. It returns an
// error wrapping ErrProcessUnkillable when the endpoint's group could
// not be killed (the process is still alive and stays tracked — the
// record is what refuses a second endpoint for the instance).
func (s *Supervisor) StopEndpoint(instanceID string) error {
	s.mu.Lock()
	t := s.endpointByInst[instanceID]
	s.mu.Unlock()
	if t == nil {
		return nil
	}
	return t.Terminate("stopped")
}

// EndpointPID reports the instance's live endpoint process id (nil when no
// endpoint is live).
func (s *Supervisor) EndpointPID(instanceID string) *int {
	s.mu.Lock()
	t := s.endpointByInst[instanceID]
	s.mu.Unlock()
	if t == nil || t.pid.Load() == 0 {
		return nil
	}
	p := int(t.pid.Load())
	return &p
}

// PTYPID reports the instance's live PTY session process id (nil when no
// PTY session is live). Read-only accessor in the style of PID/EndpointPID
// (the agent-bridge process-tree binding needs the PTY root — the runtime a
// PTY attach spawned is the root its bridge must descend from); it does not
// touch launch/reap/termination behavior.
func (s *Supervisor) PTYPID(instanceID string) *int {
	s.mu.Lock()
	t := s.ptyByInst[instanceID]
	s.mu.Unlock()
	if t == nil || t.pid.Load() == 0 {
		return nil
	}
	p := int(t.pid.Load())
	return &p
}

// EndpointCount is the number of live ClassEndpoint handles. The
// auto-update idle gate uses it (Phase 3 A7): a re-exec with a live
// endpoint would orphan it — the endpoint outlives turns, so nothing
// else would stop it.
func (s *Supervisor) EndpointCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.endpointByInst)
}

// --- guards ------------------------------------------------------------------

// pressureCheck refuses the launch when the user's process count is at
// or above HostPressurePct of the effective soft RLIMIT_NPROC (§33).
// When the platform exposes no finite limit, it falls back to the
// owned-process limits (do not guess).
func (s *Supervisor) pressureCheck() error {
	if s.cfg.HostPressurePct <= 0 {
		return nil
	}
	limit := s.processLimitFn()
	if limit <= 0 {
		return nil // unknown: owned-process limits still apply
	}
	count, err := s.userProcessCountFn()
	if err != nil {
		return nil // unreadable: owned-process limits still apply
	}
	if count*100 >= s.cfg.HostPressurePct*limit {
		return fmt.Errorf("%w: user process count %d at/above %d%% of limit %d",
			ErrHostPressure, count, s.cfg.HostPressurePct, limit)
	}
	return nil
}

// ownedSnapshot counts processes in all currently owned groups. A
// non-nil error means the enumeration FAILED: the count is UNKNOWN, not
// zero (the caller must fail closed, not read it as "no owned
// processes").
func (s *Supervisor) ownedSnapshot() (int, error) {
	s.mu.Lock()
	groups := make(map[int]bool, len(s.turns))
	for _, t := range s.turns {
		if pgid := int(t.pgid.Load()); pgid > 0 {
			groups[pgid] = true
		}
	}
	s.mu.Unlock()
	return s.countOwnedFn(groups)
}

// --- circuit / backoff ---------------------------------------------------------

func (s *Supervisor) circuitOpen() (time.Time, bool) {
	s.circMu.Lock()
	defer s.circMu.Unlock()
	now := s.now()
	if !s.circOpenUntil.IsZero() && now.Before(s.circOpenUntil) {
		return s.circOpenUntil, true
	}
	if !s.circOpenUntil.IsZero() {
		// Expired: the window restarts clean.
		s.circOpenUntil = time.Time{}
		s.circFailures = nil
	}
	return time.Time{}, false
}

// recordFailure registers one launch failure; opens the circuit after
// CircuitFailures failures inside CircuitWindow (§35).
func (s *Supervisor) recordFailure() {
	now := s.now()
	s.circMu.Lock()
	s.circFailures = append(s.circFailures, now)
	cut := now.Add(-s.cfg.CircuitWindow)
	i := 0
	for i < len(s.circFailures) && s.circFailures[i].Before(cut) {
		i++
	}
	s.circFailures = s.circFailures[i:]
	if len(s.circFailures) >= s.cfg.CircuitFailures && !now.Before(s.circOpenUntil) {
		s.circOpenUntil = now.Add(s.cfg.CircuitBlock)
		s.log.Error("launch circuit OPEN: repeated launch failures",
			"failures", len(s.circFailures), "window", s.cfg.CircuitWindow,
			"block", s.cfg.CircuitBlock)
	}
	s.circMu.Unlock()
}

// recordPressureFailure: a resource-pressure failure additionally arms
// the exponential backoff (BackoffMin * 2^shift, capped at BackoffMax,
// with jitter, §34/§35).
func (s *Supervisor) recordPressureFailure() {
	s.recordFailure()
	s.backoffMu.Lock()
	defer s.backoffMu.Unlock()
	// Exponential: BackoffMin * 2^shift, capped at BackoffMax. The shift
	// is bounded so the left shift cannot overflow a time.Duration
	// (int64 nanoseconds) before the cap is applied.
	shift := s.backoffShift
	if shift > 30 {
		shift = 30
	}
	backoff := s.cfg.BackoffMin << shift
	if backoff <= 0 || backoff > s.cfg.BackoffMax {
		backoff = s.cfg.BackoffMax
	}
	jitter := time.Duration(rand.Int63n(int64(backoff)/2 + 1))
	s.backoffUntil = s.now().Add(backoff + jitter)
	if s.backoffShift < 30 {
		s.backoffShift++
	}
	s.log.Warn("launch backoff armed (resource pressure)",
		"retry_after", (backoff + jitter).Round(time.Millisecond))
}

func (s *Supervisor) backoffActive() (time.Duration, bool) {
	s.backoffMu.Lock()
	defer s.backoffMu.Unlock()
	now := s.now()
	if s.backoffUntil.IsZero() || !now.Before(s.backoffUntil) {
		return 0, false
	}
	return s.backoffUntil.Sub(now), true
}

func (s *Supervisor) resetBackoff() {
	s.backoffMu.Lock()
	s.backoffUntil = time.Time{}
	s.backoffShift = 0
	s.backoffMu.Unlock()
}

// --- monitor -------------------------------------------------------------------

// monitor bounds runaway process trees (§30/§31): per-turn counts
// (warn/terminate) and the global owned total (refuse new launches).
func (s *Supervisor) monitor() {
	defer close(s.monitorDone)
	ticker := time.NewTicker(s.cfg.MonitorInterval)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		if s.shuttingDown {
			s.mu.Unlock()
			return
		}
		turns := make([]*managedTurn, 0, len(s.turns))
		groups := make(map[int]bool, len(s.turns))
		for _, t := range s.turns {
			if pgid := int(t.pgid.Load()); pgid > 0 {
				turns = append(turns, t)
				groups[pgid] = true
			}
		}
		s.mu.Unlock()
		if len(groups) == 0 {
			continue
		}
		counts := CountGroups(groups)
		total := 0
		for _, n := range counts {
			total += n
		}
		for _, t := range turns {
			pgid := int(t.pgid.Load())
			n := counts[pgid]
			switch {
			case n >= s.cfg.TurnProcessesHard:
				s.explosionTotal.Add(1)
				s.log.Error("turn process explosion — terminating group",
					"instance", t.InstanceID, "turn", t.TurnID,
					"pgid", pgid, "processes", n, "limit", s.cfg.TurnProcessesHard)
				t.Terminate("process_explosion")
				s.recordFailure() // apply the retry circuit breaker (§31)
			case n >= s.cfg.TurnProcessesWarn:
				if t.warnedProc.CompareAndSwap(false, true) {
					s.log.Warn("turn process count high",
						"instance", t.InstanceID, "turn", t.TurnID,
						"pgid", pgid, "processes", n, "warn", s.cfg.TurnProcessesWarn)
				}
			}
		}
		if total >= s.cfg.OwnedProcessesHard {
			s.log.Error("global owned-process ceiling reached — new launches will be refused",
				"owned", total, "limit", s.cfg.OwnedProcessesHard)
		}
	}
}

// --- shutdown ------------------------------------------------------------------

// StopAll shuts the supervisor down: no new launches, TERM → grace →
// KILL every active group, wait for all reaps within the deadline
// (§38). Returns the number of processes that did not finish in time.
func (s *Supervisor) StopAll(deadline time.Duration) int {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.shuttingDown = true
		turns := make([]*managedTurn, 0, len(s.turns))
		for _, t := range s.turns {
			turns = append(turns, t)
		}
		s.mu.Unlock()

		for _, t := range turns {
			t.Terminate("shutdown")
		}
	})
	deadlineAt := time.Now().Add(deadline)
	survivors := 0
	for {
		s.mu.Lock()
		pending := make([]*managedTurn, 0, len(s.turns))
		for _, t := range s.turns {
			if t.state.Load() != stFinished {
				pending = append(pending, t)
			}
		}
		s.mu.Unlock()
		if len(pending) == 0 {
			break
		}
		if time.Now().After(deadlineAt) {
			survivors = len(pending)
			for _, t := range pending {
				s.log.Error("shutdown deadline reached; process group not reaped",
					"instance", t.InstanceID, "turn", t.TurnID, "pgid", t.pgid.Load())
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.stoppedOnce.Do(func() { close(s.stopped) })
	return survivors
}

// Stopped is closed when StopAll completes.
func (s *Supervisor) Stopped() <-chan struct{} { return s.stopped }

// --- stats (§43) ---------------------------------------------------------------

// Stats is the supervisor's low-cardinality counter snapshot (no IDs).
type Stats struct {
	ActiveTurns         int
	ActivePTYs          int
	ActiveEndpoints     int
	ActiveProcessGroups int
	LaunchTotal         int64
	LaunchFailedTotal   int64
	CleanupTotal        int64
	ForceKillTotal      int64
	OrphanReconciled    int64
	RefusedPressure     int64
	RefusedLimit        int64
	ExplosionTotal      int64
	CircuitOpen         bool
	BackoffActive       bool
}

func (s *Supervisor) Stats() Stats {
	s.mu.Lock()
	st := Stats{
		ActiveTurns:         len(s.byInstance),
		ActivePTYs:          len(s.ptyByInst),
		ActiveEndpoints:     len(s.endpointByInst),
		ActiveProcessGroups: len(s.turns),
	}
	s.mu.Unlock()
	st.LaunchTotal = s.launchTotal.Load()
	st.LaunchFailedTotal = s.launchFailedTotal.Load()
	st.CleanupTotal = s.cleanupTotal.Load()
	st.ForceKillTotal = s.forceKillTotal.Load()
	st.OrphanReconciled = s.orphanReconciled.Load()
	st.RefusedPressure = s.refusedPressure.Load()
	st.RefusedLimit = s.refusedLimit.Load()
	st.ExplosionTotal = s.explosionTotal.Load()
	_, st.CircuitOpen = s.circuitOpen()
	_, st.BackoffActive = s.backoffActive()
	return st
}
