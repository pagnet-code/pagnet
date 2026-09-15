package proc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
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
)

func (c Class) String() string {
	if c == ClassPTY {
		return "pty"
	}
	return "turn"
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
	// PTYSize is the initial winsize for ClassPTY launches.
	PTYSize *pty.Winsize
	// Marker is the full ownership-marker env pair (e.g.
	// "PAGNET_TURN_ID=<id>") that is ALREADY in Cmd.Env; it is stored in
	// the ownership record as the restart-reconciliation proof (§42).
	Marker string
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

// Supervisor is the central turn-process supervisor (§20): one registry,
// one launch gate, one cleanup path, one set of counters.
type Supervisor struct {
	cfg Config
	log *slog.Logger
	now func() time.Time

	// Host-pressure guard sources (§33); resolved from the Config seams
	// (or the platform implementation) at construction.
	processLimitFn     func() int
	userProcessCountFn func() (int, error)

	mu           sync.Mutex
	turns        map[Key]*managedTurn
	byInstance   map[string]*managedTurn
	ptyByInst    map[string]*managedTurn
	shuttingDown bool

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
	s := &Supervisor{
		cfg:                cfg,
		log:                log,
		now:                cfg.Clock,
		turns:              map[Key]*managedTurn{},
		byInstance:         map[string]*managedTurn{},
		ptyByInst:          map[string]*managedTurn{},
		sem:                make(chan struct{}, cfg.MaxActiveTurns),
		stopped:            make(chan struct{}),
		monitorDone:        make(chan struct{}),
		processLimitFn:     pl,
		userProcessCountFn: upc,
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
	}
	t := &managedTurn{
		s:         s,
		Key:       key,
		Class:     req.Class,
		Runtime:   req.Runtime,
		Marker:    req.Marker,
		cmd:       req.Cmd,
		startedAt: s.now(),
		exitCh:    make(chan Exit, 1),
		termDone:  make(chan struct{}),
	}
	s.turns[key] = t
	if req.Class == ClassTurn {
		s.byInstance[key.InstanceID] = t
	} else {
		s.ptyByInst[key.InstanceID] = t
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
	if n := s.ownedSnapshot(); n >= s.cfg.OwnedProcessesHard {
		err := fmt.Errorf("%w: owned processes %d at/above ceiling %d",
			ErrLimitRefused, n, s.cfg.OwnedProcessesHard)
		s.refusedLimit.Add(1)
		s.log.Warn("launch refused: owned-process ceiling",
			"instance", key.InstanceID, "owned", n, "limit", s.cfg.OwnedProcessesHard)
		return fail(err)
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
		master, startErr = pty.StartWithAttrs(req.Cmd, ws, SessionAttrs())
		t.ptyMaster = master
	default:
		req.Cmd.SysProcAttr = GroupAttrs()
		startErr = req.Cmd.Start()
	}
	if startErr != nil {
		if t.ptyMaster != nil {
			_ = t.ptyMaster.Close()
			t.ptyMaster = nil
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

	_ = s.writeRecord(t)

	// Context watcher: cancellation terminates the GROUP (not just the
	// direct child). The owner goroutine (the adapter's turn loop / the
	// terminal exit loop) reaps; this watcher only requests termination.
	go func() {
		select {
		case <-ctx.Done():
			t.Terminate("context canceled")
		case <-t.exitCh:
		}
	}()

	return &Handle{t: t}, nil
}

// failLaunch cleanup for a process that never started: publish the exit
// so duplicate-handle consumers observe the failure, and release.
func (t *managedTurn) finishLaunchError(err error) {
	t.state.Store(stFinished)
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
	if t.Class == ClassTurn {
		if cur, ok := s.byInstance[t.InstanceID]; ok && cur == t {
			delete(s.byInstance, t.InstanceID)
		}
	} else {
		if cur, ok := s.ptyByInst[t.InstanceID]; ok && cur == t {
			delete(s.ptyByInst, t.InstanceID)
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

// Exit returns the exit channel (closed exactly once after the owner
// reaps).
func (h *Handle) Exit() <-chan Exit { return h.t.exitCh }

// PTY is the PTY master (ClassPTY handles only; nil for turns).
func (h *Handle) PTY() *os.File { return h.t.ptyMaster }

// Wait is the OWNER's reap: call it exactly once, from the goroutine
// that read the process's stdout (turn) or owns the session (PTY),
// AFTER all reads are done. It performs the single cmd.Wait, publishes
// the exit, closes the PTY master, and releases the turn's resources.
// Idempotent: a second call returns the stored result.
func (h *Handle) Wait() error {
	exit, _ := h.t.ownerWait()
	return exit.Err
}

// Abort is the OWNER's deliberate fast abort (e.g. a session mismatch):
// SIGKILL the whole group immediately, no TERM grace. The owner then
// calls Wait.
func (h *Handle) Abort(reason string) {
	h.t.abort(reason)
}

// Terminate requests group termination from ANY goroutine (Stop,
// shutdown, monitor, ctx watcher): SIGTERM the group, wait the grace,
// SIGKILL survivors. It returns once the signal sequence completes —
// the owner's reap follows independently. Idempotent.
func (h *Handle) Terminate(reason string) {
	h.t.Terminate(reason)
}

// Close is the defer-safe finalizer: when the owner has not reaped yet
// (early return, panic unwind), it aborts the group and reaps. After a
// normal Wait it is a no-op.
func (h *Handle) Close() {
	if !h.t.reaped.Load() {
		h.t.abort("close")
		h.t.ownerWait()
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

	cmd       *exec.Cmd
	ptyMaster *os.File
	// pid/pgid are atomic: Launch writes them (after the process starts,
	// outside s.mu) and the monitor + Handle.PID/PGID read them from other
	// goroutines without s.mu. A plain int would be a data race (caught by
	// -race). The value is set once and never changed, so a single atomic
	// store/load is sufficient.
	pid       atomic.Int32
	pgid      atomic.Int32
	identity  string
	startedAt time.Time

	state      atomic.Int32
	reaped     atomic.Bool
	forced     atomic.Bool
	warnedProc atomic.Bool

	exitOnce sync.Once
	exitCh   chan Exit
	exitErr  error

	termOnce   sync.Once
	termDone   chan struct{}
	termReason atomic.Value // string
}

// ownerWait is the single finalize: reap the direct child exactly once,
// then reclaim any group members that outlived it. §19/§24: when the turn
// is no longer executing there must be no forgotten runtime process tree —
// a runtime that exits cleanly can still leave descendants behind (MCP
// bridges, shells, helpers), and those are the leak. Reaping the direct
// child first means GroupAlive then reflects ONLY descendants, so a clean
// completion with no survivors returns immediately (no grace wait).
// Idempotent: only the first caller reaps; the rest observe the exit.
func (t *managedTurn) ownerWait() (Exit, error) {
	if !t.reaped.CompareAndSwap(false, true) {
		t.waitForExit()
		return t.exit(), nil
	}
	waitErr := t.cmd.Wait()
	if pgid := int(t.pgid.Load()); pgid > 0 && GroupAlive(pgid) {
		t.s.log.Warn("reclaiming descendants that outlived the turn",
			"instance", t.InstanceID, "turn", t.TurnID, "pgid", pgid)
		t.terminateGroup()
	}
	return t.finish(waitErr), nil
}

func (t *managedTurn) exit() Exit {
	reason := "exited"
	if r, _ := t.termReason.Load().(string); r != "" {
		reason = "terminated:" + r
	}
	return Exit{Err: t.exitErr, Reason: reason, Forced: t.forced.Load()}
}

func (t *managedTurn) waitForExit() {
	<-t.exitCh
}

// finish publishes the exit exactly once and releases the turn.
func (t *managedTurn) finish(waitErr error) Exit {
	t.exitErr = waitErr
	t.state.Store(stFinished)
	exit := t.exit()
	t.exitOnce.Do(func() {
		t.exitCh <- exit
		close(t.exitCh)
	})
	// PTY master backstop close (cmd.Wait already closed it via the
	// descriptor cleanup; this covers the launch-failure path).
	if t.ptyMaster != nil {
		_ = t.ptyMaster.Close()
		t.ptyMaster = nil
	}
	t.s.cleanup(t)
	// Post-reap group verification (§23): the direct child is reaped, so
	// any survivor is an escaped descendant — log it, never chase it by
	// name (§41/§56).
	if pgid := int(t.pgid.Load()); pgid > 0 && GroupAlive(pgid) {
		t.s.log.Warn("process group still alive after turn exit (escaped descendants)",
			"instance", t.InstanceID, "turn", t.TurnID, "pgid", pgid)
	}
	return exit
}

// abort: immediate group KILL (owner-initiated fast path).
func (t *managedTurn) abort(reason string) {
	if t.state.Load() == stFinished {
		return
	}
	t.state.Store(stStopping)
	if t.termReason.Load() == nil {
		t.termReason.Store(reason)
	}
	if pgid := int(t.pgid.Load()); pgid > 0 {
		if err := SignalGroup(pgid, syscall.SIGKILL); err != nil && !errors.Is(err, ErrGroupGone) {
			t.s.log.Warn("abort: group KILL failed", "pgid", pgid, "err", err)
		}
		t.forced.Store(true)
		t.s.forceKillTotal.Add(1)
	}
}

// Terminate: external TERM → grace → KILL sequence (idempotent; the
// first caller runs it, the rest wait for it).
func (t *managedTurn) Terminate(reason string) {
	t.termOnce.Do(func() {
		go t.terminateSequence(reason)
	})
	<-t.termDone
}

func (t *managedTurn) terminateSequence(reason string) {
	defer close(t.termDone)
	if t.state.Load() == stFinished {
		return
	}
	t.state.Store(stStopping)
	if t.termReason.Load() == nil {
		t.termReason.Store(reason)
	}
	t.s.log.Info("terminating process group",
		"instance", t.InstanceID, "turn", t.TurnID,
		"pgid", t.pgid.Load(), "reason", reason)
	t.terminateGroup()
	// The owner reaps after the group dies; do not wait on the exit here
	// (the owner may be this sequence's caller's sibling — waiting on
	// the exitCh would deadlock the abort path).
}

// terminateGroup runs TERM → grace → KILL on the process group, polling
// for ACTUAL group death instead of a fixed sleep: a group whose members
// all die on TERM returns well before the grace, and an already-dead
// group returns immediately.
//
// The poll uses GroupHasLiveMember (zombie-aware), NOT GroupAlive
// (signal-0): a zombie is a dead process awaiting reap and cannot be
// signaled into dying. The turn's direct child is typically a zombie at
// this point (it exited, and the owner reaps it via cmd.Wait AFTER this
// returns) — waiting on it would burn the full grace window for nothing
// (the 2026-09-15 5s-per-cycle leak-test regression). Only LIVE
// descendants (shells, MCP bridges, helpers) are worth waiting for.
//
// Idempotent and safe to run concurrently from the external Terminate
// path and the owner's post-reap descendant reclaim (signaling a dead
// group is a no-op; the forced flag is atomic).
func (t *managedTurn) terminateGroup() {
	pgid := int(t.pgid.Load())
	if pgid <= 0 {
		return
	}
	if err := SignalGroup(pgid, syscall.SIGTERM); err != nil && !errors.Is(err, ErrGroupGone) {
		t.s.log.Warn("group TERM failed", "pgid", pgid, "err", err)
	}
	deadline := t.s.now().Add(t.s.cfg.TermGrace)
	for GroupHasLiveMember(pgid) && t.s.now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if GroupHasLiveMember(pgid) {
		if err := SignalGroup(pgid, syscall.SIGKILL); err == nil {
			t.forced.Store(true)
			t.s.forceKillTotal.Add(1)
		} else if !errors.Is(err, ErrGroupGone) {
			t.s.log.Warn("group KILL failed", "pgid", pgid, "err", err)
		}
	}
}

// --- Stop / PID (Lifecycle) ---------------------------------------------------

// Stop terminates the instance's active turn (§24: explicit stop).
func (s *Supervisor) Stop(instanceID string) error {
	s.mu.Lock()
	t := s.byInstance[instanceID]
	s.mu.Unlock()
	if t == nil {
		return nil
	}
	t.Terminate("stopped")
	return nil
}

// WaitForStop waits (up to timeout) for the instance's active turn to be
// fully reaped and unregistered (external audit F-004). Stop is async:
// Terminate initiates the kill, and the owner's reap (which unregisters
// the turn from byInstance) follows independently. A Stop→immediate-Start
// that does not wait would race the reap and hit ErrInstanceBusy while the
// old turn is still registered. Returns true when the turn is gone (or was
// never there).
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
	// The exit is published just before the unregister (same goroutine);
	// confirm byInstance is cleared (a short re-poll covers the gap).
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

// StopPTY terminates the instance's PTY session (no-op when none).
func (s *Supervisor) StopPTY(instanceID string) {
	s.mu.Lock()
	t := s.ptyByInst[instanceID]
	s.mu.Unlock()
	if t != nil {
		t.Terminate("stopped")
	}
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

// ownedSnapshot counts processes in all currently owned groups.
func (s *Supervisor) ownedSnapshot() int {
	s.mu.Lock()
	groups := make(map[int]bool, len(s.turns))
	for _, t := range s.turns {
		if pgid := int(t.pgid.Load()); pgid > 0 {
			groups[pgid] = true
		}
	}
	s.mu.Unlock()
	return CountOwned(groups)
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
