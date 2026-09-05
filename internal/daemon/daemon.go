package daemon

import (
	"context"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"agentnet/internal/domain"
	agentruntime "agentnet/internal/runtime"
	"agentnet/internal/transport"
)

// ErrDeferred means the command cannot be executed right now but must NOT
// be acknowledged or failed: it stays queued server-side and is re-sent by
// the host dispatcher (e.g. the instance is busy and maxConcurrentTurns=1).
var ErrDeferred = errors.New("deferred: stays queued")

// Config is the daemon configuration (plain data, safe to pass by value).
type Config struct {
	ServerURL    string
	Credential   string
	HostID       string
	StateDir     string
	AllowedRoots []string
	Version      string
	Heartbeat    time.Duration
	// RuntimeEnv is applied to spawned runtime processes (E2E simulation
	// knobs live here; a real deployment leaves it empty).
	RuntimeEnv []string
}

// Daemon is a running agentnetd instance.
type Daemon struct {
	Config
	Log *slog.Logger

	state    *State
	adapters map[domain.RuntimeName]agentruntime.Adapter

	turnMu      sync.Mutex
	activeTurns map[string]bool

	// turnCtx cancels when the daemon shuts down (Close): adapters kill
	// the running turn subprocess on cancellation (spec §90: context
	// cancellation must terminate subprocess work), so a SIGTERM never
	// orphans a mid-turn process.
	turnCtx    context.Context
	turnCancel context.CancelFunc

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

// New builds a daemon. State is opened at stateDir/daemon.sqlite.
func New(cfg Config, log *slog.Logger) (*Daemon, error) {
	if log == nil {
		log = slog.Default()
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
	fake := agentruntime.NewFake("")
	fake.Env = cfg.RuntimeEnv
	turnCtx, turnCancel := context.WithCancel(context.Background())
	d := &Daemon{
		Config: cfg,
		Log:    log,
		state:  st,
		adapters: map[domain.RuntimeName]agentruntime.Adapter{
			domain.RuntimeFake:       fake,
			domain.RuntimeQwenCode:   agentruntime.NewQwen(""),
			domain.RuntimeClaudeCode: agentruntime.NewClaude(""),
		},
		activeTurns: map[string]bool{},
		attaches:    map[string]map[string]time.Time{},
		pending:     map[string]chan transport.AgentResponsePayload{},
		instQueues:  map[string]*instQueue{},
		seen:        map[string]time.Time{},
		turnCtx:     turnCtx,
		turnCancel:  turnCancel,
		repoLocks:   map[string]*sync.Mutex{},
	}
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

// Close shuts the daemon down: cancels in-flight turns (adapters kill the
// turn subprocess, spec §90), waits briefly for them to die, then closes
// the bridge socket and state.
func (d *Daemon) Close() error {
	d.turnCancel()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		d.turnMu.Lock()
		n := len(d.activeTurns)
		d.turnMu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	d.stopBridgeSocket()
	return d.state.Close()
}

// Run connects and stays connected (reconnecting with backoff) until ctx is
// canceled.
func (d *Daemon) Run(ctx context.Context) error {
	if d.Credential == "" {
		return fmt.Errorf("no host credential; run `agentnet login` first")
	}
	// The agent bridge socket is local and independent of the WSS
	// connection: it is up as soon as the daemon is, and relayed calls
	// fail cleanly (not hang) while the host connection is down.
	if err := d.startBridgeSocket(); err != nil {
		return err
	}
	backoff := time.Second
	for ctx.Err() == nil {
		err := d.connectAndRun(ctx)
		if ctx.Err() != nil {
			break
		}
		if err != nil {
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
	return u.String()
}

func (d *Daemon) connectAndRun(ctx context.Context) error {
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
			return err
		}
		var env transport.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			d.Log.Warn("bad envelope from server", "err", err)
			continue
		}
		if env.Type == transport.MsgAgentResponse {
			d.deliverAgentResponse(env)
			continue
		}
		d.handleCommand(conn, env)
	}
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

	case transport.MsgTerminalInput:
		var p transport.TerminalInputPayload
		if err := env.DecodePayload(&p); err != nil {
			// Structurally broken: the CommandID lives inside the payload,
			// so this copy cannot be acked and the server will re-send it.
			// Make that visible instead of dropping it silently.
			d.Log.Warn("command payload decode failed", "type", env.Type, "err", err)
			return
		}
		d.enqueueCommand(conn, p.InstanceID, p.CommandID, func() {
			d.guarded(conn, p.CommandID, func() error { return d.doTerminalInput(conn, p) })
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
			d.sendAck(conn, commandID, "")
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
		_ = d.state.MarkProcessed(commandID, "")
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

// workspaceAllowed validates a path against the allowed roots (resolved
// absolute prefix match).
func (d *Daemon) workspaceAllowed(path string) bool {
	if path == "" {
		return false
	}
	clean, err := pathResolved(path)
	if err != nil {
		return false
	}
	for _, root := range d.AllowedRoots {
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
	rn := domain.CanonicalRuntime(p.Runtime)
	ad, ok := d.adapters[rn]
	if !ok {
		return fmt.Errorf("runtime %q not supported on this host", p.Runtime)
	}
	if !ad.Available() {
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
		wsPath string
		lock   *sync.Mutex
	)
	if p.WorkspacePath == "" {
		// Representative (§37/§72): no git workspace; an AgentNet-managed
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
		lock = d.repoLock(workspaceLockKey(p.WorkspacePath))
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
	}
	// Launch registers the instance as idle: process-per-turn means no
	// process runs until work arrives (the runtime is the turn runner).
	kind := p.Kind
	if kind == "" {
		kind = "worker"
	}
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID:   p.InstanceID,
		DefinitionID: p.DefinitionID,
		Runtime:      string(rn),
		Workspace:    wsPath,
		Profile:      p.Profile,
		Status:       "idle",
		Access:       access,
		AgentName:    p.AgentName,
		NetworkID:    p.NetworkID,
		Kind:         kind,
	}); err != nil {
		if lock != nil {
			lock.Unlock()
		}
		return err
	}
	if lock != nil {
		lock.Unlock()
	}
	msg := "agent launched (idle, process-per-turn)"
	if wsPath != p.WorkspacePath {
		msg = "agent launched (git worktree isolation, process-per-turn)"
	}
	d.Log.Info(msg,
		"instance", p.InstanceID, "runtime", rn, "workspace", wsPath, "access", access)
	_ = d.send(conn, transport.MsgAgentStarted, map[string]any{"instanceId": p.InstanceID})
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
func workspaceLockKey(path string) string {
	if common, err := repoCommonDir(path); err == nil {
		return common
	}
	abs, _ := filepathAbs(path)
	return abs
}

func (d *Daemon) doStop(conn *websocket.Conn, instanceID string) error {
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unknown instance %s", instanceID)
	}
	if ad, ok := d.adapters[domain.RuntimeName(row.Runtime)]; ok {
		_ = ad.Stop(instanceID)
	}
	if err := d.state.SetInstanceStatus(instanceID, "stopped", ""); err != nil {
		return err
	}
	_ = d.send(conn, transport.MsgAgentStopped, map[string]any{
		"instanceId": instanceID, "reason": "stopped_by_command",
	})
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
		if ad, ok := d.adapters[domain.RuntimeName(row.Runtime)]; ok {
			_ = ad.Stop(instanceID)
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
	if ad, ok := d.adapters[domain.RuntimeName(row.Runtime)]; ok {
		_ = ad.Stop(instanceID)
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
	resume := row.SessionID != ""
	input := "You were woken. Reason: " + reason
	d.Log.Info("wake turn", "instance", instanceID, "reason", reason, "resume", resume)
	return d.runTurn(conn, d.turnSpecFor(row, resume, input, "wake"))
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
	kind := p.Kind
	if kind == "" {
		kind = "notice"
	}
	// The turn input carries the context the agent needs to ACT through the
	// network tools (reply needs the thread id, task updates need the task
	// id) — not just the rendered text.
	var input strings.Builder
	switch kind {
	case "ask", "reply":
		fmt.Fprintf(&input, "[agentnet %s] from=%s thread=%s message=%s\n",
			kind, dashOr(p.FromAgent), dashOr(p.ThreadID), dashOr(p.MessageID))
	case "task":
		fmt.Fprintf(&input, "[agentnet task] id=%s from=%s\n",
			dashOr(p.TaskID), dashOr(p.FromAgent))
	case "channel":
		fmt.Fprintf(&input, "[agentnet channel] from=%s conversation=%s network=%s message=%s\n",
			dashOr(p.FromAgent), dashOr(p.ConversationID), dashOr(p.NetworkID), dashOr(p.MessageID))
	case "status":
		fmt.Fprintf(&input, "[agentnet status] from=%s\n", dashOr(p.FromAgent))
	default: // notice
		fmt.Fprintf(&input, "[agentnet notice] from=%s\n", dashOr(p.FromAgent))
	}
	input.WriteString(p.Body)
	if len(p.AcceptanceCriteria) > 0 {
		input.WriteString("\n\nAcceptance criteria:\n- " + strings.Join(p.AcceptanceCriteria, "\n- "))
	}
	d.Log.Info("delivery turn", "instance", p.InstanceID, "kind", kind)
	return d.runTurn(conn, d.turnSpecFor(row, row.SessionID != "", input.String(), kind))
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
	contractPath, _ := d.writeContract(row)
	return agentruntime.TurnSpec{
		TurnID:       domain.NewID().String(),
		InstanceID:   row.InstanceID,
		DefinitionID: row.DefinitionID,
		Workspace:    row.Workspace,
		SessionDir:   filepath.Join(d.StateDir, "sessions", row.InstanceID),
		Resume:       resume,
		Input:        input,
		InputKind:    kind,
		Metadata:     map[string]any{"profile": row.Profile},
		Env: []string{
			"AGENTNET_INSTANCE_ID=" + row.InstanceID,
			"AGENTNET_AGENT_NAME=" + row.AgentName,
			"AGENTNET_NETWORK_ID=" + row.NetworkID,
			"AGENTNET_MCP_CONFIG=" + d.mcpConfig(row),
			"AGENTNET_COORDINATION_CONTRACT=" + contractPath,
		},
	}
}

// mcpConfig is the MCP client config the daemon injects into every
// managed agent: the bridge over the daemon's local Unix socket (the
// bridge authenticates to the daemon with the instance identity — the
// host credential never reaches the agent, §5/§17). Workers get the
// agentnet-mcp surface (network_* tools); representatives get
// agentnet-control (control_* tools) — the surfaces are separate
// binaries on purpose (§9: reduces accidental privilege escalation).
func (d *Daemon) mcpConfig(row *InstanceRow) string {
	name, command := "agentnet", "agentnet-mcp"
	if row.Kind == "representative" {
		name, command = "agentnet-control", "agentnet-control"
	}
	cfg := map[string]any{
		"mcpServers": map[string]any{
			name: map[string]any{
				"command": command,
				"args":    []string{"--socket", filepath.Join(d.StateDir, "agentnetd.sock")},
				"env": map[string]string{
					"AGENTNET_INSTANCE_ID": row.InstanceID,
					"AGENTNET_NETWORK_ID":  row.NetworkID,
				},
			},
		},
	}
	b, _ := json.Marshal(cfg)
	return string(b)
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
	defer func() {
		d.turnMu.Lock()
		delete(d.activeTurns, spec.InstanceID)
		d.turnMu.Unlock()
	}()

	if err := d.state.SetInstanceStatus(spec.InstanceID, "working", ""); err != nil {
		return err
	}
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
			_ = d.send(conn, transport.MsgRuntimeOutput, map[string]any{
				"instanceId": spec.InstanceID, "output": ev.Output,
			})
		case agentruntime.EventTurnCompleted:
			completed = true
			d.sendTurn(conn, transport.MsgRuntimeTurnCompleted, spec, sessionID,
				ev.InputTokens, ev.OutputTokens, ev.CachedTokens, ev.Model, "", nil)
		case agentruntime.EventTurnFailed:
			failedKind = string(ev.FailureKind)
			failedErr = ev.Error
			failedRetry = ev.RetryAt
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
	case turnErr != nil:
		// Adapter-level failure (spawn/IO), no turn events were produced.
		d.Log.Warn("turn failed (adapter error)",
			"instance", spec.InstanceID, "error", turnErr.Error())
		d.sendTurn(conn, transport.MsgRuntimeTurnFailed, spec, attemptedSession,
			nil, nil, nil, "", "process_error:"+turnErr.Error(), nil)
		_ = d.state.SetInstanceStatus(spec.InstanceID, "failed", "")
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
		// Completed. §35: do not hibernate underneath an attached user. An
		// active attach keeps the instance awake (idle, session active);
		// the hibernation happens when the last attach is closed.
		if d.attached(spec.InstanceID) {
			_ = d.state.SetInstanceStatus(spec.InstanceID, "idle", sessionID)
			_ = d.send(conn, transport.MsgAgentStatus, map[string]any{
				"instanceId": spec.InstanceID, "status": "idle",
			})
			d.Log.Info("turn completed; instance kept awake (attach active)",
				"instance", spec.InstanceID)
			return nil
		}
		// Completed: hibernate with the session preserved.
		_ = d.state.SetInstanceStatus(spec.InstanceID, "hibernated", sessionID)
		_ = d.send(conn, transport.MsgAgentHibernated, map[string]any{
			"instanceId": spec.InstanceID, "sessionId": sessionID,
		})
	}
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

// doAttach registers an active interactive session. A hibernated instance
// is woken so the user has a live agent; a busy one finishes its current
// turn first (which will then keep it awake because the attach is active).
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
	d.addAttach(p.InstanceID, p.SessionID)
	if d.busy(p.InstanceID) {
		d.Log.Info("attach active; instance is finishing its current turn",
			"instance", p.InstanceID)
		return nil
	}
	if row.Status == "hibernated" {
		d.Log.Info("attach wakes hibernated instance", "instance", p.InstanceID)
		input := "You were woken. Reason: a human attached an interactive session."
		return d.runTurn(conn, d.turnSpecFor(row, row.SessionID != "", input, "user_input"))
	}
	d.Log.Info("attach active (instance already awake)", "instance", p.InstanceID)
	return nil
}

// doDetach closes an interactive session. When it was the last one and the
// instance is idle with no turn running, the instance returns to normal
// hibernation (§35: "once detached and safe, the managed runtime may
// return to normal hibernation").
func (d *Daemon) doDetach(conn *websocket.Conn, p transport.DetachTerminalPayload) error {
	last := d.removeAttach(p.InstanceID, p.SessionID)
	if !last {
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
		_ = d.state.SetInstanceStatus(p.InstanceID, "hibernated", row.SessionID)
		_ = d.send(conn, transport.MsgAgentHibernated, map[string]any{
			"instanceId": p.InstanceID, "sessionId": row.SessionID,
		})
		d.Log.Info("last attach closed; instance hibernated", "instance", p.InstanceID)
	}
	return nil
}

// doTerminalInput executes one interactive user input from an attach
// session as a turn (spec §54 terminal proxy: the control plane brokers
// browser/CLI input over the host connection). A hibernated instance is
// woken by resuming its stored session; input arriving while a turn is in
// progress stays queued (deferred) and runs after it completes.
func (d *Daemon) doTerminalInput(conn *websocket.Conn, p transport.TerminalInputPayload) error {
	row, ok, err := d.state.GetInstance(p.InstanceID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unknown instance %s", p.InstanceID)
	}
	switch row.Status {
	case "blocked", "failed", "stopped":
		return fmt.Errorf("instance %s is %s; input refused", p.InstanceID, row.Status)
	}
	if strings.TrimSpace(p.Data) == "" {
		return nil
	}
	if d.busy(p.InstanceID) {
		return ErrDeferred
	}
	d.Log.Info("terminal input turn", "instance", p.InstanceID,
		"session", p.SessionID, "bytes", len(p.Data))
	return d.runTurn(conn, d.turnSpecFor(row, row.SessionID != "", p.Data, "user_input"))
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

// --- small platform helpers ---------------------------------------------------

func readLoadAvg() (float64, error) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty loadavg")
	}
	return strconv.ParseFloat(fields[0], 64)
}

// readMemInfo reads host memory from /proc/meminfo (Linux; ok=false
// elsewhere so the caller can fall back).
func readMemInfo() (total, used int64, ok bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	var memTotal, memAvail uint64
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			memTotal = meminfoKB(rest)
		} else if rest, ok := strings.CutPrefix(line, "MemAvailable:"); ok {
			memAvail = meminfoKB(rest)
		}
	}
	if memTotal == 0 {
		return 0, 0, false
	}
	used = int64(memTotal) - int64(memAvail)
	if used < 0 {
		used = 0
	}
	return int64(memTotal), used, true
}

// meminfoKB parses the "12345 kB" value of one /proc/meminfo line.
func meminfoKB(rest string) uint64 {
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return 0
	}
	n, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return n * 1024
}

func readDiskFree(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * st.Bsize, nil
}
