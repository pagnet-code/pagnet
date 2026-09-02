package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
}

// New builds a daemon. State is opened at stateDir/daemon.sqlite.
func New(cfg Config, log *slog.Logger) (*Daemon, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
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
	d := &Daemon{
		Config: cfg,
		Log:    log,
		state:  st,
		adapters: map[domain.RuntimeName]agentruntime.Adapter{
			domain.RuntimeFake: fake,
		},
		activeTurns: map[string]bool{},
	}
	return d, nil
}

func (d *Daemon) Close() error { return d.state.Close() }

// Run connects and stays connected (reconnecting with backoff) until ctx is
// canceled.
func (d *Daemon) Run(ctx context.Context) error {
	if d.Credential == "" {
		return fmt.Errorf("no host credential; run `agentnet login` first")
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
	d.Log.Info("connected to control plane")

	// Announce inventory on (re)connect: runtimes + workspaces, and it
	// triggers the server's reconnect wake re-evaluation (pending commands
	// are re-sent; we deduplicate locally by CommandID).
	d.sendInventory(conn)

	heartbeat := time.NewTicker(d.Heartbeat)
	defer heartbeat.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeat.C:
				d.sendHeartbeat(conn)
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
		d.handleCommand(conn, env)
	}
}

// send wraps a payload in a versioned envelope and writes it.
func (d *Daemon) send(conn *websocket.Conn, msgType string, payload any) error {
	env, err := transport.NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, raw)
}

func (d *Daemon) sendAck(conn *websocket.Conn, commandID, errMsg string) {
	_ = d.send(conn, transport.MsgCommandAck, map[string]any{
		"commandId": commandID,
		"error":     errMsg,
	})
}

func (d *Daemon) sendHeartbeat(conn *websocket.Conn) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	metrics := transport.HeartbeatPayload{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		DaemonVer: d.Version,
	}
	metrics.Metrics.CPUCount = runtime.NumCPU()
	if load, err := readLoadAvg(); err == nil {
		metrics.Metrics.CPULoad = load
	}
	metrics.Metrics.MemTotalBytes = int64(mem.Sys)
	metrics.Metrics.MemUsedBytes = int64(mem.HeapAlloc)
	if diskFree, err := readDiskFree(d.StateDir); err == nil {
		metrics.Metrics.DiskFreeBytes = diskFree
	}
	insts, err := d.state.ListInstances()
	if err == nil {
		for _, i := range insts {
			metrics.Instances = append(metrics.Instances, transport.InstanceStatus{
				InstanceID: i.InstanceID,
				Status:     i.Status,
			})
		}
	}
	_ = d.send(conn, transport.MsgHeartbeat, metrics)
}

// handleCommand executes one structured command from the control plane.
// Idempotency: the CommandID is remembered in local SQLite (marked processed
// on success). A daemon crash mid-flight causes at most one re-execution,
// which every handler tolerates.
func (d *Daemon) handleCommand(conn *websocket.Conn, env transport.Envelope) {
	switch env.Type {
	case transport.MsgLaunchAgent:
		var p transport.LaunchAgentPayload
		if env.DecodePayload(&p) != nil {
			return
		}
		d.guarded(conn, p.CommandID, func() error { return d.doLaunch(conn, p) })

	case transport.MsgStopAgent:
		var p transport.StopAgentPayload
		if env.DecodePayload(&p) != nil {
			return
		}
		d.guarded(conn, p.CommandID, func() error { return d.doStop(conn, p.InstanceID) })

	case transport.MsgRestartAgent:
		var p transport.RestartAgentPayload
		if env.DecodePayload(&p) != nil {
			return
		}
		d.guarded(conn, p.CommandID, func() error { return d.doRestart(conn, p.InstanceID) })

	case transport.MsgWakeAgent:
		var p transport.WakeAgentPayload
		if env.DecodePayload(&p) != nil || p.WakeRequestID == "" {
			return
		}
		d.guarded(conn, p.WakeRequestID, func() error { return d.doWake(conn, p.InstanceID, p.Reason) })

	case transport.MsgDeliverNetworkEvent:
		var p transport.NetworkEventPayload
		if env.DecodePayload(&p) != nil {
			return
		}
		d.guarded(conn, p.CommandID, func() error { return d.doDeliver(conn, p) })

	case transport.MsgRequestInventory:
		d.sendInventory(conn)

	default:
		d.Log.Warn("unknown command type", "type", env.Type)
	}
}

// guarded runs fn for a CommandID exactly once (idempotency gate) and acks.
// A deferred outcome (ErrDeferred) is NOT acked: the command stays queued
// server-side and the dispatcher re-sends it (§32: one active turn per
// instance, multiple inbound items queue durably).
func (d *Daemon) guarded(conn *websocket.Conn, commandID string, fn func() error) {
	if commandID != "" && d.alreadyProcessed(commandID) {
		d.sendAck(conn, commandID, "")
		return
	}
	err := fn()
	if errors.Is(err, ErrDeferred) {
		d.Log.Debug("command deferred (stays queued)", "command", commandID)
		return
	}
	if err != nil {
		d.sendAck(conn, commandID, err.Error())
		return
	}
	if commandID != "" {
		_ = d.state.MarkProcessed(commandID, "")
	}
	d.sendAck(conn, commandID, "")
}

func (d *Daemon) alreadyProcessed(commandID string) bool {
	if commandID == "" {
		return false
	}
	ok, err := d.state.IsProcessed(commandID)
	return err == nil && ok
}

// workspaceAllowed validates a path against the allowed roots (cleaned
// absolute prefix match).
func (d *Daemon) workspaceAllowed(path string) bool {
	if path == "" {
		return false
	}
	clean, err := filepathAbs(path)
	if err != nil {
		return false
	}
	for _, root := range d.AllowedRoots {
		rc, err := filepathAbs(root)
		if err != nil {
			continue
		}
		if clean == rc || strings.HasPrefix(clean, rc+string(os.PathSeparator)) {
			return true
		}
	}
	return false
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
	if !d.workspaceAllowed(p.WorkspacePath) {
		return fmt.Errorf("workspace %q is not under an allowed root", p.WorkspacePath)
	}
	rn := domain.CanonicalRuntime(p.Runtime)
	if _, ok := d.adapters[rn]; !ok {
		return fmt.Errorf("runtime %q not supported on this host", p.Runtime)
	}
	// Launch registers the instance as idle: process-per-turn means no
	// process runs until work arrives (the runtime is the turn runner).
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID:   p.InstanceID,
		DefinitionID: p.DefinitionID,
		Runtime:      string(rn),
		Workspace:    p.WorkspacePath,
		Profile:      p.Profile,
		Status:       "idle",
	}); err != nil {
		return err
	}
	d.Log.Info("agent launched (idle, process-per-turn)",
		"instance", p.InstanceID, "runtime", rn, "workspace", p.WorkspacePath)
	_ = d.send(conn, transport.MsgAgentStarted, map[string]any{"instanceId": p.InstanceID})
	return nil
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
	input := p.Body
	if p.AcceptanceCriteria != nil {
		input += "\n\nAcceptance criteria:\n- " + strings.Join(p.AcceptanceCriteria, "\n- ")
	}
	return d.runTurn(conn, d.turnSpecFor(row, row.SessionID != "", input, kind))
}

func (d *Daemon) busy(instanceID string) bool {
	d.turnMu.Lock()
	defer d.turnMu.Unlock()
	return d.activeTurns[instanceID]
}

func (d *Daemon) turnSpecFor(row *InstanceRow, resume bool, input, kind string) agentruntime.TurnSpec {
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
	}
}

// runTurn executes one turn through the adapter, translating normalized
// events into host protocol events, then hibernates the instance when the
// process exits (process-per-turn).
func (d *Daemon) runTurn(conn *websocket.Conn, spec agentruntime.TurnSpec) error {
	row, ok, _ := d.state.GetInstance(spec.InstanceID)
	if !ok {
		return fmt.Errorf("unknown instance %s", spec.InstanceID)
	}
	ad, ok := d.adapters[domain.RuntimeName(row.Runtime)]
	if !ok {
		return fmt.Errorf("no adapter for runtime %q", row.Runtime)
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
		turnDone <- ad.StartTurn(context.Background(), spec, events)
	}()

	sessionID := ""
	var failedKind, failedErr string
	var failedRetry *string
	var sessionLost bool

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
		if failedKind == "rate_limited" {
			st = "rate_limited"
		}
		_ = d.state.SetInstanceStatus(spec.InstanceID, st, sessionID)
		return fmt.Errorf("turn failed: %s: %s", failedKind, failedErr)
	case turnErr != nil:
		// Adapter-level failure (spawn/IO), no turn events were produced.
		d.sendTurn(conn, transport.MsgRuntimeTurnFailed, spec, attemptedSession,
			nil, nil, nil, "", "process_error:"+turnErr.Error(), nil)
		_ = d.state.SetInstanceStatus(spec.InstanceID, "failed", "")
		return fmt.Errorf("turn failed: process_error: %v", turnErr)
	default:
		// Completed: hibernate with the session preserved.
		_ = d.state.SetInstanceStatus(spec.InstanceID, "hibernated", sessionID)
		_ = d.send(conn, transport.MsgAgentHibernated, map[string]any{
			"instanceId": spec.InstanceID, "sessionId": sessionID,
		})
	}
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

func readDiskFree(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * st.Bsize, nil
}
