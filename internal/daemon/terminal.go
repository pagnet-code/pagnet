package daemon

// TerminalManager — the daemon's PTY terminal sessions (addendum §8–§15).
//
// A PTY session is a SECOND process class, deliberately outside the
// process-per-turn machinery (adapters/procTracker/activeTurns): it is a
// long-lived interactive runtime process that survives turns, detach, and
// browser closes (§10: "Detach must NOT terminate the Agent"). Turns keep
// running their own short-lived processes; the PTY runs the runtime's
// interactive UI (the ACTUAL CLI, §7) so a human can type into it directly.
//
// Wire shape (PROTOCOL §3):
//   - input/resize are LIVE messages handled on a single ordered worker
//     (keystroke order matters; the durable command pipeline would add a
//     Postgres round-trip and busy-deferral per keystroke);
//   - output is host.terminal_output: base64 raw bytes, per-session
//     monotonic seq, in order; a snapshot frame (Snapshot=true) replays
//     the bounded ring buffer for a (re)attaching client and carries the
//     LastSeq where live output resumes (§11: no duplication).
//
// The bounded ring is the ONLY terminal state kept: never infinite
// output (§11). A daemon restart drops the PTY (the process cannot
// survive it); the next attach starts a fresh session, resuming the
// stored runtime session when the runtime supports it.

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"

	"pagnet/internal/domain"
	"pagnet/internal/transport"
)

const (
	// terminalRingCap: bounded scrollback (addendum §11 "Do NOT store
	// infinite terminal output"). 256 KiB base64-encodes to ~341 KiB per
	// snapshot — one bounded envelope, not a stream.
	terminalRingCap = 256 * 1024
	// terminalChunk: max raw bytes per live terminal_output frame.
	terminalChunk = 16 * 1024
	// terminalDefaultSize: initial PTY size until the client sends its
	// first (debounced) fit-resize.
	terminalDefaultRows = 24
	terminalDefaultCols = 80
)

// ptySession is one live PTY for an instance.
type ptySession struct {
	instanceID string
	cmd        *exec.Cmd
	f          *os.File

	// bufMu guards seq + ring: the reader appends, attach snapshots read.
	// seq counts BYTES (monotonic per session) — the replay→live dedup
	// unit on the server.
	bufMu sync.Mutex
	seq   uint64
	ring  []byte

	// killed marks an explicit Stop: the exit watcher must NOT emit the
	// natural-exit (hibernated) event — the stopper owns instance state.
	killed bool
}

// terminalLiveMsg is one input/resize unit on the ordered live channel.
type terminalLiveMsg struct {
	isResize bool
	instance string
	session  string
	data     []byte
	cols     uint16
	rows     uint16
}

type terminalManager struct {
	d *Daemon

	mu       sync.Mutex
	sessions map[string]*ptySession // instanceID -> live session

	// Single ordered worker: keystroke order across ALL instances is
	// preserved (it only matters per instance, but one FIFO is the
	// simplest correct shape). Bounded: overflow drops with a warning
	// (a lost keystroke beats a stalled read loop — live semantics,
	// at-most-once).
	liveCh chan terminalLiveMsg
}

func newTerminalManager(d *Daemon) *terminalManager {
	tm := &terminalManager{
		d:        d,
		sessions: map[string]*ptySession{},
		liveCh:   make(chan terminalLiveMsg, 1024),
	}
	go tm.liveLoop()
	return tm
}

func (tm *terminalManager) liveLoop() {
	for m := range tm.liveCh {
		s := tm.get(m.instance)
		if s == nil {
			continue // no live PTY: the byte has nowhere to go
		}
		if m.isResize {
			if m.cols > 0 && m.rows > 0 {
				_ = pty.Setsize(s.f, &pty.Winsize{Rows: m.rows, Cols: m.cols})
			}
			continue
		}
		if len(m.data) == 0 {
			continue
		}
		// A stalled PTY consumer must not stall the live worker (every
		// instance's input queues behind it): bounded write, drop on
		// timeout.
		_ = s.f.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := s.f.Write(m.data); err != nil {
			tm.d.Log.Warn("pty input write dropped", "instance", m.instance, "err", err)
		}
	}
}

// submit enqueues one live input/resize message (non-blocking).
func (tm *terminalManager) submit(m terminalLiveMsg) bool {
	select {
	case tm.liveCh <- m:
		return true
	default:
		tm.d.Log.Warn("terminal live message dropped (back-pressure)", "instance", m.instance)
		return false
	}
}

func (tm *terminalManager) get(instanceID string) *ptySession {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.sessions[instanceID]
}

// active reports whether the instance has a live PTY (§35 keep-awake:
// while attached OR PTY-active the daemon does not hibernate).
func (tm *terminalManager) active(instanceID string) bool {
	return tm.get(instanceID) != nil
}

// activeCount is the number of live PTY sessions (the auto-update idle
// gate, P6: a re-exec must not orphan a running PTY process).
func (tm *terminalManager) activeCount() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return len(tm.sessions)
}

// start launches the instance's PTY if not already running (idempotent —
// attach is a durable command and may re-send). The interactive command
// comes from the runtime adapter (the ACTUAL CLI, addendum §7); resume
// selects the stored runtime session.
func (tm *terminalManager) start(instanceID string, resume bool) (*ptySession, error) {
	tm.mu.Lock()
	if s := tm.sessions[instanceID]; s != nil {
		tm.mu.Unlock()
		return s, nil
	}
	tm.mu.Unlock()

	row, ok, err := tm.d.state.GetInstance(instanceID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("unknown instance %s", instanceID)
	}
	ad, ok := tm.d.adapters[domain.RuntimeName(row.Runtime)]
	if !ok {
		return nil, fmt.Errorf("no adapter for runtime %q", row.Runtime)
	}
	cmd, err := ad.InteractiveCmd(tm.d.turnSpecFor(row, resume, "", "terminal"))
	if err != nil {
		return nil, err
	}
	f, err := pty.StartWithSize(cmd, &pty.Winsize{
		Rows: terminalDefaultRows,
		Cols: terminalDefaultCols,
	})
	if err != nil {
		return nil, fmt.Errorf("pty start: %w", err)
	}
	s := &ptySession{instanceID: instanceID, cmd: cmd, f: f}
	tm.mu.Lock()
	if existing := tm.sessions[instanceID]; existing != nil {
		tm.mu.Unlock()
		_ = f.Close()
		_ = cmd.Process.Kill()
		return existing, nil
	}
	tm.sessions[instanceID] = s
	tm.mu.Unlock()

	// P6 configStale: the PTY was just spawned with the daemon's CURRENT
	// injected config (MCP bridge + identity env) — record its
	// fingerprint so a later auto-update re-exec marks it stale. (A
	// re-sent attach returns the existing session above and keeps the
	// fingerprint of the process actually running.)
	_ = tm.d.state.SetInstanceConfigFingerprint(instanceID, tm.d.instanceFingerprint(row))

	go tm.readLoop(s)
	go tm.exitLoop(s)
	tm.d.Log.Info("pty started", "instance", instanceID, "pid", cmd.Process.Pid, "resume", resume)
	return s, nil
}

// readLoop streams PTY output: ring append + one ordered terminal_output
// frame per chunk. The frame carries the post-chunk seq; frames are sent
// from this single goroutine, so per-session order is socket order.
func (tm *terminalManager) readLoop(s *ptySession) {
	buf := make([]byte, terminalChunk)
	for {
		n, err := s.f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			s.bufMu.Lock()
			s.seq += uint64(n)
			seq := s.seq
			s.ring = append(s.ring, chunk...)
			if int64(len(s.ring)) > terminalRingCap {
				s.ring = s.ring[int64(len(s.ring))-terminalRingCap:]
			}
			s.bufMu.Unlock()
			tm.d.send(nil, transport.MsgTerminalOutput, transport.TerminalOutputPayload{
				InstanceID: s.instanceID,
				Data:       base64.StdEncoding.EncodeToString(chunk),
				Seq:        seq,
			})
		}
		if err != nil {
			return
		}
	}
}

// snapshot returns the bounded ring + current seq atomically (attach
// replays this before switching the client to live output, §11).
func (tm *terminalManager) snapshot(s *ptySession) (data string, lastSeq uint64) {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	return base64.StdEncoding.EncodeToString(s.ring), s.seq
}

// exitLoop reports the PTY process's natural exit. An explicit Stop marks
// the session killed first — that path owns instance state (stop/
// restart/forget/shutdown).
func (tm *terminalManager) exitLoop(s *ptySession) {
	waitErr := s.cmd.Wait()
	_ = s.f.Close()
	tm.mu.Lock()
	killed := false
	if tm.sessions[s.instanceID] == s {
		delete(tm.sessions, s.instanceID)
		killed = s.killed
	}
	tm.mu.Unlock()
	if killed {
		return
	}
	row, ok, _ := tm.d.state.GetInstance(s.instanceID)
	if !ok {
		return
	}
	// A turn drives instance state while in flight: never clobber a
	// working/waking instance — its finish path settles the status.
	switch row.Status {
	case "working", "waking", "starting", "hibernating", "stopping":
		return
	}
	_ = tm.d.state.SetInstanceStatus(s.instanceID, "hibernated", row.SessionID)
	tm.d.send(nil, transport.MsgAgentHibernated, map[string]any{
		"instanceId": s.instanceID, "sessionId": row.SessionID,
		// The PTY process itself exited: terminal clients must be told
		// (other hibernate reasons must not tear down a fresh session's
		// clients — see the server's MsgAgentHibernated handler).
		"reason": "process_exited",
	})
	tm.d.Log.Info("pty exited; instance hibernated (session preserved)",
		"instance", s.instanceID, "wait", waitErr)
}

// stop kills the instance's PTY. Idempotent; suppresses the natural-exit
// event (the caller drives instance state).
func (tm *terminalManager) stop(instanceID string) {
	tm.mu.Lock()
	s := tm.sessions[instanceID]
	if s != nil {
		s.killed = true
		delete(tm.sessions, instanceID)
	}
	tm.mu.Unlock()
	if s == nil || s.cmd.Process == nil {
		return
	}
	_ = s.cmd.Process.Kill()
	tm.d.Log.Info("pty stopped", "instance", instanceID)
}

// stopAll kills every PTY (daemon shutdown: never orphan the processes).
func (tm *terminalManager) stopAll() {
	tm.mu.Lock()
	ids := make([]string, 0, len(tm.sessions))
	for id := range tm.sessions {
		ids = append(ids, id)
	}
	tm.mu.Unlock()
	for _, id := range ids {
		tm.stop(id)
	}
}
