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
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/creack/pty"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/transport"
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
	// h is the supervisor's handle for this PTY session (ClassPTY): the
	// session is an isolated process SESSION (Setsid+Setctty, its own
	// group, pgid == leader pid). Termination kills the WHOLE group —
	// the runtime TUI AND its slave-holding helper descendants — so the
	// PTY is released and the read loop unblocks (abuse addendum Part B
	// §26). The session never holds the raw *exec.Cmd: it requests
	// termination and observes the exit; the supervisor's owner (this
	// session's exitLoop) is the single reaper.
	h *proc.Handle
	// f is the PTY master (h.PTY()). The read loop streams from it; it
	// errors (EIO) once every slave fd is closed (the group is dead).
	f *os.File
	// live is closed once h and f are set (the session is ready). A
	// concurrent start that finds a not-yet-live session waits on it
	// (external audit F-002: atomic STARTING reservation — exactly one
	// start launches; the rest reconcile to the reserved session instead
	// of racing a second Launch, which the supervisor would dedup to the
	// SAME process and the old re-check-and-kill path would then
	// terminate, killing the shared session). startErr is set (before
	// live is closed) when the launch fails; the channel close is the
	// happens-before edge that makes the read race-free.
	live     chan struct{}
	startErr error

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

// lastSize is one attached client's most recent requested geometry,
// remembered per (instance, attach session) so the shared PTY's size can
// be restored to a SURVIVING client when the last resizer detaches
// (otherwise the size silently sticks with the detaching client's window
// and the remaining clients' TUI reflows to a size they never asked for).
type lastSize struct {
	cols uint16
	rows uint16
	at   time.Time
}

type terminalManager struct {
	d *Daemon

	mu       sync.Mutex
	sessions map[string]*ptySession // instanceID -> live session
	// lastSize: instanceID -> attachSessionID -> latest resize.
	lastSize map[string]map[string]lastSize

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
		lastSize: map[string]map[string]lastSize{},
		liveCh:   make(chan terminalLiveMsg, 1024),
	}
	go tm.liveLoop()
	return tm
}

func (tm *terminalManager) liveLoop() {
	for m := range tm.liveCh {
		s := tm.get(m.instance)
		if s == nil || s.f == nil {
			// No live PTY yet (or a starting session whose master is not
			// open): the byte has nowhere to go (external audit F-002).
			continue
		}
		if m.isResize {
			if m.cols > 0 && m.rows > 0 {
				_ = pty.Setsize(s.f, &pty.Winsize{Rows: m.rows, Cols: m.cols})
				tm.recordSize(m.instance, m.session, m.cols, m.rows)
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

// recordSize remembers the attach session's latest requested geometry
// (see reapplySize).
func (tm *terminalManager) recordSize(instanceID, sessionID string, cols, rows uint16) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.lastSize[instanceID] == nil {
		tm.lastSize[instanceID] = map[string]lastSize{}
	}
	tm.lastSize[instanceID][sessionID] = lastSize{cols: cols, rows: rows, at: time.Now()}
}

// reapplySize restores the shared PTY's geometry to a still-attached
// client after the last resizer detached. The most recently resized
// surviving session wins; the detacher's record is dropped. When no
// survivor has a recorded size, the PTY keeps its size — every client
// sends its own fit-resize shortly after (re)attach.
func (tm *terminalManager) reapplySize(instanceID, excludeSession string) {
	tm.mu.Lock()
	s := tm.sessions[instanceID]
	var bestSz lastSize
	found := false
	for sess, sz := range tm.lastSize[instanceID] {
		if sess == excludeSession {
			continue
		}
		if !found || sz.at.After(bestSz.at) {
			bestSz = sz
			found = true
		}
	}
	delete(tm.lastSize[instanceID], excludeSession)
	tm.mu.Unlock()
	if !found || s == nil || s.f == nil {
		return
	}
	_ = pty.Setsize(s.f, &pty.Winsize{Rows: bestSz.rows, Cols: bestSz.cols})
	tm.d.Log.Info("pty size re-applied from surviving attach",
		"instance", instanceID, "cols", bestSz.cols, "rows", bestSz.rows)
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
//
// Atomic STARTING reservation (external audit F-002): the slot is
// reserved in the sessions map BEFORE the (slow) launch, so a concurrent
// start reconciles to the reserved session (waiting on its live channel)
// instead of racing a second Launch. The supervisor would dedup the
// duplicate to the SAME process, and the old re-check-and-kill path would
// then terminate that shared handle — killing the winner's session. With
// the reservation, exactly one start launches; the rest wait.
func (tm *terminalManager) start(instanceID string, resume bool) (*ptySession, error) {
	tm.mu.Lock()
	if s := tm.sessions[instanceID]; s != nil {
		tm.mu.Unlock()
		return tm.awaitLive(s)
	}
	s := &ptySession{instanceID: instanceID, live: make(chan struct{})}
	tm.sessions[instanceID] = s
	tm.mu.Unlock()

	if err := tm.launchPTY(s, instanceID, resume); err != nil {
		tm.mu.Lock()
		if tm.sessions[instanceID] == s {
			delete(tm.sessions, instanceID)
		}
		tm.mu.Unlock()
		s.startErr = err
		close(s.live)
		return nil, err
	}
	close(s.live)
	return s, nil
}

// awaitLive blocks until the reserved session is live (or its launch
// failed) and returns the result. The channel close is the happens-before
// edge that makes reading startErr race-free.
func (tm *terminalManager) awaitLive(s *ptySession) (*ptySession, error) {
	<-s.live
	if s.startErr != nil {
		return nil, s.startErr
	}
	return s, nil
}

// launchPTY performs the actual (slow) PTY launch into an already-
// reserved session. It sets s.h/s.f and starts the read/exit loops; the
// caller closes s.live on return.
func (tm *terminalManager) launchPTY(s *ptySession, instanceID string, resume bool) error {
	row, ok, err := tm.d.state.GetInstance(instanceID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unknown instance %s", instanceID)
	}
	ad, ok := tm.d.adapters[domain.RuntimeName(row.Runtime)]
	if !ok {
		return fmt.Errorf("no adapter for runtime %q", row.Runtime)
	}
	cmd, err := ad.InteractiveCmd(tm.d.turnSpecFor(row, resume, "", "terminal"))
	if err != nil {
		return err
	}
	// The supervisor launches the PTY under an isolated process SESSION
	// (Setsid+Setctty — the same SysProcAttr pty.StartWithSize always
	// set, now owned in one place) and hands back the master. context.
	// Background is deliberate: a PTY session is long-lived and must NOT
	// be tied to a turn's context (it survives turns and detaches, §10).
	h, err := tm.d.sup.Launch(context.Background(), proc.LaunchRequest{
		InstanceID: instanceID,
		TurnID:     proc.PTYTurnID,
		Runtime:    row.Runtime,
		Class:      proc.ClassPTY,
		Cmd:        cmd,
		PTYSize: &pty.Winsize{
			Rows: terminalDefaultRows,
			Cols: terminalDefaultCols,
		},
		Marker: "PAGNET_INSTANCE_ID=" + instanceID,
	})
	if err != nil {
		return fmt.Errorf("pty start: %w", err)
	}
	s.h = h
	s.f = h.PTY()

	// P6 configStale: the PTY was just spawned with the daemon's CURRENT
	// injected config (MCP bridge + identity env) — record its
	// fingerprint so a later auto-update re-exec marks it stale. (A
	// re-sent attach returns the existing session above and keeps the
	// fingerprint of the process actually running.)
	_ = tm.d.state.SetInstanceConfigFingerprint(instanceID, tm.d.instanceFingerprint(row))

	go tm.readLoop(s)
	go tm.exitLoop(s)
	tm.d.Log.Info("pty started", "instance", instanceID, "pid", h.PID(), "resume", resume)
	return nil
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
	// Owner's reap (single Wait): reaps the session leader AND reclaims
	// any slave-holding descendants that outlived it (§19/§24/§26) — this
	// is what releases the PTY and unblocks the read loop.
	waitErr := s.h.Wait()
	_ = s.f.Close() // backstop: the master already errored when the group died
	tm.mu.Lock()
	killed := false
	if tm.sessions[s.instanceID] == s {
		delete(tm.sessions, s.instanceID)
		delete(tm.lastSize, s.instanceID)
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

// stop terminates the instance's PTY session. Idempotent; suppresses the
// natural-exit event (the caller drives instance state). It terminates the
// WHOLE process group (the session leader AND its slave-holding
// descendants) via the supervisor — never just the direct child, which
// would leave the PTY allocated and the read loop blocked (§26).
func (tm *terminalManager) stop(instanceID string) {
	tm.mu.Lock()
	s := tm.sessions[instanceID]
	tm.mu.Unlock()
	if s == nil {
		return
	}
	// A starting session has no handle yet: wait for the launch to settle
	// (external audit F-002) so we never terminate a nil handle or orphan
	// a just-launched process. If the launch already failed there is
	// nothing to terminate.
	<-s.live
	if s.startErr != nil {
		return
	}
	tm.mu.Lock()
	if tm.sessions[instanceID] == s {
		s.killed = true
		delete(tm.sessions, instanceID)
		delete(tm.lastSize, instanceID)
	}
	tm.mu.Unlock()
	s.h.Terminate("stopped")
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
