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
//   - input/resize are LIVE messages handled on an ordered worker per PTY
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
	// exitSettled reserves this generation while its natural exit is published.
	// Replacement waits without holding the global terminal map lock.
	exitSettled chan struct{}

	// endpointView marks a Phase 3 (terminal session unification) session
	// on a session-driven endpoint's OWN TUI PTY — the always-on CAPTURE
	// (adoptEndpoint: from the driver's launch via its PTYAvailable hook,
	// with the attach-time backstop adopting the same way; the master's
	// single reader, A6) — as opposed to a legacy ClassPTY session the
	// terminal plane launched itself. A capture:
	//   - holds h == nil (the endpoint's handle is owned by the session
	//     core / its driver — the capture never Waits or Terminates it,
	//     G3/G5);
	//   - holds f = the endpoint's PTY master as a VIEW (never closes it —
	//     the process handle owns it; a closed master is EOF to the
	//     capture);
	//   - is torn down observationally on master EOF (eofCh): the session
	//     core owns the endpoint's lifecycle and instance status, so the
	//     teardown writes NO status and emits NO hibernated event.
	endpointView bool
	// eofCh is closed when the view's master hits EOF (the endpoint died).
	// It is the view's exit signal (readLoop closes it; exitLoop waits on
	// it). Legacy sessions leave it nil.
	eofCh chan struct{}

	// input is bound to this concrete PTY generation; tm.mu guards it.
	input *terminalInputQueue
}

// terminalLiveMsg is one input/resize unit on the ordered live channel.
type terminalLiveMsg struct {
	expected *ptySession // internal resize restoration stays generation-bound
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
	native *nativeTerminalManager
	d      *Daemon

	mu       sync.Mutex
	sessions map[string]*ptySession // instanceID -> live session
	// lastSize: instanceID -> attachSessionID -> latest resize.
	lastSize map[string]map[string]lastSize
	reports  chan struct{} // bounds asynchronous rejection writes
}

const (
	terminalInputMessages     = 1024
	terminalInputBytes        = 4 * 1024 * 1024
	terminalInputWriteTimeout = 10 * time.Second
)

type terminalInputQueue struct {
	messages chan terminalLiveMsg
	stop     chan struct{}
	done     chan struct{}
	bytes    int // queued plus in-flight bytes, guarded by tm.mu
	stopped  bool
	rejected map[string]string
}

func newTerminalManager(d *Daemon) *terminalManager {
	return &terminalManager{d: d, sessions: map[string]*ptySession{}, lastSize: map[string]map[string]lastSize{}, reports: make(chan struct{}, 16)}
}

// submit resolves the PTY before enqueueing. A later replacement never inherits
// old input, and each PTY has its own bounded FIFO so one blocked consumer cannot
// delay keystrokes or resizes for another agent.
func (tm *terminalManager) submit(m terminalLiveMsg) bool {
	tm.mu.Lock()
	s := tm.sessions[m.instance]
	if m.expected != nil && s != m.expected {
		tm.mu.Unlock()
		return false
	}
	if s == nil {
		tm.mu.Unlock()
		tm.reportInputDrop(m, "input_unavailable")
		return false
	}
	select {
	case <-s.live:
	default:
		tm.mu.Unlock()
		tm.reportInputDrop(m, "input_unavailable")
		return false
	}
	if s.startErr != nil || s.f == nil {
		tm.mu.Unlock()
		tm.reportInputDrop(m, "input_unavailable")
		return false
	}
	q := s.input
	if q == nil {
		q = &terminalInputQueue{messages: make(chan terminalLiveMsg, terminalInputMessages), stop: make(chan struct{}), done: make(chan struct{}), rejected: map[string]string{}}
		s.input = q
		go tm.liveLoop(s, q)
	}
	// Discard stale rejection records only after the viewer has detached.
	tm.d.attachMu.Lock()
	for id := range q.rejected {
		if _, active := tm.d.attaches[m.instance][id]; !active && id != "" {
			delete(q.rejected, id)
		}
	}
	_, attached := tm.d.attaches[m.instance][m.session]
	tm.d.attachMu.Unlock()
	if m.session != "" && !attached {
		tm.mu.Unlock()
		return false
	}
	if reason := q.rejected[m.session]; reason != "" {
		tm.mu.Unlock()
		// If all bounded notification slots were occupied, a subsequent key
		// retries the rejection instead of leaving a permanently silent view.
		tm.reportInputDrop(m, reason)
		return false
	}
	accepted := false
	if !q.stopped && len(m.data) <= terminalInputBytes-q.bytes {
		select {
		case q.messages <- m:
			q.bytes += len(m.data)
			if m.isResize && m.cols > 0 && m.rows > 0 {
				if tm.lastSize[m.instance] == nil {
					tm.lastSize[m.instance] = map[string]lastSize{}
				}
				tm.lastSize[m.instance][m.session] = lastSize{cols: m.cols, rows: m.rows, at: time.Now()}
			}
			accepted = true
		default:
		}
	}
	if !accepted {
		q.rejected[m.session] = "input_backpressure"
	}
	tm.mu.Unlock()
	if !accepted {
		tm.reportInputDrop(m, "input_backpressure")
	}

	return accepted
}

func (tm *terminalManager) reportInputDrop(m terminalLiveMsg, reason string) {
	tm.d.Log.Warn("terminal live message rejected", "instance", m.instance, "resize", m.isResize, "bytes", len(m.data), "reason", reason)
	if m.session != "" {
		select {
		case tm.reports <- struct{}{}:
			go func() {
				defer func() { <-tm.reports }()
				_ = tm.d.send(nil, transport.MsgTerminalOutput, transport.TerminalOutputPayload{InstanceID: m.instance, SessionID: m.session, ClosedReason: reason})
			}()
		default:
			// A disconnected control plane already closes its viewers; never let
			// rejection notifications create unbounded goroutines or stall input.
		}
	}
}

// stopInputLocked invalidates queued work and interrupts the current write. It
// never closes a borrowed endpoint master: the runtime owns that descriptor.
func (tm *terminalManager) stopInputLocked(s *ptySession) {
	if q := s.input; q != nil && !q.stopped {
		q.stopped = true
		close(q.stop)
		_ = s.f.SetWriteDeadline(time.Now())
	}
}

func (tm *terminalManager) liveLoop(s *ptySession, q *terminalInputQueue) {
	defer func() {
		tm.mu.Lock()
		// Release queued paste bytes even when a borrowed view remains alive
		// after detach. The runtime owns its master and may not reach EOF soon.
	drain:
		for {
			select {
			case <-q.messages:
			default:
				break drain
			}
		}
		q.bytes = 0
		clear(q.rejected)
		// Clear our deadline before any new lane can use the borrowed master.
		current := tm.sessions[s.instanceID]
		if current == nil || current == s || current.f != s.f || current.input == nil {
			_ = s.f.SetWriteDeadline(time.Time{})
		}
		tm.mu.Unlock()
		close(q.done)
	}()
	for {
		var m terminalLiveMsg
		select {
		case <-q.stop:
			return
		case m = <-q.messages:
		}
		tm.mu.Lock()
		if q.stopped || tm.sessions[s.instanceID] != s {
			tm.mu.Unlock()
			return
		}
		tm.d.attachMu.Lock()
		_, attached := tm.d.attaches[m.instance][m.session]
		tm.d.attachMu.Unlock()
		if q.rejected[m.session] != "" || (m.session != "" && !attached) {
			q.bytes -= len(m.data)
			tm.mu.Unlock()
			continue
		}
		if m.isResize {
			if m.cols > 0 && m.rows > 0 {
				_ = pty.Setsize(s.f, &pty.Winsize{Rows: m.rows, Cols: m.cols})
			}
			q.bytes -= len(m.data)
			tm.mu.Unlock()
			continue
		}
		// Synchronize setting the deadline with teardown: stop cannot be undone by
		// a late worker extending the deadline after cancellation.
		err := s.f.SetWriteDeadline(time.Now().Add(terminalInputWriteTimeout))
		tm.mu.Unlock()
		if err == nil && len(m.data) > 0 {
			var n int
			n, err = s.f.Write(m.data)
			if err == nil && n != len(m.data) {
				err = fmt.Errorf("short PTY write: %d of %d bytes", n, len(m.data))
			}
		}
		tm.mu.Lock()
		q.bytes -= len(m.data)
		stopped := q.stopped
		if err != nil && !stopped {
			q.rejected[m.session] = "input_write_failed"
		}
		tm.mu.Unlock()
		if err != nil && !stopped {
			tm.reportInputDrop(m, "input_write_failed")
		}
	}
}

func (tm *terminalManager) get(instanceID string) *ptySession {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.sessions[instanceID]
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
	var bestSession string
	found := false
	for sess, sz := range tm.lastSize[instanceID] {
		if sess == excludeSession {
			continue
		}
		if !found || sz.at.After(bestSz.at) {
			bestSz = sz
			bestSession = sess
			found = true
		}
	}
	delete(tm.lastSize[instanceID], excludeSession)
	tm.mu.Unlock()
	if !found || s == nil || s.f == nil {
		return
	}
	tm.submit(terminalLiveMsg{expected: s, instance: instanceID, session: bestSession, isResize: true, rows: bestSz.rows, cols: bestSz.cols})
	tm.d.Log.Info("pty size re-applied from surviving attach",
		"instance", instanceID, "cols", bestSz.cols, "rows", bestSz.rows)
}

// active reports whether the instance has a live LEGACY PTY session (§35
// keep-awake: while attached OR PTY-active the daemon does not hibernate).
// Phase 3 (A6): endpoint VIEWS are excluded — a view is an observational
// relay of an endpoint the session core already keeps alive; counting it
// as "terminal-active" would block hibernation of an idle endpoint that
// merely has a (possibly detached) view. Keep-awake for a session-driven
// endpoint is the HUMAN attach (d.attached), not the view.
func (tm *terminalManager) active(instanceID string) bool {
	s := tm.get(instanceID)
	return s != nil && !s.endpointView
}

// activeCount is the number of live LEGACY PTY sessions (the auto-update
// idle gate, P6: a re-exec must not orphan a running PTY process). Phase 3
// (A6): endpoint views are excluded — they are not processes the terminal
// plane launched; the live endpoints they view are counted separately by
// the supervisor's EndpointCount (A7).
func (tm *terminalManager) activeCount() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	n := 0
	for _, s := range tm.sessions {
		if !s.endpointView {
			n++
		}
	}
	return n
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
		if s.exitSettled != nil {
			tm.mu.Unlock()
			return nil, ErrDeferred
		}
		tm.mu.Unlock()
		return tm.awaitLive(s)
	}
	s := &ptySession{instanceID: instanceID, live: make(chan struct{})}
	tm.sessions[instanceID] = s
	tm.mu.Unlock()

	if err := tm.launchPTY(s, instanceID, resume); err != nil {
		tm.mu.Lock()
		if tm.sessions[instanceID] == s {
			tm.stopInputLocked(s)
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

// adoptEndpoint creates (or reconciles to) the always-on CAPTURE of a
// session-driven endpoint's OWN TUI PTY (Phase 3 terminal session
// unification, promoted to launch-time by the activation-deadlock fix):
// the master's SINGLE reader (A6), in place from the FIRST byte. It is
// wired from the driver's launch through its PTYAvailable hook the moment
// the PTY master is registered — strictly BEFORE the activation
// (session_start) settles — so a TUI runtime that renders before
// session_start (qwen, codex) always finds a reader: a never-read master
// fills the kernel PTY buffer, the TUI blocks in write(), and the
// activation times out at the startup budget with a healthy, alive process
// (the 2026-09-30 incident).
//
// Unlike start/launchPTY (which LAUNCH a legacy ClassPTY process),
// adoptEndpoint never spawns a process: it holds the endpoint's existing
// PTY master as a view (the two-planes invariant — the human plane is the
// endpoint's own PTY, not a second interactive process).
//
// The capture carries the endpointView semantics: it is OBSERVATIONAL —
// h == nil (the endpoint's handle is owned by the session core / its
// driver — the capture never Waits or Terminates it, G3/G5), it never
// closes the master (the process handle owns it; a closed master is EOF to
// the capture), and it is torn down observationally on master EOF (eofCh)
// with no status write and no hibernated event (the session core owns the
// endpoint's lifecycle and instance status).
//
// Idempotent + reconciled under tm.mu (the same reservation discipline as
// start):
//   - master nil → error (the launch has no PTY — the no-PTY topology is
//     first-class, I1; the hook must not fire for it);
//   - an existing LEGACY session → error (a capture and a launched PTY are
//     mutually exclusive for an instance);
//   - an existing LIVE capture → return it (reconcile, created=false —
//     never a second readLoop or session, A6);
//   - an existing DEAD capture (eofCh closed — master EOF) → the endpoint
//     it captured is gone; the master handed to us belongs to a
//     re-activation's fresh endpoint — replace it (the remembered client
//     geometry, when any, is applied to the fresh master so the PTY does
//     not boot at the 24x80 default).
//
// The created result reports whether a NEW capture was created (true) or
// the call reconciled to an existing live capture (false) — the caller
// stamps the config fingerprint only at a genuine (re)activation, so a
// reconcile never hides a stale fingerprint.
//
// The capture is live immediately (no slow launch): live is closed before
// return and the read/exit loops are started.
func (tm *terminalManager) adoptEndpoint(instanceID string, master *os.File) (*ptySession, bool, error) {
	if master == nil {
		return nil, false, fmt.Errorf("endpoint %s has no live TUI PTY to attach", instanceID)
	}
	var remembered lastSize
	haveRemembered := false
	tm.mu.Lock()
	if s := tm.sessions[instanceID]; s != nil {
		if !s.endpointView {
			tm.mu.Unlock()
			return nil, false, fmt.Errorf("instance %s has a legacy PTY session; a view cannot attach to it", instanceID)
		}
		// Existing capture: live → reconcile to it (idempotent, one
		// reader per master); dead (master EOF) → the endpoint it
		// captured is gone and the master belongs to a re-activation's
		// fresh endpoint — replace it.
		dead := false
		select {
		case <-s.eofCh:
			dead = true
		default:
		}
		if !dead {
			tm.mu.Unlock()
			return s, false, nil
		}
		// Remember the most recent client geometry BEFORE the old record
		// is dropped, so the fresh PTY boots at the size a (still
		// attached) client last asked for instead of the 24x80 default.
		remembered, haveRemembered = tm.latestSizeLocked(instanceID)
		tm.stopInputLocked(s)
		delete(tm.sessions, instanceID)
		delete(tm.lastSize, instanceID)
	}
	s := &ptySession{
		instanceID:   instanceID,
		f:            master,
		live:         make(chan struct{}),
		endpointView: true,
		eofCh:        make(chan struct{}),
	}
	tm.sessions[instanceID] = s
	tm.mu.Unlock()

	// The fresh master must not boot at the 24x80 default when the
	// terminal plane already knows a client's geometry for the instance.
	if haveRemembered {
		_ = pty.Setsize(s.f, &pty.Winsize{Rows: remembered.rows, Cols: remembered.cols})
	}

	// A capture is ready immediately (no launch): close live, start the
	// read/exit loops.
	close(s.live)
	go tm.readLoop(s)
	go tm.exitLoop(s)
	tm.d.Log.Info("endpoint capture adopted", "instance", instanceID)
	return s, true, nil
}

// latestSizeLocked reports the instance's most recently requested geometry
// across all of its attach sessions (see lastSize). The caller must hold
// tm.mu.
func (tm *terminalManager) latestSizeLocked(instanceID string) (lastSize, bool) {
	var bestSz lastSize
	found := false
	for _, sz := range tm.lastSize[instanceID] {
		if !found || sz.at.After(bestSz.at) {
			bestSz = sz
			found = true
		}
	}
	return bestSz, found
}

// attachEndpoint binds a client to the instance's endpoint CAPTURE (the
// always-on ptySession adoptEndpoint adopted at the driver's launch — the
// capture exists from the LAUNCH site, the master registration: strictly
// earlier than the old activation-site invariant, A5). It never spawns a
// process and never starts a second readLoop or session: the capture is
// the master's single reader (A6).
//
// Idempotent + reconciled under tm.mu (the same reservation discipline as
// start):
//   - master nil → error (the endpoint has no live PTY — the daemon refuses
//     the attach cleanly: no crash, no hang, no partial state);
//   - an existing LEGACY session → error (a capture and a launched PTY are
//     mutually exclusive for an instance);
//   - an existing DEAD capture (eofCh closed — master EOF) → the attach is
//     REFUSED (G7: never bind a client to a dead master — the endpoint is
//     gone; a (re)activation adopts a fresh capture for the fresh endpoint
//     at launch, so a bind landing on a dead capture is a race to be
//     retried, never a terminal to be shown);
//   - an existing LIVE capture → return it (reconcile, created=false);
//   - no session at all (should be impossible — the driver's launch adopts
//     the capture; a capture dropped by stop() while the endpoint is live
//     is the only realistic case) → adopt it now, the same code path.
//
// The created result reports whether a NEW capture was created (true) or
// the call reconciled to the existing live capture (false).
//
// The capture is live immediately (no slow launch): live is closed before
// return and the read/exit loops are started. It never closes the master,
// Waits, or Terminates (the process handle owns those — G3/G5).
func (tm *terminalManager) attachEndpoint(instanceID string, master *os.File) (*ptySession, bool, error) {
	if master == nil {
		return nil, false, fmt.Errorf("endpoint %s has no live TUI PTY to attach", instanceID)
	}
	tm.mu.Lock()
	if s := tm.sessions[instanceID]; s != nil {
		if !s.endpointView {
			tm.mu.Unlock()
			return nil, false, fmt.Errorf("instance %s has a legacy PTY session; a view cannot attach to it", instanceID)
		}
		select {
		case <-s.eofCh:
			// G7: the capture's endpoint is gone (master EOF). Refuse the
			// bind with the existing no-live-PTY error shape — a
			// (re)activation adopts a fresh capture at launch, so a client
			// that lands on a dead capture is retried, never shown a
			// torn-down terminal.
			tm.mu.Unlock()
			return nil, false, fmt.Errorf("endpoint %s has no live TUI PTY to attach", instanceID)
		default:
			tm.mu.Unlock()
			return s, false, nil
		}
	}
	tm.mu.Unlock()
	// No capture (the backstop — the driver's launch adopts one, so this
	// is only reachable when a capture was dropped while the endpoint is
	// live): adopt it now, exactly the launch-time path.
	return tm.adoptEndpoint(instanceID, master)
}

// hasSession reports whether the instance has ANY terminal session (legacy
// PTY or endpoint view). It is the doDetach reapplySize gate: a view counts
// as a session for size-reapply purposes even though active() excludes it
// (A6: keep-awake is the human attach, not the view).
func (tm *terminalManager) hasSession(instanceID string) bool {
	return tm.get(instanceID) != nil
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
	if err := tm.d.checkRuntimeProfile(row, false); err != nil {
		return err
	}
	ad, ok := tm.d.adapterFor(row)
	if !ok {
		return fmt.Errorf("no adapter for runtime %q", row.Runtime)
	}
	spec := tm.d.turnSpecFor(row, resume, "", "terminal")
	cmd, err := ad.InteractiveCmd(spec)
	if err != nil {
		return err
	}
	// The supervisor launches the PTY under an isolated process SESSION
	// (Setsid+Setctty — the same SysProcAttr pty.StartWithSize always
	// set, now owned in one place) and hands back the master. context.
	// Background is deliberate: a PTY session is long-lived and must NOT
	// be tied to a turn's context (it survives turns and detaches, §10).
	// S2: the PTY process is sandboxed like every other class — the
	// driver's per-instance spec (the same one its StartTurn launch
	// carries) is applied at the supervisor's single policy point.
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
		Marker:  "PAGNET_INSTANCE_ID=" + instanceID,
		Sandbox: ad.SandboxSpec(spec),
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
			// View: master EOF means the endpoint died. Signal the view's
			// exit loop (observational teardown — no status write). This
			// goroutine is the single reader, so the close is once.
			if s.endpointView {
				close(s.eofCh)
			}
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
//
// Phase 3 (terminal session unification): a view's exit is OBSERVATIONAL.
// The endpoint's lifecycle and instance status are owned by the session
// core (its driver reaps the process; the daemon's turn/hibernate paths
// settle the status). The view merely watched the master; on master EOF it
// drops itself from the map and logs — it writes NO status and emits NO
// hibernated event, and it never closes the master or Waits the process
// (the process handle owns both).
func (tm *terminalManager) exitLoop(s *ptySession) {
	if s.endpointView {
		<-s.eofCh // the read loop closed it on master EOF (endpoint died)
		tm.mu.Lock()
		var ended []string
		if tm.sessions[s.instanceID] == s {
			// Record only viewers of this capture before releasing its slot.
			// A replacement capture's late EOF must not close the new view.
			tm.d.attachMu.Lock()
			for sessionID := range tm.d.attaches[s.instanceID] {
				ended = append(ended, sessionID)
			}
			tm.d.attachMu.Unlock()
			tm.stopInputLocked(s)
			delete(tm.sessions, s.instanceID)
			delete(tm.lastSize, s.instanceID)
		}
		tm.mu.Unlock()
		for _, sessionID := range ended {
			_ = tm.d.send(nil, transport.MsgTerminalOutput, transport.TerminalOutputPayload{
				InstanceID: s.instanceID, SessionID: sessionID, ClosedReason: "process_exited",
			})
		}
		tm.d.Log.Info("endpoint view torn down (master EOF; session core owns lifecycle)",
			"instance", s.instanceID)
		return
	}
	// Owner's reap (single Wait): reaps the session leader AND reclaims
	// any slave-holding descendants that outlived it (§19/§24/§26) — this
	// is what releases the PTY and unblocks the read loop.
	waitErr := s.h.Wait()
	_ = s.f.Close() // backstop: the master already errored when the group died
	tm.finishExitedPTY(s, waitErr)
}

// finishExitedPTY publishes lifecycle effects only for the retiring owner.
func (tm *terminalManager) finishExitedPTY(s *ptySession, waitErr error) {
	tm.mu.Lock()
	// Only this generation may publish lifecycle effects. Explicit stop
	// removes its slot before the reaper returns; a replacement can already
	// own the instance when this watcher runs.
	owned := tm.sessions[s.instanceID] == s
	killed := s.killed
	var ended []string
	if owned && !killed {
		s.exitSettled = make(chan struct{})
		tm.stopInputLocked(s)
		tm.d.attachMu.Lock()
		for sessionID := range tm.d.attaches[s.instanceID] {
			ended = append(ended, sessionID)
		}
		tm.d.attachMu.Unlock()
	}
	tm.mu.Unlock()
	if !owned || killed {
		return
	}
	defer func() {
		tm.mu.Lock()
		if tm.sessions[s.instanceID] == s {
			delete(tm.sessions, s.instanceID)
			delete(tm.lastSize, s.instanceID)
		}
		close(s.exitSettled)
		tm.mu.Unlock()
	}()
	for _, sessionID := range ended {
		_ = tm.d.send(nil, transport.MsgTerminalOutput, transport.TerminalOutputPayload{
			InstanceID: s.instanceID, SessionID: sessionID, ClosedReason: "process_exited",
		})
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
	tm.d.invalidateBridgeNonce(s.instanceID) // S1: the PTY (and its bridge) is dead
	_ = tm.d.state.SetInstanceStatus(s.instanceID, "hibernated", row.SessionID)
	tm.d.send(nil, transport.MsgAgentHibernated, map[string]any{
		"instanceId": s.instanceID, "sessionId": row.SessionID,
		// Viewers of this generation were closed individually above. An
		// instance-wide close would also terminate a newly requested view.
		"reason": "terminal_exited",
	})
	tm.d.reportEndpointStatus(nil, s.instanceID) // offline (hibernated)
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
	// nothing to terminate. (A view is live immediately, so this is a
	// no-op wait for it.)
	<-s.live
	if s.startErr != nil {
		return
	}
	tm.mu.Lock()
	if tm.sessions[instanceID] == s {
		if done := s.exitSettled; done != nil {
			tm.mu.Unlock()
			<-done
			return
		}
		s.killed = true
		tm.stopInputLocked(s)
		delete(tm.sessions, instanceID)
		delete(tm.lastSize, instanceID)
	}
	tm.mu.Unlock()
	if q := s.input; q != nil {
		<-q.done // cancellation wakes pollable writes; never retain an input worker
	}
	// Phase 3 (G5): a view must NOT terminate the endpoint — the session
	// core owns the endpoint's process stop (its driver runs the TERM →
	// grace → KILL sequence). Stopping a view only drops the view; the
	// endpoint keeps running (the caller — doTerminalStop / doStop —
	// separately stops the session-driven endpoint through the session
	// core). The view's exit loop will drop it on master EOF if the
	// endpoint is in fact stopped.
	if s.endpointView {
		tm.d.Log.Info("endpoint view dropped (endpoint stop owned by session core)",
			"instance", instanceID)
		return
	}
	s.h.Terminate("stopped")
	tm.d.Log.Info("pty stopped", "instance", instanceID)
}

// stopAll kills every PTY (daemon shutdown: never orphan the processes).
func (tm *terminalManager) stopAll() {
	tm.closeNative()
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
