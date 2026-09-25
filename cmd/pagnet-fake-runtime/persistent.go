package main

// Persistent mode (--persistent): a deterministic, long-lived fake native
// runtime endpoint. Unlike turn mode (one process per turn, exits at turn
// end), a persistent endpoint is ONE process that services many logical
// submits over a stdin control channel and streams structured events on
// stdout for its whole life. It is the reference implementation of the
// runtime-lifecycle refactor's persistent model (Phase 1): the daemon
// drives it through the generic session core (EnsureActive + Submit +
// consume normalized events) and hibernates/wakes it without losing the
// native session.
//
// Protocol (JSONL):
//
//	stdin commands (one JSON per line):
//	  {"type":"submit","turnId":"...","input":"...","inputKind":"..."}
//	  {"type":"interaction","turnId":"...","interactionId":"...",
//	     "decision":"...","answer":"..."}
//
//	stdout events (one JSON per line, the pagnet normalized vocabulary):
//	  runtime.session.started | resumed | lost
//	  runtime.busy | runtime.idle
//	  runtime.turn.started | output | completed | failed
//	  runtime.interaction.started | resolved
//
// Every turn event carries the turnId so the driver can route it to the
// right in-flight submit. The process is single-turn: one prompt turn at a
// time (pagnet owns serialisation — no vendor queue). An interaction
// command answers the current turn's pending native interaction and
// unblocks it; it is NOT a new turn.
//
// Lifecycle:
//   - cold start: mints a native session id, emits session.started. The
//     session file is written only after the first exchange (the
//     "materialised" boundary — a started-but-unexchanged session has no
//     durable state to resume).
//   - resume (--resume <id>): reads the session file; a match with at least
//     one exchange emits session.resumed, otherwise session.lost (honest —
//     never a silent fresh session).
//   - hibernate: the daemon SIGTERMs the process; it saves the session and
//     exits cleanly (the session survives for a later resume).
//
// Simulation knobs (env) carry over from turn mode:
//   - PAGNET_FAKE_INTERACTION=<kind>: a scripted native interaction the
//     turn blocks on (answered via an interaction command).
//   - PAGNET_FAKE_INTERACTION_SUMMARY / _PAYLOAD / _ANSWER: shape the
//     interaction.
//   - PAGNET_FAKE_RATELIMIT / _RESUME_FAIL: failure simulation.
//   - PAGNET_FAKE_DIE_MID_TURN=1: the endpoint CRASHES in the middle of the
//     first turn its session services (a hard SIGKILL to itself right after
//     turn.started — no terminal event, no session save). A marker file in
//     the session dir records that the crash already happened, so the
//     re-activated endpoint services the retry normally. It is the
//     deterministic stand-in for a vendor crash / SIGKILL / OOM landing
//     mid-turn.
//
// TUI (Phase 3 terminal session unification): when the endpoint OWNS a
// controlling terminal (the daemon launches it with a PTY), a
// deterministic LINE-mode TUI runs on /dev/tty — the HUMAN plane:
//
//   - human lines typed on the tty are dispatched through the SAME
//     turnQueue as machine submits (one turn at a time; pagnet owns
//     serialisation);
//   - turn events render to the tty (turn.output → its text,
//     turn.completed → "done", interaction.started → "? <summary>"); the
//     TUI does NOT answer interactions (those are resolved on the machine
//     plane);
//   - `let <k> <v>` / `print <k>` are session-memory commands (persisted
//     in the session file, so they survive hibernate/wake);
//   - the MACHINE plane (stdin/stdout JSONL) is untouched: the TUI is a
//     second sink/source on the same process, never a replacement, and
//     no PTY byte is ever interpreted as machine protocol.
//
// When /dev/tty cannot be opened (the endpoint was launched without a
// PTY — the pre-Phase-3 shape, or a test), the TUI degrades OFF and
// everything runs through the machine plane only (existing tests pass
// unmodified).

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type persistCmd struct {
	Type          string `json:"type"` // "submit" | "interaction"
	TurnID        string `json:"turnId"`
	Input         string `json:"input,omitempty"`
	InputKind     string `json:"inputKind,omitempty"`
	InteractionID string `json:"interactionId,omitempty"`
	Decision      string `json:"decision,omitempty"`
	Answer        string `json:"answer,omitempty"`
}

type persistEvent struct {
	Event               string          `json:"event"`
	SessionID           string          `json:"sessionId,omitempty"`
	TurnID              string          `json:"turnId,omitempty"`
	Output              string          `json:"output,omitempty"`
	Model               string          `json:"model,omitempty"`
	Kind                string          `json:"kind,omitempty"`
	Error               string          `json:"error,omitempty"`
	RetryAt             *string         `json:"retryAt,omitempty"`
	NativeInteractionID string          `json:"nativeInteractionId,omitempty"`
	InteractionKind     string          `json:"interactionKind,omitempty"`
	Summary             string          `json:"summary,omitempty"`
	NativePayload       json.RawMessage `json:"nativePayload,omitempty"`
	Decision            string          `json:"decision,omitempty"`
	Answer              string          `json:"answer,omitempty"`
}

func emitPersist(e persistEvent) {
	b, _ := json.Marshal(e)
	fmt.Fprintln(os.Stdout, string(b))
}

// openTUI opens the controlling terminal (the human plane) for the
// endpoint's TUI. It returns nil — degrading the TUI OFF, with everything
// running through the machine plane only — unless BOTH:
//
//   - the driver launched this endpoint WITH a TUI PTY (PAGNET_FAKE_TUI=1,
//     set by the driver when its PTYSize is non-nil), AND
//   - the controlling terminal is openable.
//
// The gate is the driver's signal, NOT "is /dev/tty openable": an endpoint
// launched WITHOUT a PTY may still inherit a controlling terminal from its
// parent's session (e.g. a test run from a terminal), and that inherited
// tty is not the endpoint's own TUI. Turning the TUI on there would let the
// human plane (an undrained inherited terminal) block the machine plane —
// the TUI is a feature of the PTY-owning topology, not "any available tty".
func openTUI() *os.File {
	if os.Getenv("PAGNET_FAKE_TUI") != "1" {
		return nil
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil
	}
	return f
}

// sessionMemCmd is a parsed `let <k> <v>` / `print <k>` session-memory
// command.
type sessionMemCmd struct {
	op    string // "let" | "print"
	key   string
	value string
}

// isMemKey reports whether s is a valid session-memory key: alphanumeric
// plus '_', '-', '.' (an identifier-like token, never empty).
func isMemKey(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return true
}

// sessionMemoryCmd scans the input's LINES for a session-memory command
// (`let <k> <v>` or `print <k>`). It line-scans (rather than
// prefix-matching the whole input) because a machine-plane delivery wraps
// the body in a <pagnet-message> XML envelope: the command is a line
// INSIDE the envelope, not the whole input. It returns nil when no line
// is a memory command.
func sessionMemoryCmd(input string) *sessionMemCmd {
	for _, line := range strings.Split(input, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "let":
			if len(f) == 3 && isMemKey(f[1]) {
				return &sessionMemCmd{op: "let", key: f[1], value: f[2]}
			}
		case "print":
			if len(f) == 2 && isMemKey(f[1]) {
				return &sessionMemCmd{op: "print", key: f[1]}
			}
		}
	}
	return nil
}

// sigtermDrainTimeout bounds how long the SIGTERM (hibernate) path waits
// for the in-flight worker to drain before saving. It must be SHORTER than
// the supervisor's TERM→grace→KILL window (default 5s) so the process
// exits cleanly before the KILL lands. A normal (non-interaction-blocked)
// fake turn completes in well under this; a worker blocked on a native
// interaction times out and the process exits without saving (the last
// completed turn is already saved by runPersistTurn).
const sigtermDrainTimeout = 2 * time.Second

// runPersistent is the long-lived endpoint. It reads commands from stdin,
// services them one turn at a time, and streams events on stdout. It runs
// until stdin is closed (EOF) or it receives SIGTERM (hibernate), at which
// point it saves the session and exits cleanly.
func runPersistent(instanceID, sessionDir, resumeID string) {
	sessionPath := filepath.Join(sessionDir, "session.json")
	prev := loadSession(sessionPath)

	// Activation: cold start or resume. A resume of a session with no real
	// exchange (turns == 0) is refused honestly — there is no durable state
	// to resume (the "materialised" boundary).
	if resumeID != "" {
		if os.Getenv("PAGNET_FAKE_RESUME_FAIL") == "1" ||
			prev == nil || prev.SessionID != resumeID || prev.Turns == 0 {
			emitPersist(persistEvent{Event: "runtime.session.lost", Error: "no resumable session found"})
			return
		}
		emitPersist(persistEvent{Event: "runtime.session.resumed", SessionID: prev.SessionID})
	} else {
		id := "fake-persist-" + short(instanceID)
		if prev != nil {
			// Cold start while an old session file exists: start a NEW
			// session (the old one is stale by definition of cold start).
			// The timestamp is PREPENDED so short()'s 12-char truncation
			// does not drop it (an appended timestamp would be truncated
			// away, colliding with the old session's id).
			id = "fake-persist-" + short(fmt.Sprint(time.Now().UnixNano())+instanceID)
		}
		prev = &session{SessionID: id}
		emitPersist(persistEvent{Event: "runtime.session.started", SessionID: prev.SessionID})
	}

	// Single-turn worker: processes one prompt turn at a time (pagnet owns
	// serialisation). The main loop dispatches commands; the worker runs
	// turns and blocks on a scripted interaction until it is answered.
	turnQueue := make(chan persistCmd, 16)
	interactionCh := make(chan persistCmd, 1)

	// TUI (human plane): open the controlling terminal when the endpoint
	// owns one (the daemon launches it with a PTY). tty == nil degrades
	// the TUI OFF (pre-Phase-3 shape / test): the machine plane alone
	// carries everything.
	tty := openTUI()
	var ttyMu sync.Mutex
	ttyDead := false
	ttyWrite := func(s string) {
		if tty == nil {
			return
		}
		ttyMu.Lock()
		defer ttyMu.Unlock()
		if ttyDead {
			return
		}
		if _, err := tty.WriteString(s); err != nil {
			// The master went away (view torn down / endpoint stopping):
			// stop trying — never block shutdown on a dead tty.
			ttyDead = true
		}
	}

	// stdout write serialisation (the worker and the main loop both emit).
	var outMu sync.Mutex
	emit := func(e persistEvent) {
		outMu.Lock()
		defer outMu.Unlock()
		emitPersist(e)
		// TUI: render the turn's visible events to the controlling
		// terminal. A SECOND sink — the machine plane (stdout JSONL) was
		// just emitted and is untouched. The TUI does NOT answer
		// interactions (those resolve on the machine plane).
		switch e.Event {
		case "runtime.turn.output":
			ttyWrite(e.Output + "\n")
		case "runtime.turn.completed":
			ttyWrite("done\n")
		case "runtime.interaction.started":
			ttyWrite("? " + e.Summary + "\n")
		}
	}

	// stopping is closed at the START of shutdown. Every sender to the
	// turn queue (the TUI reader below and the stdin dispatch) selects on
	// it, so a shutdown can unblock a sender that is blocked on a full
	// queue — closing the queue while a sender is blocked on it would
	// panic (send on closed channel). A send case on an already-closed
	// channel is never "ready" in a select, so once stopping is closed the
	// select always resolves to the drop path, never a panic.
	stopping := make(chan struct{})
	tuiDone := make(chan struct{})
	if tty != nil {
		go func() {
			defer close(tuiDone)
			r := bufio.NewReader(tty)
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					// tty closed (shutdown) or EOF (master closed): the
					// TUI is done; the machine plane keeps running.
					return
				}
				line = strings.TrimRight(line, "\r\n")
				if line == "" {
					continue
				}
				ttyWrite("you> " + line + "\n")
				cmd := persistCmd{
					Type:      "submit",
					TurnID:    "tui-" + strconv.FormatInt(time.Now().UnixNano(), 10),
					Input:     line,
					InputKind: "user_input",
				}
				select {
				case turnQueue <- cmd:
				case <-stopping:
					return
				}
			}
		}()
	}
	// stopTUI closes the tty (unblocking the reader if it is waiting on a
	// line) and waits for the reader to exit. It is called AFTER stopping
	// is closed, so the reader has already dropped any in-flight send.
	stopTUI := func() {
		if tty == nil {
			return
		}
		ttyMu.Lock()
		ttyDead = true
		_ = tty.Close()
		ttyMu.Unlock()
		<-tuiDone
	}

	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for cmd := range turnQueue {
			runPersistTurn(cmd, prev, sessionPath, emit, interactionCh)
		}
	}()

	// Graceful shutdown: SIGTERM (hibernate) or EOF (stdin closed) saves
	// the session and exits cleanly. The session file is the resume
	// payload; saving on the way out is what makes hibernate preserve the
	// native session (invariant F).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	dispatch := func(cmd persistCmd) {
		switch cmd.Type {
		case "submit":
			// Select on stopping: a shutdown unblocks a full queue (a
			// plain send would race the queue close and panic).
			select {
			case turnQueue <- cmd:
			case <-stopping:
			}
		case "interaction":
			interactionCh <- cmd
		default:
			// Unknown command types are ignored (never a silent failure of
			// a known one).
		}
	}
	// shutdown begins the orderly teardown, exactly once (the stdin-EOF
	// path and the SIGTERM path both want to drain the worker; a double
	// close of stopping or the queue would panic). Order matters:
	//   1. close stopping  — every sender drops its in-flight send;
	//   2. stopTUI         — close the tty, wait for the TUI reader out;
	//   3. close the queue — safe now: no sender is blocked on it.
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			close(stopping)
			stopTUI()
			close(turnQueue)
		})
	}

	readLoop := make(chan struct{})
	go func() {
		defer close(readLoop)
		for scanner.Scan() {
			var cmd persistCmd
			if err := json.Unmarshal(scanner.Bytes(), &cmd); err != nil {
				continue
			}
			dispatch(cmd)
		}
		// EOF: begin the orderly teardown so the worker drains and exits.
		shutdown()
	}()

	select {
	case <-sigCh:
		// Hibernate: drain the in-flight worker BEFORE saving (R2 — the EOF
		// path already did; the SIGTERM path must too, or the save races
		// the worker's own session write). shutdown() stops the senders
		// and closes the turn queue, letting the worker finish its
		// in-flight turn (which saves the session at the end of the turn).
		// The drain is BOUNDED: a worker blocked on a native interaction
		// would otherwise hang shutdown past the supervisor's
		// TERM→grace→KILL window. When the drain times out (worker still
		// blocked), do NOT save — it would race the worker's own write;
		// the last COMPLETED turn is already saved by runPersistTurn.
		shutdown()
		select {
		case <-workerDone:
			// The worker finished (and saved the session for its last turn).
		case <-time.After(sigtermDrainTimeout):
			// The worker is blocked (e.g. on a native interaction): exit
			// without saving (the in-flight turn is lost, the last
			// completed turn is preserved).
			return
		}
	case <-readLoop:
		// stdin closed: the readLoop goroutine already ran shutdown();
		// drain in-flight work, then exit.
		<-workerDone
	}
	if prev != nil {
		// R9: a failed session save is logged (like the legacy turn mode),
		// not silently dropped — a lost save means the next resume loses
		// the session.
		if err := saveSession(sessionPath, prev); err != nil {
			fmt.Fprintln(os.Stderr, "save session:", err)
		}
	}
}

// dieMidTurnOnce simulates an endpoint that CRASHES in the middle of a turn
// (PAGNET_FAKE_DIE_MID_TURN=1): the first turn its SESSION services kills
// the process with a hard SIGKILL, right after turn.started — no terminal
// event, no session save, no graceful shutdown. A marker file in the session
// dir (which outlives the process, unlike memory) records that the crash
// already happened, so the endpoint the session core re-activates for the
// retry services the turn normally.
//
// It is the deterministic stand-in for the vendor crash / SIGKILL / OOM that
// lands mid-turn: the ONE condition the session core must tolerate without
// wedging the instance.
func dieMidTurnOnce(sessionPath string) {
	if os.Getenv("PAGNET_FAKE_DIE_MID_TURN") != "1" {
		return
	}
	marker := filepath.Join(filepath.Dir(sessionPath), ".died-mid-turn")
	if _, err := os.Stat(marker); err == nil {
		return // this session already crashed once — service the turn
	}
	if err := os.WriteFile(marker, []byte("died mid-turn\n"), 0o600); err != nil {
		// Fail loudly: without the marker the crash would repeat on every
		// re-activation and the test would not be testing recovery.
		fmt.Fprintln(os.Stderr, "die-mid-turn marker:", err)
		return
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
}

// runPersistTurn runs one prompt turn: emits busy/started, blocks on a
// scripted interaction (answered via interactionCh), emits output/completed
// and idle, and persists the session (materialising it on the first
// exchange).
func runPersistTurn(cmd persistCmd, prev *session, sessionPath string, emit func(persistEvent), interactionCh <-chan persistCmd) {
	emit(persistEvent{Event: "runtime.busy", TurnID: cmd.TurnID, SessionID: prev.SessionID})
	emit(persistEvent{Event: "runtime.turn.started", TurnID: cmd.TurnID, SessionID: prev.SessionID})

	// The turn is now genuinely in flight — this is where a real vendor
	// process can die (see dieMidTurnOnce).
	dieMidTurnOnce(sessionPath)

	// Rate-limit simulation (deterministic for tests): a turn that fails as
	// rate_limited never materialises the session.
	if rl := os.Getenv("PAGNET_FAKE_RATELIMIT"); rl != "" {
		var retryAt *string
		if rl != "unknown" {
			d := parseDuration(rl)
			t := time.Now().UTC().Add(d).Format(time.RFC3339)
			retryAt = &t
		}
		emit(persistEvent{Event: "runtime.turn.failed", TurnID: cmd.TurnID, SessionID: prev.SessionID,
			Kind: "rate_limited", Error: "rate limited (simulated)", RetryAt: retryAt})
		emit(persistEvent{Event: "runtime.idle", TurnID: cmd.TurnID, SessionID: prev.SessionID})
		return
	}

	// Session memory (Phase 3): `let <k> <v>` stores a value, `print <k>`
	// reads it back. Both are FULL turns (busy/started/output/completed/
	// idle, Turns++, persisted) so they flow through the same turn
	// lifecycle — and because the value is persisted in the session file,
	// it survives hibernate/wake (invariant F).
	if mem := sessionMemoryCmd(cmd.Input); mem != nil {
		var out string
		if mem.op == "let" {
			if prev.Vars == nil {
				prev.Vars = map[string]string{}
			}
			prev.Vars[mem.key] = mem.value
			out = fmt.Sprintf("[fake-persist %s] let %s = %s",
				kindOr(cmd.InputKind, "turn"), mem.key, mem.value)
		} else {
			if v, ok := prev.Vars[mem.key]; ok {
				out = fmt.Sprintf("[fake-persist %s] print %s: %s",
					kindOr(cmd.InputKind, "turn"), mem.key, v)
			} else {
				out = fmt.Sprintf("[fake-persist %s] print %s: %s unset",
					kindOr(cmd.InputKind, "turn"), mem.key, mem.key)
			}
		}
		emit(persistEvent{Event: "runtime.turn.output", TurnID: cmd.TurnID, SessionID: prev.SessionID, Output: out})
		prev.Turns++
		prev.LastInput = firstLine(cmd.Input)
		prev.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		_ = saveSession(sessionPath, prev)
		emit(persistEvent{
			Event: "runtime.turn.completed", TurnID: cmd.TurnID, SessionID: prev.SessionID, Model: "fake-persist-1",
		})
		emit(persistEvent{Event: "runtime.idle", TurnID: cmd.TurnID, SessionID: prev.SessionID})
		return
	}

	// Scripted native interaction: the turn blocks until an interaction
	// command answers it (the busy/idle + interaction round-trip).
	if kind := os.Getenv("PAGNET_FAKE_INTERACTION"); kind != "" {
		nativeID := "fake-int-" + short(cmd.TurnID)
		var payload json.RawMessage
		if raw := os.Getenv("PAGNET_FAKE_INTERACTION_PAYLOAD"); raw != "" {
			if !json.Valid([]byte(raw)) {
				fmt.Fprintf(os.Stderr, "PAGNET_FAKE_INTERACTION_PAYLOAD is not valid JSON: %q\n", raw)
				os.Exit(2)
			}
			payload = json.RawMessage(raw)
		} else {
			payload, _ = json.Marshal(map[string]any{
				"version": 1,
				"prompt":  "fake native question (opaque vendor payload)",
			})
		}
		summary := os.Getenv("PAGNET_FAKE_INTERACTION_SUMMARY")
		if summary == "" {
			summary = "fake " + kind + " (simulated)"
		}
		emit(persistEvent{
			Event: "runtime.interaction.started", TurnID: cmd.TurnID, SessionID: prev.SessionID,
			NativeInteractionID: nativeID, InteractionKind: kind, Summary: summary, NativePayload: payload,
		})
		// Block until the interaction is answered externally (via the
		// submit path), or the process is told to stop.
		ans := <-interactionCh
		decision := ans.Decision
		if decision == "" {
			decision = "resolved"
		}
		emit(persistEvent{
			Event: "runtime.interaction.resolved", TurnID: cmd.TurnID, SessionID: prev.SessionID,
			NativeInteractionID: nativeID, InteractionKind: kind, Decision: decision, Answer: ans.Answer,
		})
	}

	// Deterministic "work": echo the input (one transcript chunk).
	out := fmt.Sprintf("[fake-persist %s] handled %s: %s",
		kindOr(cmd.InputKind, "turn"), firstLine(cmd.Input), firstLine(cmd.Input))
	emit(persistEvent{Event: "runtime.turn.output", TurnID: cmd.TurnID, SessionID: prev.SessionID, Output: out})

	// Persist the session (materialises it on the first exchange).
	prev.Turns++
	prev.LastInput = firstLine(cmd.Input)
	prev.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = saveSession(sessionPath, prev)

	emit(persistEvent{
		Event: "runtime.turn.completed", TurnID: cmd.TurnID, SessionID: prev.SessionID, Model: "fake-persist-1",
	})
	emit(persistEvent{Event: "runtime.idle", TurnID: cmd.TurnID, SessionID: prev.SessionID})
}
