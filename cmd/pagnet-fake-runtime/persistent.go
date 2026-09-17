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

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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

	// stdout write serialisation (the worker and the main loop both emit).
	var outMu sync.Mutex
	emit := func(e persistEvent) {
		outMu.Lock()
		defer outMu.Unlock()
		emitPersist(e)
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
			turnQueue <- cmd
		case "interaction":
			interactionCh <- cmd
		default:
			// Unknown command types are ignored (never a silent failure of
			// a known one).
		}
	}
	// The turn queue is closed exactly once (the EOF path and the SIGTERM
	// path both want to drain the worker; a double close would panic).
	var closeQueueOnce sync.Once
	closeTurnQueue := func() { closeQueueOnce.Do(func() { close(turnQueue) }) }

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
		// EOF: close the turn queue so the worker drains and exits.
		closeTurnQueue()
	}()

	select {
	case <-sigCh:
		// Hibernate: drain the in-flight worker BEFORE saving (R2 — the EOF
		// path already did; the SIGTERM path must too, or the save races
		// the worker's own session write). Closing the turn queue lets the
		// worker finish its in-flight turn (which saves the session at the
		// end of the turn). The drain is BOUNDED: a worker blocked on a
		// native interaction would otherwise hang shutdown past the
		// supervisor's TERM→grace→KILL window. When the drain times out
		// (worker still blocked), do NOT save — it would race the worker's
		// own write; the last COMPLETED turn is already saved by
		// runPersistTurn.
		closeTurnQueue()
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
		// stdin closed: drain in-flight work, then exit.
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

// runPersistTurn runs one prompt turn: emits busy/started, blocks on a
// scripted interaction (answered via interactionCh), emits output/completed
// and idle, and persists the session (materialising it on the first
// exchange).
func runPersistTurn(cmd persistCmd, prev *session, sessionPath string, emit func(persistEvent), interactionCh <-chan persistCmd) {
	emit(persistEvent{Event: "runtime.busy", TurnID: cmd.TurnID, SessionID: prev.SessionID})
	emit(persistEvent{Event: "runtime.turn.started", TurnID: cmd.TurnID, SessionID: prev.SessionID})

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
