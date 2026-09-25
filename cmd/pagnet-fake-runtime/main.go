// Command pagnet-fake-runtime is the subprocess the fake runtime adapter
// launches for each turn (process-per-turn). It is a real, resumable
// simulation runtime:
//
//   - stdin:  one JSON turn spec {instanceId, sessionDir, resume, input,
//     inputKind, wakeReason, metadata}
//   - stdout: JSONL events (runtime.session.started|resumed,
//     runtime.session.lost, runtime.turn.started, runtime.turn.completed,
//     runtime.turn.failed)
//   - state:  <sessionDir>/session.json persists the resumable session
//
// Simulation knobs (env), used by the E2E suite:
//   - PAGNET_FAKE_RATELIMIT=<duration|"unknown">: fail every turn as
//     rate_limited; with a duration the retryAt is provider-style, with
//     "unknown" no retryAt is provided (manual recovery path).
//   - PAGNET_FAKE_RESUME_FAIL=1: a resume request always loses the session.
//   - PAGNET_FAKE_HOLD=<duration>: keep the turn process alive for the
//     duration (cancellation/stop lifecycle tests).
//   - PAGNET_FAKE_EXIT_DELAY=<duration>: delay the process's exit AFTER
//     its last event (completion/failure/lost) — a runtime that takes
//     time to shut down (flushing, closing connections). The process is
//     still alive when the adapter's post-terminal-event cleanup TERM
//     arrives: the deterministic fixture for the turn-lifecycle
//     exit-window race (2026-09-16 e2e cascade).
//   - PAGNET_FAKE_DESCENDANTS=<n>: spawn n descendant branches
//     (sh → sleep) that outlive the runtime process — the process-tree
//     containment fixture (abuse addendum §47). The branches inherit this
//     process's environment, so a PAGNET_P0_LEAK marker in the turn env
//     marks the whole tree for measurement.
//   - PAGNET_FAKE_PTY_CHILD=1 (PTY mode): spawn a child that keeps the
//     PTY slave open (PTY lifecycle fixture: slave-holding descendants).
//
// Interactive PTY mode (--pty): a deterministic, scriptable stand-in for a
// real runtime's interactive UI (addendum §68 "fake PTY fixtures that
// emulate differing runtime UIs"). The daemon runs it under a PTY and the
// whole browser/CLI terminal stack is exercised against it:
//   - commands: echo <text> | unicode | big | resized | exit | crash
//   - keystrokes: Ctrl+C (caught, stays alive), Ctrl+D (EOF), backspace
//   - arrow keys: ESC [ A/B/C/D reported ("arrow: up" ...)
//   - SIGWINCH: prints "resized to <cols>x<rows>"
//   - UI variant: PAGNET_FAKE_UI=classic (default) | dense
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

type spec struct {
	InstanceID string         `json:"instanceId"`
	SessionDir string         `json:"sessionDir"`
	Resume     bool           `json:"resume"`
	Input      string         `json:"input"`
	InputKind  string         `json:"inputKind"`
	WakeReason string         `json:"wakeReason"`
	Metadata   map[string]any `json:"metadata"`
}

type session struct {
	SessionID string `json:"sessionId"`
	Turns     int    `json:"turns"`
	LastInput string `json:"lastInput,omitempty"`
	UpdatedAt string `json:"updatedAt"`
	// Vars is the endpoint's session memory (Phase 3 terminal session
	// unification): `let <k> <v>` / `print <k>` persist here so the value
	// survives hibernate/wake (the session file is the resume payload).
	Vars map[string]string `json:"vars,omitempty"`
	// pagnet injection observed by the runtime process (spec E2E 8:
	// "MCP injected, coordination contract injected"). Real runtimes
	// consume the MCP config as their MCP client config; the fake only
	// records that it arrived.
	MCPInjected      bool `json:"mcpInjected,omitempty"`
	ContractInjected bool `json:"contractInjected,omitempty"`
}

type event struct {
	Event        string  `json:"event"`
	SessionID    string  `json:"sessionId,omitempty"`
	Output       string  `json:"output,omitempty"`
	Model        string  `json:"model,omitempty"`
	InputTokens  *int    `json:"inputTokens,omitempty"`
	OutputTokens *int    `json:"outputTokens,omitempty"`
	CachedTokens *int    `json:"cachedTokens,omitempty"`
	Kind         string  `json:"kind,omitempty"`
	Error        string  `json:"error,omitempty"`
	RetryAt      *string `json:"retryAt,omitempty"`
	// Native-interaction fields (Phase 5). The helper only supplies the
	// runtime-native id + normalized fields; the adapter/daemon mint the
	// pagnet-side interaction id.
	NativeInteractionID string          `json:"nativeInteractionId,omitempty"`
	InteractionKind     string          `json:"interactionKind,omitempty"`
	Summary             string          `json:"summary,omitempty"`
	NativePayload       json.RawMessage `json:"nativePayload,omitempty"`
	Decision            string          `json:"decision,omitempty"`
	Answer              string          `json:"answer,omitempty"`
}

func emit(e event) {
	b, _ := json.Marshal(e)
	fmt.Fprintln(os.Stdout, string(b))
}

func main() {
	if hasArg(os.Args[1:], "--version") || hasArg(os.Args[1:], "-v") {
		fmt.Println("pagnet-fake-runtime 1.0.0 (deterministic test runtime)")
		return
	}
	if hasArg(os.Args[1:], "--pty") {
		runPTY(plyArgValue(os.Args[1:], "--instance-id"),
			plyArgValue(os.Args[1:], "--session-dir"),
			plyArgValue(os.Args[1:], "--resume"))
	}
	if hasArg(os.Args[1:], "--persistent") {
		runPersistent(plyArgValue(os.Args[1:], "--instance-id"),
			plyArgValue(os.Args[1:], "--session-dir"),
			plyArgValue(os.Args[1:], "--resume"))
		return
	}
	var s spec
	if err := json.NewDecoder(os.Stdin).Decode(&s); err != nil {
		fmt.Fprintln(os.Stderr, "bad spec:", err)
		os.Exit(2)
	}

	// PAGNET_FAKE_EXIT_DELAY: registered here, run at main's return —
	// AFTER the last event has been written to the (unbuffered) stdout
	// pipe — so the process stays alive past its terminal event on every
	// exit path (completion, failure, lost). (os.Exit paths skip defers;
	// those are fixture errors, not turn outcomes.)
	if d := os.Getenv("PAGNET_FAKE_EXIT_DELAY"); d != "" {
		delay := parseDuration(d)
		defer time.Sleep(delay)
	}

	sessionPath := filepath.Join(s.SessionDir, "session.json")
	prev := loadSession(sessionPath)

	// Record the pagnet injection handed to this process by the daemon.
	mcpInjected := os.Getenv("PAGNET_MCP_CONFIG") != ""
	contractInjected := false
	if p := os.Getenv("PAGNET_COORDINATION_CONTRACT"); p != "" {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			contractInjected = true
		}
	}

	// Resume handling: a requested resume with no usable session is a
	// first-class outcome (session_lost), not an error to swallow.
	if s.Resume {
		if os.Getenv("PAGNET_FAKE_RESUME_FAIL") == "1" || prev == nil {
			emit(event{Event: "runtime.session.lost", Error: "no resumable session found"})
			return
		}
		emit(event{Event: "runtime.session.resumed", SessionID: prev.SessionID})
	} else {
		id := "fake-" + short(s.InstanceID)
		if prev != nil {
			// Cold start while an old session file exists: start a NEW
			// session (the old one is stale by definition of cold start).
			id = "fake-" + short(s.InstanceID+"-"+fmt.Sprint(time.Now().UnixNano()))
		}
		prev = &session{SessionID: id}
		emit(event{Event: "runtime.session.started", SessionID: prev.SessionID})
	}

	// Rate-limit simulation (deterministic for tests).
	if rl := os.Getenv("PAGNET_FAKE_RATELIMIT"); rl != "" {
		var retryAt *string
		if rl != "unknown" {
			d := parseDuration(rl)
			t := time.Now().UTC().Add(d).Format(time.RFC3339)
			retryAt = &t
		}
		fail := event{
			Event:   "runtime.turn.failed",
			Kind:    "rate_limited",
			Error:   "rate limited (simulated)",
			RetryAt: retryAt,
		}
		if prev != nil {
			fail.SessionID = prev.SessionID
		}
		emit(fail)
		return
	}

	emit(event{Event: "runtime.turn.started", SessionID: prev.SessionID})

	// Process-tree containment fixture (§47): spawn descendant branches
	// that outlive this process (a real runtime's shells / MCP bridges /
	// node helpers). Deliberately NOT waited on: reaping the tree is the
	// supervisor's job, never the runtime's.
	spawnDescendants()

	// Hold the process alive (cancellation / stop lifecycle tests).
	if hold := os.Getenv("PAGNET_FAKE_HOLD"); hold != "" {
		time.Sleep(parseDuration(hold))
	}

	// Native-interaction simulation (Phase 5): when scripted, the fake
	// "asks" a native question mid-turn (runtime.interaction.started) and,
	// when also scripted, the (fake) user answers in the native TUI before
	// the turn ends (runtime.interaction.resolved). The turn ALWAYS
	// completes — the fake is process-per-turn; "defer" (PAGNET_FAKE_DEFER)
	// only changes how the DAEMON treats the pending interaction (hibernate
	// vs keep waiting), not whether the process exits.
	if kind := os.Getenv("PAGNET_FAKE_INTERACTION"); kind != "" {
		nativeID := "fake-int-" + short(s.InstanceID)
		// PAGNET_FAKE_INTERACTION_PAYLOAD overrides the opaque vendor
		// payload (raw JSON) so e2e can script arbitrary payload shapes;
		// invalid JSON is a fixture error, not a silent fallback.
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
		emit(event{
			Event:               "runtime.interaction.started",
			SessionID:           prev.SessionID,
			NativeInteractionID: nativeID,
			InteractionKind:     kind,
			Summary:             summary,
			NativePayload:       payload,
		})
		if decision := os.Getenv("PAGNET_FAKE_INTERACTION_RESOLVE"); decision != "" {
			emit(event{
				Event:               "runtime.interaction.resolved",
				SessionID:           prev.SessionID,
				NativeInteractionID: nativeID,
				InteractionKind:     kind,
				Decision:            decision,
				Answer:              os.Getenv("PAGNET_FAKE_INTERACTION_ANSWER"),
			})
		}
	}

	// Deterministic "work": echo the input; transcript-level network means
	// the daemon receives one output chunk.
	out := fmt.Sprintf("[fake %s] handled %s: %s",
		kindOr(s.InputKind, "turn"), firstLine(s.Input), firstLine(s.Input))
	emit(event{Event: "runtime.turn.output", Output: out, SessionID: prev.SessionID})

	prev.Turns++
	prev.LastInput = firstLine(s.Input)
	prev.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	prev.MCPInjected = mcpInjected
	prev.ContractInjected = contractInjected
	if err := saveSession(sessionPath, prev); err != nil {
		fmt.Fprintln(os.Stderr, "save session:", err)
	}

	inTok := 4 + len(s.Input)/4
	outTok := 4 + len(out)/4
	emit(event{
		Event:        "runtime.turn.completed",
		SessionID:    prev.SessionID,
		Model:        "fake-1",
		InputTokens:  &inTok,
		OutputTokens: &outTok,
	})
}

func loadSession(path string) *session {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var s session
	if err := json.Unmarshal(b, &s); err != nil || s.SessionID == "" {
		return nil
	}
	return &s
}

func saveSession(path string, s *session) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	// 0600 (private) + atomic (temp+rename): a crash mid-write must not
	// corrupt the resumable session, and the session file is never
	// world-readable (external audit F-013/F-015).
	return atomicWriteFile(path, b, 0o600)
}

// atomicWriteFile writes data to path atomically (temp file in the same
// directory, fsync, rename) with the given perm.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func short(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return -1
	}, s)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func kindOr(k, def string) string {
	if k == "" {
		return def
	}
	return k
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

func parseDuration(s string) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return 30 * time.Second
}

// spawnDescendants starts PAGNET_FAKE_DESCENDANTS branches (default 2)
// of `sh -c 'sleep 3600 & sleep 3600'` — parent → child → grandchild,
// the §47 tree shape. The branches inherit this process's environment
// (ownership markers included) and are left running: they simulate the
// helper processes a real runtime leaves behind (MCP bridges, shells,
// node). Containment of the tree is the pagnet supervisor's job.
//
// The descendants' stdio is /dev/null, NOT an inheritance of this
// process's pipes: a real runtime's background helpers do not write to
// the turn's stdout, and a descendant that holds the turn's stdout/
// stderr pipe open keeps the reader blocked on EOF until it dies — the
// hang mode behind the 2026-09-15 stress incident (every test cycle
// waited out the full turn context before the group was reclaimed).
func spawnDescendants() {
	n := 2
	if v := os.Getenv("PAGNET_FAKE_DESCENDANTS"); v != "" {
		if m, err := strconv.Atoi(v); err == nil && m > 0 {
			n = m
		}
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "descendant fixture devnull:", err)
		return
	}
	defer devNull.Close()
	for i := 0; i < n; i++ {
		cmd := exec.Command("sh", "-c", "sleep 3600 & sleep 3600")
		cmd.Stdout = devNull
		cmd.Stderr = devNull // Stdin nil → /dev/null
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "descendant fixture spawn:", err)
		}
	}
}

func hasArg(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func plyArgValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// --- interactive PTY mode ------------------------------------------------------

func runPTY(instanceID, sessionDir, resumeID string) {
	fd := int(os.Stdin.Fd())

	// Raw termios: drop canonical mode, signal generation AND echo so the
	// process sees individual keystrokes and control sequences (arrows,
	// Ctrl+C) as BYTES — the way a real interactive CLI (raw mode)
	// handles its own ^C. (With ISIG left on, the kernel would turn ^C
	// into SIGINT and kill this process before it could react — the wrong
	// model for an interactive UI.) Input echo is the REPL's own, below.
	//
	// ECHO is cleared too: with ICANON off the kernel no longer treats
	// 0x7f/0x08 as the erase control — and with ECHO on it would echo
	// those raw backspace bytes into the output (the "strange characters
	// on backspace" bug: a literal DEL/BS byte or "^?"/"^H" on the
	// screen). The REPL owns ALL input echo now, the way a real raw-mode
	// interactive CLI does: it echoes typed characters itself and
	// redraws on erase.
	restore := setRawInput(fd)
	defer restore()

	ui := os.Getenv("PAGNET_FAKE_UI")
	if ui == "" {
		ui = "classic"
	}
	prompt := "\x1b[1;32mfake-agent>\x1b[0m "
	if ui == "dense" {
		prompt = "\x1b[38;5;45m▸\x1b[0m "
	}

	// SIGWINCH: the PTY resize lands here (addendum §9 flow end point).
	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.SIGWINCH)
	go func() {
		for range sigwinch {
			if c, r, err := term.GetSize(fd); err == nil {
				fmt.Printf("\r\nresized to %dx%d\r\n", c, r)
			}
		}
	}()

	// Session (resumed when the daemon handed a stored id and the file
	// exists — the same resume semantics as turn mode).
	var prev *session
	var status string
	if sessionDir != "" {
		prev = loadSession(filepath.Join(sessionDir, "session.json"))
	}
	resumed := false
	if resumeID != "" && prev != nil {
		resumed = true
	}
	if prev == nil {
		prev = &session{SessionID: "fake-" + short(instanceID)}
	}
	status = "started"
	if resumed {
		status = "resumed"
	}

	winsize := func() (int, int) {
		if c, r, err := term.GetSize(fd); err == nil {
			return c, r
		}
		return 80, 24
	}
	cols, rows := winsize()

	if ui == "dense" {
		fmt.Printf("\x1b[7m fake %s %s \x1b[27m turns=%d size=%dx%d ✓\r\n",
			prev.SessionID, status, prev.Turns, cols, rows)
	} else {
		fmt.Printf("\x1b[1;32mFAKE AGENT\x1b[0m (ui=%s) — session %s %s, turns: %d\r\n",
			ui, prev.SessionID, status, prev.Turns)
		fmt.Printf("initial size: %dx%d — unicode ok: äöü ñçß 🚀\r\n", cols, rows)
	}
	fmt.Print(prompt)

	// PTY lifecycle fixture: a child that keeps the PTY slave open (a
	// real TUI's helper processes inherit the slave). It must inherit
	// the slave fds explicitly — exec would otherwise give it fresh
	// pipes.
	//
	// The child IGNORES SIGHUP (trap "" HUP; exec …): when the session
	// leader (the runtime) dies, the kernel broadcasts SIGHUP to the PTY
	// foreground process group. A helper with the default SIGHUP
	// disposition would die from that broadcast and the leak would be
	// masked — but real helpers (daemons, nohup'd processes, job-control
	// background jobs) ignore SIGHUP or sit in their own group and
	// SURVIVE, keeping the slave open. Ignoring HUP here reproduces the
	// production shape: the direct child is killed, the slave-holding
	// descendant is not.
	if os.Getenv("PAGNET_FAKE_PTY_CHILD") == "1" {
		c := exec.Command("sh", "-c", "trap \"\" HUP; exec sleep 3600")
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := c.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "pty child fixture spawn: %v\r\n", err)
		}
	}

	save := func() {
		if sessionDir == "" {
			return
		}
		prev.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		_ = saveSession(filepath.Join(sessionDir, "session.json"), prev)
	}

	var line []byte
	one := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(one)
		if n > 0 {
			switch c := one[0]; {
			case c == 0x03: // Ctrl+C: caught, the REPL stays alive
				fmt.Printf("\r\n^C (caught)\r\n%s", prompt)
			case c == 0x04: // Ctrl+D: EOF
				save()
				fmt.Print("bye\r\n")
				return
			case c == 0x1b: // ESC: read the two sequence bytes
				if a, b := readByte(one), readByte(one); a == '[' {
					switch b {
					case 'A':
						fmt.Print("\r\narrow: up\r\n" + prompt)
					case 'B':
						fmt.Print("\r\narrow: down\r\n" + prompt)
					case 'C':
						fmt.Print("\r\narrow: right\r\n" + prompt)
					case 'D':
						fmt.Print("\r\narrow: left\r\n" + prompt)
					}
				}
				line = nil
				continue
			case c == '\r', c == '\n':
				// Enter (ICRNL maps \r→\n; either byte may arrive). The
				// REPL owns the newline echo in raw mode.
				fmt.Print("\r\n")
				processFakeLine(string(line), prev, save, prompt, winsize)
				line = nil
				continue
			case c == 0x7f, c == 0x08: // backspace (DEL or Ctrl+Backspace)
				// Raw-mode erase: retract the last visible character
				// ourselves so screen and line stay in sync — left,
				// blank, left.
				if len(line) > 0 {
					line = line[:len(line)-1]
					fmt.Print("\b \b")
				}
				continue
			default:
				// Typed input echo (kernel ECHO is off in raw mode).
				line = append(line, c)
				fmt.Print(string(c))
			}
			continue
		}
		if err != nil {
			save()
			return
		}
	}
}

// readByte reads one stdin byte (0 on EOF) — for ESC sequences.
func readByte(one []byte) byte {
	n, _ := os.Stdin.Read(one)
	if n == 0 {
		return 0
	}
	return one[0]
}

func processFakeLine(s string, prev *session, save func(), prompt string, winsize func() (int, int)) {
	switch {
	case s == "":
		fmt.Print(prompt)
	case s == "exit":
		save()
		fmt.Print("bye\r\n")
		os.Exit(0)
	case s == "crash":
		save()
		os.Exit(1)
	case strings.HasPrefix(s, "echo "):
		fmt.Printf("echo: %s\r\n%s", s[len("echo "):], prompt)
	case s == "unicode":
		fmt.Printf("unicode: äöü ñçß emoji: 🚀 ✅\r\n%s", prompt)
	case s == "big":
		// ~512 KiB of output: exercises the bounded ring buffer and the
		// browser's scrollback under load (addendum §68 "large output").
		for i := 0; i < 512; i++ {
			fmt.Printf("line %04d: %s\r\n", i, strings.Repeat("x", 1024))
		}
		fmt.Print(prompt)
	case s == "resized":
		c, r := winsize()
		fmt.Printf("current size: %dx%d\r\n%s", c, r, prompt)
	default:
		fmt.Printf("fake: got %q\r\n%s", s, prompt)
	}
	prev.Turns++
	prev.LastInput = firstLine(s)
	save()
}
