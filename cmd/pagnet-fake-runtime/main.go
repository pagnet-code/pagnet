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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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
}

func emit(e event) {
	b, _ := json.Marshal(e)
	fmt.Fprintln(os.Stdout, string(b))
}

func main() {
	if hasArg(os.Args[1:], "--pty") {
		runPTY(plyArgValue(os.Args[1:], "--instance-id"),
			plyArgValue(os.Args[1:], "--session-dir"),
			plyArgValue(os.Args[1:], "--resume"))
	}
	var s spec
	if err := json.NewDecoder(os.Stdin).Decode(&s); err != nil {
		fmt.Fprintln(os.Stderr, "bad spec:", err)
		os.Exit(2)
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
	return os.WriteFile(path, b, 0o644)
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

	// Raw-ish termios: drop canonical mode AND signal generation so the
	// process sees individual keystrokes and control sequences (arrows,
	// Ctrl+C) as BYTES — the way a real interactive CLI (raw mode)
	// handles its own ^C. ECHO is kept so typed input stays visible
	// through the PTY line discipline. (With ISIG left on, the kernel
	// would turn ^C into SIGINT and kill this process before it could
	// react — the wrong model for an interactive UI.)
	var old *unix.Termios
	if t, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
		old = t
		raw := *t
		raw.Lflag &^= unix.ICANON | unix.ISIG
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, &raw)
		defer func() {
			if old != nil {
				_ = unix.IoctlSetTermios(fd, unix.TCSETS, old)
			}
		}()
	}

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
		fmt.Printf("initial size: %dx%d — unicode ok: äöü 日本語 🚀\r\n", cols, rows)
	}
	fmt.Print(prompt)

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
			case c == '\r':
				// \r\n pair: the \n finalizes the line.
				continue
			case c == 0x7f, c == 0x08: // backspace (kernel already echoed)
				if len(line) > 0 {
					line = line[:len(line)-1]
				}
				continue
			case c == '\n':
				processFakeLine(string(line), prev, save, prompt, winsize)
				line = nil
				continue
			default:
				line = append(line, c)
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
		fmt.Printf("unicode: äöü 日本語 emoji: 🚀 ✅\r\n%s", prompt)
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
