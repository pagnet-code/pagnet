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
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
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
