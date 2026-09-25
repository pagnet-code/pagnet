// codex.go — Codex app-server mode (trigger: `app-server` in argv): a
// deterministic fake Codex app-server (JSON-RPC 2.0 over stdio, one JSON
// object per line).
//
// It is the fixture stand-in for `codex app-server --stdio` for the
// CodexPersistent driver tests: a REAL process with real stdio and real
// JSON-RPC, scripted deterministically through env knobs (the same
// pattern as --persistent mode). It speaks the protocol subset the
// driver uses:
//
//	Requests (client → server):
//	  initialize {clientInfo}
//		thread/start {cwd, developerInstructions?, model?}
//		thread/resume {threadId, cwd, developerInstructions?}
//		turn/start {threadId, input:[{type:"text", text}]}
//
//	Notifications (server → client, no id):
//	  turn/started, item/agentMessage/delta, item/started,
//	  item/completed, thread/tokenUsage/updated, turn/completed (terminal)
//
//	Server requests (server → client, WITH id — native interactions):
//	  item/commandExecution/requestApproval, item/fileChange/requestApproval,
//	  item/permissions/requestApproval, item/tool/requestUserInput,
//	  mcpServer/elicitation/request, openai/form
//
// Simulation knobs (env):
//   - PAGNET_FAKE_CODEX_THREAD_ID=<id>: the thread id to mint/return
//     (default: a fixed UUIDv7-shaped id).
//   - PAGNET_FAKE_CODEX_ARGV_FILE=<path>: write os.Args (JSON) at start —
//     the assertion point for the -c MCP config overrides.
//   - PAGNET_FAKE_CODEX_METHODS_FILE=<path>: append every request method
//     received — the assertion point for thread/start vs thread/resume
//     and the turn count.
//   - PAGNET_FAKE_CODEX_STANDING_FILE=<path>: write the
//     developerInstructions received on thread/start / thread/resume —
//     the assertion point for standing-document delivery.
//   - PAGNET_FAKE_CODEX_TURN_INPUT_FILE=<path>: write the turn/start
//     input text on every turn — the assertion point that the turn input
//     is the daemon's input verbatim (and never the standing document).
//   - PAGNET_FAKE_CODEX_RESPONSE_FILE=<path>: write the raw JSON-RPC
//     response line to a server request — the assertion point for the
//     exact interaction-resolution shape.
//   - PAGNET_FAKE_CODEX_NO_INITIALIZE_RESPONSE=1: never answer
//     initialize (the handshake-timeout fixture: a clean launch error,
//     not a hang).
//   - PAGNET_FAKE_CODEX_NOISE=1: emit unrelated notifications before the
//     initialize and turn/start responses (the correlation fixture:
//     responses must be matched by id, not by arrival order).
//   - PAGNET_FAKE_CODEX_THREAD_START_FAIL=1: thread/start answers with a
//     JSON-RPC error (a cold-start failure).
//   - PAGNET_FAKE_CODEX_THREAD_START_EMPTY=1: thread/start answers with a
//     result carrying no thread id.
//   - PAGNET_FAKE_CODEX_RESUME_FAIL=1: thread/resume answers with a
//     JSON-RPC error (a lost session).
//   - PAGNET_FAKE_CODEX_RESUME_REBASE=1: thread/resume answers with a
//     DIFFERENT thread id (a re-based resume — a lost session).
//   - PAGNET_FAKE_CODEX_TURN_START_FAIL=1: turn/start answers with a
//     JSON-RPC error (the server rejected the turn; the endpoint stays
//     alive).
//   - PAGNET_FAKE_CODEX_CRASH_BEFORE_ACCEPT=1: die before answering
//     turn/start (a death with no acceptance — ErrEndpointGone).
//   - PAGNET_FAKE_CODEX_CRASH_AFTER_ACCEPT=1: answer turn/start and emit
//     turn/started, then die with no terminal event (a death AFTER
//     acceptance — ErrTurnInterrupted).
//   - PAGNET_FAKE_CODEX_CRASH_MARKER=<path>: with a crash knob set, the
//     crash happens ONCE — the marker file is written at the crash, and a
//     process that finds the marker already present does not crash (the
//     re-activated endpoint services the retry normally).
//   - PAGNET_FAKE_CODEX_INTERACTION=<method>: mid-turn, emit a server
//     request with that method and block the turn until the client
//     answers (the native-interaction fixture).
//   - PAGNET_FAKE_CODEX_DELTA=<text>: the agent-message delta text
//     (default: "fake codex reply: <input>").
//   - PAGNET_FAKE_CODEX_ITEM=commandExecution|fileChange|mcpToolCall:
//     emit item/started + item/completed for that item type.
//   - PAGNET_FAKE_CODEX_TOKENS=<in>,<out>,<cached>: emit
//     thread/tokenUsage/updated with that per-turn ("last") breakdown.
//   - PAGNET_FAKE_CODEX_TURN_STATUS=completed|failed|interrupted: the
//     terminal turn status (default: completed).
//   - PAGNET_FAKE_CODEX_TURN_ERROR=<raw json>: the turn.error object when
//     TURN_STATUS=failed (default: a plain message).

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type codexRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *codexRPCError  `json:"error,omitempty"`
}

type codexRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func codexWrite(v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintln(os.Stdout, string(b))
}

func codexRespond(id json.RawMessage, result any) {
	b, _ := json.Marshal(result)
	codexWrite(codexRPCMessage{JSONRPC: "2.0", ID: id, Result: b})
}

func codexRespondError(id json.RawMessage, code int, msg string) {
	codexWrite(codexRPCMessage{JSONRPC: "2.0", ID: id, Error: &codexRPCError{Code: code, Message: msg}})
}

func codexNotify(method string, params any) {
	b, _ := json.Marshal(params)
	codexWrite(codexRPCMessage{JSONRPC: "2.0", Method: method, Params: b})
}

// codexTurnScript is the in-flight turn's remaining script (the
// notifications after the turn/start response). When the turn blocks on a
// scripted interaction, the script is parked (awaiting) until the client's
// response arrives; then finishCodexTurnScript emits the rest.
type codexTurnScript struct {
	threadID string
	turnID   string
	input    string
	awaiting bool
}

func runCodexAppServer() {
	// Observation points: the argv (the -c MCP overrides the driver
	// computed) and the request-method sequence (thread/start vs
	// thread/resume, the turn count).
	if f := os.Getenv("PAGNET_FAKE_CODEX_ARGV_FILE"); f != "" {
		if b, err := json.Marshal(os.Args); err == nil {
			os.WriteFile(f, b, 0o600)
		}
	}
	methodsFile := os.Getenv("PAGNET_FAKE_CODEX_METHODS_FILE")
	recordMethod := func(m string) {
		if methodsFile == "" {
			return
		}
		f, err := os.OpenFile(methodsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		fmt.Fprintln(f, m)
		f.Close()
	}

	threadID := os.Getenv("PAGNET_FAKE_CODEX_THREAD_ID")
	if threadID == "" {
		threadID = "01900000-0000-7000-8000-000000000001"
	}
	standingFile := os.Getenv("PAGNET_FAKE_CODEX_STANDING_FILE")
	turnInputFile := os.Getenv("PAGNET_FAKE_CODEX_TURN_INPUT_FILE")
	responseFile := os.Getenv("PAGNET_FAKE_CODEX_RESPONSE_FILE")

	nextServerReqID := 100
	nextTurnNum := 0

	// crashOnce makes a crash knob fire exactly ONCE across re-activated
	// process instances (the marker file is the cross-process memory —
	// the same pattern as --persistent mode's PAGNET_FAKE_DIE_MID_TURN).
	crashMarker := os.Getenv("PAGNET_FAKE_CODEX_CRASH_MARKER")
	crashOnce := func() bool {
		if crashMarker == "" {
			return true
		}
		if _, err := os.Stat(crashMarker); err == nil {
			return false
		}
		os.WriteFile(crashMarker, []byte("1"), 0o600)
		return true
	}

	var turn *codexTurnScript

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var msg codexRPCMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		if msg.Method == "" {
			// A client RESPONSE (an interaction resolution): record it
			// and resume the parked turn script.
			if responseFile != "" {
				os.WriteFile(responseFile, []byte(line), 0o600)
			}
			if turn != nil && turn.awaiting {
				turn.awaiting = false
				finishCodexTurnScript(turn)
				turn = nil
			}
			continue
		}
		recordMethod(msg.Method)
		switch msg.Method {
		case "initialize":
			if os.Getenv("PAGNET_FAKE_CODEX_NOISE") == "1" {
				// Unrelated noise BEFORE the response: the client must
				// correlate by id, not by arrival order.
				codexNotify("turn/started", map[string]any{
					"threadId": threadID,
					"turn":     map[string]any{"id": "noise-turn", "status": "inProgress"},
				})
			}
			if os.Getenv("PAGNET_FAKE_CODEX_NO_INITIALIZE_RESPONSE") == "1" {
				// Never answer: the client's handshake must time out
				// (a clean launch error, not a hang). Block until killed.
				select {}
			}
			codexRespond(msg.ID, map[string]any{
				"serverInfo": map[string]any{"name": "fake-codex", "version": "0.0.0"},
			})
		case "thread/start":
			var p struct {
				CWD                   string `json:"cwd"`
				DeveloperInstructions string `json:"developerInstructions"`
				Model                 string `json:"model"`
			}
			_ = json.Unmarshal(msg.Params, &p)
			if standingFile != "" {
				os.WriteFile(standingFile, []byte(p.DeveloperInstructions), 0o600)
			}
			switch {
			case os.Getenv("PAGNET_FAKE_CODEX_THREAD_START_FAIL") == "1":
				codexRespondError(msg.ID, -32000, "fake: thread/start refused")
			case os.Getenv("PAGNET_FAKE_CODEX_THREAD_START_EMPTY") == "1":
				codexRespond(msg.ID, map[string]any{})
			default:
				model := p.Model
				if model == "" {
					model = "fake-codex-model"
				}
				codexRespond(msg.ID, map[string]any{
					"thread": map[string]any{"id": threadID, "model": model},
				})
			}
		case "thread/resume":
			var p struct {
				ThreadID              string `json:"threadId"`
				DeveloperInstructions string `json:"developerInstructions"`
			}
			_ = json.Unmarshal(msg.Params, &p)
			if standingFile != "" {
				os.WriteFile(standingFile, []byte(p.DeveloperInstructions), 0o600)
			}
			switch {
			case os.Getenv("PAGNET_FAKE_CODEX_RESUME_FAIL") == "1":
				codexRespondError(msg.ID, -32000, "fake: thread/resume refused")
			case os.Getenv("PAGNET_FAKE_CODEX_RESUME_REBASE") == "1":
				codexRespond(msg.ID, map[string]any{
					"thread": map[string]any{"id": threadID + "-rebased", "model": "fake-codex-model"},
				})
			default:
				codexRespond(msg.ID, map[string]any{
					"thread": map[string]any{"id": p.ThreadID, "model": "fake-codex-model"},
				})
			}
		case "turn/start":
			if os.Getenv("PAGNET_FAKE_CODEX_CRASH_BEFORE_ACCEPT") == "1" && crashOnce() {
				// Die BEFORE answering: no acceptance signal was emitted.
				os.Exit(1)
			}
			var p struct {
				ThreadID string `json:"threadId"`
				Input    []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"input"`
			}
			_ = json.Unmarshal(msg.Params, &p)
			if turnInputFile != "" {
				var texts []string
				for _, in := range p.Input {
					texts = append(texts, in.Text)
				}
				os.WriteFile(turnInputFile, []byte(strings.Join(texts, "\n")), 0o600)
			}
			if os.Getenv("PAGNET_FAKE_CODEX_TURN_START_FAIL") == "1" {
				codexRespondError(msg.ID, -32000, "fake: turn/start refused")
				continue
			}
			nextTurnNum++
			turnID := "turn-" + strconv.Itoa(nextTurnNum)
			codexRespond(msg.ID, map[string]any{
				"turn": map[string]any{"id": turnID, "status": "inProgress"},
			})
			if os.Getenv("PAGNET_FAKE_CODEX_NOISE") == "1" {
				// Unrelated noise between the response and the turn
				// events (correlation fixture, second half): an event for
				// a DIFFERENT thread (the app-server can host several) —
				// the driver must attribute events by thread, not just
				// dispatch by method.
				codexNotify("turn/started", map[string]any{
					"threadId": "01900000-0000-7000-8000-0000000000ff",
					"turn":     map[string]any{"id": "noise-turn", "status": "inProgress"},
				})
			}
			codexNotify("turn/started", map[string]any{
				"threadId": threadID,
				"turn":     map[string]any{"id": turnID, "status": "inProgress"},
			})
			if os.Getenv("PAGNET_FAKE_CODEX_CRASH_AFTER_ACCEPT") == "1" && crashOnce() {
				// The acceptance signal (response + turn/started) is out;
				// die with NO terminal event (the crash-after-accept
				// fixture: the turn must settle as interrupted).
				os.Exit(1)
			}
			script := &codexTurnScript{
				threadID: threadID,
				turnID:   turnID,
				input:    strings.Join(codexInputTexts(p.Input), " "),
			}
			if method := os.Getenv("PAGNET_FAKE_CODEX_INTERACTION"); method != "" {
				// Park the turn on a scripted native interaction: emit
				// the server request and wait for the client's response.
				script.awaiting = true
				nextServerReqID++
				codexWrite(codexRPCMessage{
					JSONRPC: "2.0",
					ID:      json.RawMessage(strconv.Itoa(nextServerReqID)),
					Method:  method,
					Params:  codexInteractionParams(method),
				})
				turn = script
				continue
			}
			finishCodexTurnScript(script)
		}
	}
}

func codexInputTexts(in []struct {
	Type string `json:"type"`
	Text string `json:"text"`
}) []string {
	var out []string
	for _, i := range in {
		out = append(out, i.Text)
	}
	return out
}

// codexInteractionParams builds the server-request params for the scripted
// interaction method (the shape the driver's classifier reads).
func codexInteractionParams(method string) json.RawMessage {
	switch method {
	case "item/commandExecution/requestApproval":
		return json.RawMessage(`{"item":{"id":"item-cmd","type":"commandExecution","command":"ls -la"}}`)
	case "item/fileChange/requestApproval":
		return json.RawMessage(`{"item":{"id":"item-fc","type":"fileChange"}}`)
	case "item/permissions/requestApproval":
		return json.RawMessage(`{"reason":"needs network access"}`)
	case "item/tool/requestUserInput":
		return json.RawMessage(`{"questions":[{"id":"q1","text":"Which option should I use?"}]}`)
	case "mcpServer/elicitation/request", "openai/form":
		return json.RawMessage(`{"serverName":"pagnet"}`)
	default:
		return json.RawMessage(`{}`)
	}
}

// finishCodexTurnScript emits the rest of the turn: the agent-message
// delta, the scripted item lifecycle, the per-turn token usage, and the
// terminal turn/completed (the status is scripted).
func finishCodexTurnScript(s *codexTurnScript) {
	delta := os.Getenv("PAGNET_FAKE_CODEX_DELTA")
	if delta == "" {
		delta = "fake codex reply: " + firstLine(s.input)
	}
	codexNotify("item/agentMessage/delta", map[string]any{
		"threadId": s.threadID,
		"turnId":   s.turnID,
		"itemId":   "item-msg",
		"delta":    delta,
	})
	if item := os.Getenv("PAGNET_FAKE_CODEX_ITEM"); item != "" {
		it := codexItemPayload(item)
		codexNotify("item/started", map[string]any{"threadId": s.threadID, "turnId": s.turnID, "item": it})
		codexNotify("item/completed", map[string]any{"threadId": s.threadID, "turnId": s.turnID, "item": it})
	}
	if t := os.Getenv("PAGNET_FAKE_CODEX_TOKENS"); t != "" {
		var in, out, cached int64
		_, _ = fmt.Sscanf(t, "%d,%d,%d", &in, &out, &cached)
		last := map[string]any{
			"inputTokens":           in,
			"outputTokens":          out,
			"cachedInputTokens":     cached,
			"reasoningOutputTokens": 0,
			"totalTokens":           in + out,
		}
		codexNotify("thread/tokenUsage/updated", map[string]any{
			"threadId":   s.threadID,
			"turnId":     s.turnID,
			"tokenUsage": map[string]any{"last": last, "total": last},
		})
	}
	status := os.Getenv("PAGNET_FAKE_CODEX_TURN_STATUS")
	if status == "" {
		status = "completed"
	}
	turnObj := map[string]any{"id": s.turnID, "status": status}
	if status == "failed" {
		errJSON := os.Getenv("PAGNET_FAKE_CODEX_TURN_ERROR")
		if errJSON == "" {
			errJSON = `{"message":"fake turn failure"}`
		}
		turnObj["error"] = json.RawMessage(errJSON)
	}
	codexNotify("turn/completed", map[string]any{"threadId": s.threadID, "turn": turnObj})
}

// codexItemPayload builds the ThreadItem for the scripted item type.
func codexItemPayload(itemType string) map[string]any {
	switch itemType {
	case "commandExecution":
		return map[string]any{
			"id": "item-cmd", "type": "commandExecution",
			"command": "ls -la", "status": "completed", "exitCode": 0,
		}
	case "fileChange":
		return map[string]any{
			"id": "item-fc", "type": "fileChange", "status": "completed",
		}
	case "mcpToolCall":
		return map[string]any{
			"id": "item-mcp", "type": "mcpToolCall",
			"server": "pagnet", "tool": "whoami", "status": "completed",
		}
	default:
		return map[string]any{"id": "item-x", "type": itemType, "status": "completed"}
	}
}
