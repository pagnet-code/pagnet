//go:build linux || darwin

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

func TestQwenManagerChoicePreservesAllowRejectAndRefusesUnknown(t *testing.T) {
	for _, option := range []string{"allow_once", "reject_once", "invented-choice", ""} {
		t.Run(option, func(t *testing.T) {
			q, workspace, _, argsPath, env := newQwenPersistentFixture(t, false)
			manager := session.NewManager()
			manager.RegisterDriver(q)
			sess := manager.Session("choice-instance", domain.RuntimeQwenCode, workspace)
			manager.SetLaunchEnv(sess, append(env, "QWEN_FAKE_ECHO_SUBMIT=1"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			events := make(chan session.SessionEvent, 32)
			done := make(chan error, 1)
			go func() {
				_, err := manager.Submit(ctx, sess, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: "choice-turn", Input: "observe permission"}, events)
				done <- err
			}()
			deadline := time.NewTimer(8 * time.Second)
			defer deadline.Stop()
			for {
				select {
				case event := <-events:
					if event.Type == session.EventTurnStarted {
						goto accepted
					}
				case <-deadline.C:
					t.Fatal("native turn not accepted")
				}
			}
		accepted:
			t.Cleanup(func() {
				cancel()
				q.Stop(sess.InstanceID)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("native turn failed to stop")
				}
			})
			argv := readArgv(t, argsPath)
			f, err := os.OpenFile(qwenArgAfter(argv, "--json-file"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			line := controlRequestLine(t, sess.NativeID, "actual-choice", "bash")
			_, err = f.Write(append([]byte(line), '\n'))
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
			for !manager.HasPendingInteraction(sess.InstanceID) {
				select {
				case <-events:
				case <-deadline.C:
					t.Fatal("native permission not observed")
				}
			}
			before, err := os.ReadFile(qwenArgAfter(argv, "--input-file"))
			if err != nil {
				t.Fatal(err)
			}
			err = manager.ResolvePendingInteraction(context.Background(), sess.InstanceID, sess.NativeID, "actual-choice", option)
			after, readErr := os.ReadFile(qwenArgAfter(argv, "--input-file"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if option != "allow_once" && option != "reject_once" {
				if err == nil || !bytes.Equal(before, after) {
					t.Fatal("unknown option reached native confirmation")
				}
				if !manager.HasPendingInteraction(sess.InstanceID) || !q.Live(sess.InstanceID) {
					t.Fatal("unknown choice disturbed pending native turn")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var confirmation qwenInputCmd
			for _, line := range bytes.Split(after, []byte{'\n'}) {
				var cmd qwenInputCmd
				if json.Unmarshal(line, &cmd) == nil && cmd.Type == "confirmation_response" {
					confirmation = cmd
				}
			}
			if confirmation.RequestID != "actual-choice" || confirmation.Allowed == nil || *confirmation.Allowed != (option == "allow_once") {
				t.Fatalf("wrong actual native confirmation for %s: %+v", option, confirmation)
			}
		})
	}
}

func TestQwenNativePermissionOptionsAndBoundedLabel(t *testing.T) {
	state, _ := newFixtureState(false, "")
	feedLines(t, state, validHandshakeLine(t, fixtureSID, fixtureCWD))
	state.beginMachineTurn("turn", "hello")
	feedLines(t, state, userTextLine(t, fixtureSID, "hello"))
	name := string(bytes.Repeat([]byte("long-tool<&>"), 100000))
	line := controlRequestLine(t, fixtureSID, "bounded-label", name)
	events := feedLines(t, state, line)
	if len(events) != 1 || events[0].Interaction == nil {
		t.Fatal("native permission missing")
	}
	interaction := events[0].Interaction
	if !domain.ValidRuntimeInteractionOptions(interaction.Options) || len(interaction.Options) != 2 || interaction.Options[0].ID != "allow_once" || interaction.Options[1].ID != "reject_once" {
		t.Fatal("observed native options are missing or incorrect")
	}
	if len(interaction.Summary) > 600 {
		t.Fatal("derived label duplicates huge original request")
	}
	var request qwenDOControlRequest
	if json.Unmarshal(interaction.NativePayload, &request) != nil || request.ToolName != name {
		t.Fatal("bounded label truncated actual native request")
	}
	if len(qwenPermissionOptions("question")) != 0 {
		t.Fatal("human-only question gained a fabricated permission choice")
	}
}

func TestQwenNativeChoiceRefusesWrongDecisionQuestionOrStaleRequest(t *testing.T) {
	q, workspace, _, argsPath, env := newQwenPersistentFixture(t, false)
	sess := &session.RuntimeSession{InstanceID: "negative-choice", Runtime: domain.RuntimeQwenCode, Workspace: workspace, Env: env}
	if _, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 16)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Stop(sess.InstanceID) })
	q.mu.Lock()
	endpoint := q.endpoints[sess.InstanceID]
	q.mu.Unlock()
	endpoint.state.mu.Lock()
	endpoint.state.interactions["permission"] = &qwenInteraction{kind: "permission"}
	endpoint.state.interactions["question"] = &qwenInteraction{kind: "question"}
	endpoint.state.mu.Unlock()
	input := qwenArgAfter(readArgv(t, argsPath), "--input-file")
	before, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []session.SubmitRequest{
		{InteractionID: "permission", Decision: "cancelled", Answer: "allow_once"},
		{InteractionID: "permission", Decision: "declined", Answer: "allow_once"},
		{InteractionID: "permission", Decision: "resolved", Answer: "reject_once"},
		{InteractionID: "permission", Decision: "resolved", Answer: ""},
		{InteractionID: "question", Decision: "resolved", Answer: "allow_once"},
		{InteractionID: "already-resolved", Decision: "resolved", Answer: "allow_once"},
	} {
		req.Kind = session.SubmitInteraction
		if err = q.Submit(context.Background(), sess, req, nil); err == nil {
			t.Fatalf("invalid choice reached native endpoint: %+v", req)
		}
		after, err := os.ReadFile(input)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refused choice wrote a native confirmation")
		}
	}
}
