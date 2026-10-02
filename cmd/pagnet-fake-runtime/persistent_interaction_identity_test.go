package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPersistentPermissionsHaveDistinctOriginalWorkerTurnIDs(t *testing.T) {
	if os.Getenv("PAGNET_FAKE_PERMISSION_ID_CHILD") == "1" {
		runPersistent("native-permission-identity", os.Getenv("PAGNET_FAKE_PERMISSION_ID_DIR"), "")
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPersistentPermissionsHaveDistinctOriginalWorkerTurnIDs$")
	cmd.Env = append(os.Environ(), "PAGNET_FAKE_PERMISSION_ID_CHILD=1", "PAGNET_FAKE_PERMISSION_ID_DIR="+t.TempDir(), "PAGNET_FAKE_INTERACTION=permission", `PAGNET_FAKE_INTERACTION_OPTIONS=[{"id":"deny","kind":"reject_once"}]`)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		input.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	events := make(chan persistEvent, 32)
	go func() {
		defer close(events)
		scan := bufio.NewScanner(output)
		for scan.Scan() {
			var e persistEvent
			if json.Unmarshal(scan.Bytes(), &e) == nil {
				events <- e
			}
		}
	}()
	next := func(kind string) persistEvent {
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case e, ok := <-events:
				if !ok {
					t.Fatal("original native process exited")
				}
				if e.Event == kind {
					return e
				}
			case <-deadline.C:
				t.Fatalf("missing genuine native %s", kind)
			}
		}
	}
	send := func(c persistCmd) {
		raw, _ := json.Marshal(c)
		if _, err := input.Write(append(raw, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	started := next("runtime.session.started")
	originalPID := cmd.Process.Pid
	var previous string
	for _, turn := range []string{"pagnet-worker-turn-2", "pagnet-worker-turn-19"} {
		send(persistCmd{Type: "submit", TurnID: turn, InputKind: "channel", Input: "synthetic original native channel"})
		native := next("runtime.interaction.started")
		if native.SessionID != started.SessionID || native.TurnID != turn || native.NativeInteractionID == "" || cmd.Process.Pid != originalPID {
			t.Fatal("native permission changed original process/session/turn")
		}
		if native.NativeInteractionID == previous {
			t.Fatal("distinct original worker turns reused native permission identity")
		}
		previous = native.NativeInteractionID
		send(persistCmd{Type: "interaction", TurnID: turn, InteractionID: native.NativeInteractionID, Decision: "declined"})
		next("runtime.turn.completed")
	}
}
