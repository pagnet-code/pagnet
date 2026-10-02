//go:build linux

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestPersistentHumanTTYProcess(t *testing.T) {
	if os.Getenv("PAGNET_FAKE_TTY_CHILD") == "1" {
		runPersistent("native-tty-fixture", os.Getenv("PAGNET_FAKE_TTY_DIR"), "")
		os.Exit(0)
	}
	for _, externalStop := range []bool{false, true} {
		name := "human_controls"
		if externalStop {
			name = "stop_while_waiting_input"
		}
		t.Run(name, func(t *testing.T) { runPersistentHumanTTYProcess(t, externalStop) })
	}
}

func runPersistentHumanTTYProcess(t *testing.T, externalStop bool) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPersistentHumanTTYProcess$")
	cmd.Env = append(os.Environ(), "PAGNET_FAKE_TTY_CHILD=1", "PAGNET_FAKE_TTY_DIR="+t.TempDir(), "PAGNET_FAKE_TUI=1")
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 2}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	slave.Close()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	t.Cleanup(func() {
		input.Close()
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-waited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-waited
		}
	})
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() {
		t.Fatal("missing genuine private session event")
	}
	var event map[string]any
	if err = json.Unmarshal(scanner.Bytes(), &event); err != nil || event["event"] != "runtime.session.started" {
		t.Fatalf("private session event: %v", event["event"])
	}
	var mu sync.Mutex
	var terminal strings.Builder
	go func() {
		b := make([]byte, 4096)
		for {
			n, e := master.Read(b)
			if n > 0 {
				mu.Lock()
				terminal.Write(b[:n])
				mu.Unlock()
			}
			if e != nil {
				return
			}
		}
	}()
	wait := func(text string) {
		t.Helper()
		end := time.Now().Add(5 * time.Second)
		for time.Now().Before(end) {
			mu.Lock()
			ok := strings.Contains(terminal.String(), text)
			mu.Unlock()
			if ok {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("native terminal missing %q", text)
	}
	send := func(s string) {
		t.Helper()
		if _, e := master.WriteString(s); e != nil {
			t.Fatal(e)
		}
	}
	wait("fake-agent>")
	if err = pty.Setsize(master, &pty.Winsize{Cols: 120, Rows: 40}); err != nil {
		t.Fatal(err)
	}
	wait("resized to 120x40")
	send("echo same-process\n")
	wait("echo: same-process")
	send("unicode\n")
	wait("unicode: äöü ñçß emoji: 🚀 ✅")
	send("\x1b[A")
	wait("arrow: up")
	send("\x03")
	wait("^C (caught)")
	send("big\n")
	wait("line 0511:")
	if externalStop {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
	} else {
		send("exit\n")
		wait("bye")
	}
	select {
	case e := <-waited:
		if e != nil {
			t.Fatal(e)
		}
		waited <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("original native endpoint did not exit")
	}
}
