//go:build linux

// PTY-owning endpoint tests (Phase 3 terminal session unification, D1):
// a ClassEndpoint launched WITH a PTYSize OWNS its TUI PTY — the PTY
// slave is its CONTROLLING terminal (the human plane) while the
// stdin/stdout pipes remain the machine plane. The tests prove the
// topology on process facts (Linux: /proc):
//
//   - the child's /dev/tty IS the PTY slave (a marker written to
//     /dev/tty arrives at the master);
//   - the machine pipe is NOT the tty (a line written to the stdin pipe
//     is seen by the child on fd 0 and echoed to /dev/tty → the master);
//   - the child is its own session AND group leader (sid == pid,
//     pgid == pid) — the group-kill math (pgid == leader pid) holds;
//   - Stop of a PTY endpoint reclaims the whole process group (TERM →
//     grace → KILL), including slave-holding descendants;
//   - EndpointCount reflects the live PTY endpoint;
//   - ClassEndpoint WITHOUT a PTYSize keeps the pre-Phase-3 shape
//     (group-isolated, no PTY, no controlling terminal, same session
//     as the parent).

package proc

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

// selfSessionID is the calling process's session id (from
// /proc/self/stat).
func selfSessionID() (int, error) {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 || i+2 >= len(b) {
		return 0, fmt.Errorf("unparseable /proc/self/stat")
	}
	f := strings.Fields(string(b)[i+2:])
	if len(f) < 4 {
		return 0, fmt.Errorf("short /proc/self/stat")
	}
	return strconv.Atoi(f[3])
}

// procSessionGroup reads the child's session id (stat field 6) and
// process group (stat field 5) from /proc/<pid>/stat.
func procSessionGroup(t *testing.T, pid int) (sid, pgid int) {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatalf("read /proc/%d/stat: %v", pid, err)
	}
	s := string(b)
	// comm (field 2) is parenthesized and may contain spaces: parse
	// after the LAST ')'.
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		t.Fatalf("unparseable /proc stat: %q", s)
	}
	// After ')': field 3 (state), field 4 (ppid), field 5 (pgrp),
	// field 6 (session).
	f := strings.Fields(s[i+2:])
	if len(f) < 4 {
		t.Fatalf("short /proc stat: %q", s)
	}
	pgid, err1 := strconv.Atoi(f[2])
	sid, err2 := strconv.Atoi(f[3])
	if err1 != nil || err2 != nil {
		t.Fatalf("parse /proc stat fields: %v / %v", err1, err2)
	}
	return sid, pgid
}

// readMasterLine reads one line from the PTY master (10s deadline).
func readMasterLine(t *testing.T, master *os.File) string {
	t.Helper()
	_ = master.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReaderSize(master, 4096).ReadString('\n')
	if err != nil {
		t.Fatalf("read master: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// TestEndpointPTYOwnsControllingTerminal: a ClassEndpoint launched with a
// PTYSize owns its TUI PTY. The fixture writes a marker to /dev/tty (the
// controlling terminal), reads one line from fd 0 (the MACHINE pipe) and
// echoes it to /dev/tty, then stays alive.
func TestEndpointPTYOwnsControllingTerminal(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second, MonitorInterval: time.Hour})
	ctx := context.Background()
	cmd := exec.Command("sh", "-c", `
		echo tty-marker > /dev/tty
		read -r line
		echo "machine:$line" > /dev/tty
		sleep 3600
	`)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	h, err := s.Launch(ctx, LaunchRequest{
		InstanceID: "ep-pty", TurnID: "endpoint", Runtime: "test",
		Class: ClassEndpoint, Cmd: cmd,
		PTYSize: &pty.Winsize{Rows: 24, Cols: 80},
	})
	if err != nil {
		t.Fatalf("launch PTY endpoint: %v", err)
	}
	pid := waitForPID(t, h)

	// One handle, one registry entry (G2): the master is exposed on the
	// endpoint handle.
	master := h.PTY()
	if master == nil {
		t.Fatal("PTY master is nil on a PTY-owning endpoint handle")
	}
	if n := s.EndpointCount(); n != 1 {
		t.Fatalf("EndpointCount = %d, want 1", n)
	}

	// The child is its own session AND group leader: the group-kill math
	// (pgid == leader pid) holds for the TERM → grace → KILL sequence.
	sid, pgid := procSessionGroup(t, pid)
	if sid != pid {
		t.Fatalf("child sid %d != pid %d (Setsid failed)", sid, pid)
	}
	if pgid != pid {
		t.Fatalf("child pgid %d != pid %d (the group-kill math breaks)", pgid, pid)
	}
	if h.PGID() != pid {
		t.Fatalf("handle pgid %d != pid %d", h.PGID(), pid)
	}

	// The marker written to /dev/tty arrives at the master: the PTY slave
	// IS the child's controlling terminal (the human plane).
	if got := readMasterLine(t, master); got != "tty-marker" {
		t.Fatalf("first master line = %q, want tty-marker (/dev/tty must be the PTY slave)", got)
	}

	// The machine pipe is NOT the tty: a line on the stdin pipe is seen by
	// the child on fd 0 and echoed to /dev/tty (→ the master).
	if _, err := stdin.Write([]byte("hello-machine\n")); err != nil {
		t.Fatalf("stdin pipe write: %v", err)
	}
	if got := readMasterLine(t, master); got != "machine:hello-machine" {
		t.Fatalf("machine-pipe echo = %q, want machine:hello-machine (fd 0 must be the pipe, the tty the slave)", got)
	}

	terminateAndReap(t, h)
	waitGroupGone(t, pid)
	if n := s.EndpointCount(); n != 0 {
		t.Fatalf("EndpointCount after reap = %d, want 0", n)
	}
}

// TestEndpointPTYStopReclaimsGroup: Stop of a PTY endpoint reclaims the
// WHOLE process group — including a slave-holding descendant (a real TUI's
// helper processes inherit the slave fd and the controlling terminal).
func TestEndpointPTYStopReclaimsGroup(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second, MonitorInterval: time.Hour})
	ctx := context.Background()
	cmd := exec.Command("sh", "-c", "sleep 3600 & sleep 3600")
	h, err := s.Launch(ctx, LaunchRequest{
		InstanceID: "ep-pty-stop", TurnID: "endpoint", Runtime: "test",
		Class: ClassEndpoint, Cmd: cmd,
		PTYSize: &pty.Winsize{Rows: 24, Cols: 80},
	})
	if err != nil {
		t.Fatalf("launch PTY endpoint: %v", err)
	}
	pid := waitForPID(t, h)
	// Wait for the two descendants (sh + 2 sleeps = 3 group members).
	waitForGroupCount(t, pid, 3)

	reaped := make(chan struct{})
	go func() { _ = h.Wait(); close(reaped) }()
	s.StopEndpoint("ep-pty-stop")
	select {
	case <-reaped:
	case <-time.After(15 * time.Second):
		t.Fatal("endpoint never reaped after StopEndpoint")
	}
	waitGroupGone(t, pid)
}

// TestEndpointWithoutPTYUnchanged: a ClassEndpoint launched WITHOUT a
// PTYSize keeps the pre-Phase-3 shape — group-isolated (Setpgid), no PTY,
// no controlling terminal, and the child stays in the PARENT's session
// (no Setsid).
func TestEndpointWithoutPTYUnchanged(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second, MonitorInterval: time.Hour})
	ctx := context.Background()
	outFile := filepath.Join(t.TempDir(), "tty")
	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		`if (exec 3>/dev/tty) 2>/dev/null; then echo has-tty > %s; else echo no-tty > %s; fi; sleep 3600`,
		outFile, outFile))
	h, err := s.Launch(ctx, LaunchRequest{
		InstanceID: "ep-nopTY", TurnID: "endpoint", Runtime: "test",
		Class: ClassEndpoint, Cmd: cmd,
	})
	if err != nil {
		t.Fatalf("launch PTY-less endpoint: %v", err)
	}
	pid := waitForPID(t, h)

	if h.PTY() != nil {
		t.Fatal("PTY master set on a PTY-less endpoint")
	}
	// Group leader (Setpgid), as today.
	if h.PGID() != pid {
		t.Fatalf("handle pgid %d != pid %d (Setpgid shape changed)", h.PGID(), pid)
	}
	// Same session as the parent (no Setsid): the distinguishing fact
	// against the PTY-owning shape.
	sid, _ := procSessionGroup(t, pid)
	parentSID, err := selfSessionID()
	if err != nil {
		t.Fatalf("read own session id: %v", err)
	}
	if sid != parentSID {
		t.Fatalf("PTY-less endpoint sid %d != parent sid %d (the pre-Phase-3 shape must not Setsid)", sid, parentSID)
	}

	// The child stays in the PARENT's session, so its /dev/tty must
	// resolve exactly as the test process's own /dev/tty does
	// (environment-dependent: a daemon without a controlling terminal
	// gives its endpoints none; a test run from a terminal inherits
	// one). The supervisor must not change that either way.
	want := "no-tty"
	if probe, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0); err == nil {
		_ = probe.Close()
		want = "has-tty"
	}
	deadline := time.Now().Add(10 * time.Second)
	var content []byte
	for {
		content, err = os.ReadFile(outFile)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tty probe never wrote %s: %v", outFile, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := strings.TrimSpace(string(content)); got != want {
		t.Fatalf("tty probe = %q, want %s (a PTY-less endpoint must keep the parent session's tty state)", got, want)
	}

	terminateAndReap(t, h)
	waitGroupGone(t, pid)
}
