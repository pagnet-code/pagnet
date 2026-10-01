//go:build linux

package localpeer

import (
	"os"
	"os/exec"
	"testing"
)

// TestParseProcStat: /proc/<pid>/stat parsing, including a comm field with
// spaces and parentheses (the field split must start after the LAST ')').
func TestParseProcStat(t *testing.T) {
	// pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt
	// majflt cmajflt utime stime cutime cstime priority nice itrealvalue
	// starttime ...
	// After the last ')': fields[1]=ppid, fields[19]=starttime (field 22).
	line := "1234 (my (proc)) S 999 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 424242 1234567 100"
	st, err := parseProcStat([]byte(line))
	if err != nil {
		t.Fatalf("parseProcStat: %v", err)
	}
	if st.pid != 1234 {
		t.Errorf("pid = %d, want 1234", st.pid)
	}
	if st.ppid != 999 {
		t.Errorf("ppid = %d, want 999", st.ppid)
	}
	if st.starttime != 424242 {
		t.Errorf("starttime = %d, want 424242", st.starttime)
	}

	// A comm with no closing paren is malformed.
	if _, err := parseProcStat([]byte("1234 (broken S 999")); err == nil {
		t.Fatal("parseProcStat on a line without a comm close must fail")
	}
	// Too few fields after the close is malformed.
	if _, err := parseProcStat([]byte("1234 (x) S 999 1 2 3")); err == nil {
		t.Fatal("parseProcStat on a too-short line must fail")
	}
}

// TestProcessTreeReaches: the /proc ppid walk. A process always reaches
// itself (0 hops); it does NOT reach an unrelated process (a child, which is
// below it — the walk only goes UP toward init).
func TestProcessTreeReaches(t *testing.T) {
	self := os.Getpid()
	if err := VerifyProcessTree(self, self, uint32(os.Getuid()), ReadProcess); err != nil {
		t.Fatalf("a process must reach itself (0 hops): %v", err)
	}

	// A freshly spawned child is NOT an ancestor of the test process: the
	// walk from the test process goes up to init and never reaches it.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot spawn a child for the tree test: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	if err := VerifyProcessTree(self, cmd.Process.Pid, uint32(os.Getuid()), ReadProcess); err == nil {
		t.Fatal("the walk must not reach a non-ancestor (a child process)")
	}
}
