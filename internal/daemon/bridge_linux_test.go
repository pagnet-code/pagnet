//go:build linux

package daemon

// Linux process-tree binding tests (security wave S1).
//
// These cover the SO_PEERCRED + /proc tree binding that is enforced on Linux
// after the portable nonce/kind/network/status/live-process checks. The
// parseProcStat / processTreeReaches unit tests are deterministic and
// platform-pure; the tree-rejection test proves an UNRELATED same-UID process
// (the test process itself) is refused even with a valid nonce.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	if err := processTreeReaches(self, self); err != nil {
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
	if err := processTreeReaches(self, cmd.Process.Pid); err == nil {
		t.Fatal("the walk must not reach a non-ancestor (a child process)")
	}
}

// TestBridgeTreeRejectsUnrelatedProcess: the portable checks can all pass
// (valid nonce, matching kind, idle status, a live endpoint root) and the
// connection is STILL refused on Linux when the connecting process is not the
// instance's own process tree. The test process — same UID as the daemon, but
// unrelated to the endpoint and older than it — dials the socket with the
// endpoint's real nonce and is rejected by the SO_PEERCRED/proc verification
// (here, the pid-reuse/start-time discriminator: an unrelated same-UID process
// cannot postdate the root it would falsely join).
func TestBridgeTreeRejectsUnrelatedProcess(t *testing.T) {
	d, _ := newBridgeE2EDaemon(t)

	instanceID := launchFakeEndpoint(t, d, "worker")
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance not found: ok=%v err=%v", ok, err)
	}
	nonce := d.currentBridgeNonce(instanceID)
	if nonce == "" {
		t.Fatal("no nonce minted for the live endpoint")
	}

	// A raw dial from the test process (unrelated to the endpoint, same UID):
	// the portable checks pass, but the Linux tree binding refuses it.
	c := bridgeDial(t, filepath.Join(d.StateDir, bridgeSocketName))
	resp := c.authFull(t, instanceID, row.NetworkID, nonce, "worker")
	msg, _ := resp["error"].(string)
	assertBridgeError(t, resp, "peer process verification failed")
	if !strings.Contains(msg, "identity rejected") {
		t.Fatalf("error = %q, want the identity-rejected peer verification message", msg)
	}
	t.Logf("unrelated same-UID process refused: %s", msg)
}
