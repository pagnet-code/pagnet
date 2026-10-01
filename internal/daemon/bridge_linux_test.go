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
	"path/filepath"
	"strings"
	"testing"
)

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
