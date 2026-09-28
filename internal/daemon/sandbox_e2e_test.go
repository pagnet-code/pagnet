//go:build linux

// Daemon-level sandbox test (security wave S2, the negative test).
//
// A REAL fake-persistent endpoint is launched through the daemon's real
// supervisor (which now REQUIRES the sandbox: procConfigFromDaemon sets
// RequireSandbox=true and the wrapper is the daemon's own executable —
// this test binary, intercepted in TestMain). The endpoint is sandboxed
// by the driver's per-instance spec: its own session dir + scratch + the
// bridge socket's traversal chain + the test-scoped result-file dir. The
// daemon's OWN state dir (planted with the exact secrets the P0 finding
// names: accounts/<name>/config.yaml, e2ee/host.json, daemon.sqlite) is
// NOT in the allowlist.
//
// The test asserts, on the SAME endpoint:
//  1. NEGATIVE: a scripted secret-read (PAGNET_FAKE_FS_PROBE) is DENIED
//     (EACCES) for every daemon-state secret — the sandboxed runtime
//     cannot read the daemon's credentials/keys/DB.
//  2. S1 INVARIANTS: the same endpoint's in-tree bridge STILL
//     authenticates with the daemon-minted nonce (auth_ok — the
//     SO_PEERCRED process-tree binding sees the wrapped-but-in-place-
//     exec'd endpoint's real PID) and its tool call is relayed
//     end-to-end.
//  3. FUNCTIONAL: a delivered turn COMPLETES on the sandboxed endpoint
//     (the sandbox does not break the runtime's own work).
//  4. The planted secrets are INTACT on disk (the denial is a read
//     denial, not a mutation).

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/sandbox"
	"github.com/pagnet-code/pagnet/transport"
)

func TestSandboxE2E_EndpointCannotReadDaemonState(t *testing.T) {
	if !sandbox.Available() {
		t.Skipf("kernel %s has no Landlock — the fail-closed refusal is the platform behavior (no launch happens to sandbox)", sandbox.KernelRelease())
	}
	d, server := newBridgeE2EDaemon(t)
	startBridgeRelayResponder(t, server)

	// Plant the daemon-state secrets the P0 finding names, in the
	// test-scoped StateDir the real daemon owns (daemon.sqlite is the
	// daemon's ACTUAL database file, created by New).
	accountsCfg := filepath.Join(d.StateDir, "accounts", "x", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(accountsCfg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accountsCfg, []byte("host_credential: pagnet-account-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostJSON := filepath.Join(d.StateDir, "e2ee", "host.json")
	if err := os.MkdirAll(filepath.Dir(hostJSON), 0o700); err != nil {
		t.Fatal(err)
	}
	// The test-scoped StateDir is fresh: planting the host-identity file
	// here cannot clobber a real one (a real daemon's e2ee/host.json is
	// written by crypto.EnsureHostIdentity into ITS state dir — this
	// daemon's EnsureHostIdentity, if it ran, created it in this same
	// fresh dir, and the probe only ever READS).
	if err := os.WriteFile(hostJSON, []byte(`{"privateKey":"host-x25519-secret"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	daemonSQLite := filepath.Join(d.StateDir, "daemon.sqlite")
	// (daemon.sqlite exists — OpenState created it at New.)

	// ONE test-scoped dir for both fixture outputs: the fake driver
	// grants exactly the dir of PAGNET_FAKE_BRIDGE_RESULT_FILE (the
	// documented PAGNET_FAKE_* test knob), so the FS-probe output lives
	// beside it.
	resultDir := t.TempDir()
	probeFile := filepath.Join(resultDir, "fs-probe.json")
	resultFile := filepath.Join(resultDir, "bridge-result.json")

	pf := mustPersistentFake(t, d)
	// The fake binary must live OUTSIDE this test's /tmp root. RuntimeSupportRO
	// grants the binary's dir AND its immediate parent (the coarse node-
	// install grant that makes a `.../bin/<cli>` shebang script executable);
	// newPersistentTestDaemon put the binary in a t.TempDir() sibling of
	// d.StateDir under the shared /tmp/TestXXX/ root, whose PARENT grant
	// would then cover the planted daemon-state secrets below. Production
	// keeps the install dir disjoint from the daemon state dir (H7 layout);
	// this mirrors that — the negative assertion must test the spec, not a
	// test-harness path collision.
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("resolve user cache dir: %v", err)
	}
	t.Setenv("PAGNET_P0_BIN_DIR", filepath.Join(cacheDir, "pagnet-s2-p0"))
	pf.Binary = p0FakeBinary(t)
	pf.Env = append(hostileFixtureEnv(resultFile, "network_whoami", "", false),
		"PAGNET_FAKE_FS_PROBE="+strings.Join([]string{accountsCfg, filepath.Join(d.StateDir, "e2ee", "host.json"), daemonSQLite}, ","),
		"PAGNET_FAKE_FS_PROBE_FILE="+probeFile,
	)

	instanceID := launchFakeEndpoint(t, d, "worker")

	// (1) NEGATIVE: the sandboxed endpoint is denied every daemon-state
	// secret.
	probes := readFSProbe(t, probeFile)
	for _, p := range probes {
		path, _ := p["fs_probe"].(string)
		if p["ok"] == true {
			t.Fatalf("SANDBOX LEAK: the sandboxed endpoint READ %q — the daemon-state secret is exposed", path)
		}
		if e, _ := p["err"].(string); e != "permission denied" {
			t.Errorf("denial for %s = %v, want the Landlock read denial (permission denied / EACCES)", path, p)
		}
	}

	// (2) S1 INVARIANTS UNDER S2: the same endpoint's in-tree bridge
	// authenticates (the process-tree binding reaches the wrapped
	// endpoint's root PID — H1 held) and its tool call is relayed.
	lines := readBridgeResult(t, resultFile)
	assertAuthOK(t, lines, instanceID)
	if len(lines) < 2 {
		t.Fatalf("expected auth + a tool response, got %v", lines)
	}
	if lines[1]["ok"] != true {
		t.Fatalf("network_whoami on the SANDBOXED endpoint = %v, want a successful correlated relay", lines[1])
	}

	// (3) FUNCTIONAL: a delivered turn completes on the sandboxed
	// endpoint (the sandbox bounds the filesystem, not the runtime's
	// own work).
	//
	// The launch-time relay responder is the SOLE reader of the bridge host
	// conn above and would swallow this turn's ack/envelopes (two readers on
	// one websocket race). The bridge fixture is done, so swap the daemon
	// onto a FRESH host conn — the same operation the daemon performs on a
	// control-plane reconnect (d.send always writes to the CURRENT conn) —
	// and drive + read the turn there. The relay responder stays parked on
	// the old conn, blocked and harmless.
	client2, server2 := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client2
	d.connMu.Unlock()

	envs := driveDeliver(t, d, server2, transport.NetworkEventPayload{
		CommandID:  "cmd-sandbox-turn",
		InstanceID: instanceID,
		Kind:       "task",
		Body:       "sandbox functional turn",
	})
	if !hasEnvelopeType(envs, transport.MsgRuntimeTurnCompleted) {
		t.Fatalf("sandboxed fake turn did not complete: %+v", envs)
	}

	// (4) The planted secrets are intact on disk (the denial is a read
	// denial; nothing mutated them).
	if b, err := os.ReadFile(accountsCfg); err != nil || !strings.Contains(string(b), "pagnet-account-secret") {
		t.Fatalf("planted account config not intact after the sandboxed turn: %v %q", err, b)
	}
}

// readFSProbe polls the fixture's FS-probe output until it holds a
// non-empty JSON array, then returns the per-path records.
func readFSProbe(t *testing.T, path string) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil && len(b) > 1 {
			var recs []map[string]any
			if json.Unmarshal(b, &recs) == nil && len(recs) > 0 {
				return recs
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("fs-probe file %s never appeared (the endpoint did not run the scripted probe)", path)
	return nil
}
