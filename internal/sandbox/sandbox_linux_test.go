//go:build linux

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// installApplyFault is the test-only seam: it forces the wrapper's Landlock
// step to fail so the fail-closed contract (H3) can be verified at the
// process level (non-zero exit, explicit security error, child never runs).
// It only ever makes the sandbox STRICTER (refusal), never weaker — there is
// no production path that disables or bypasses the sandbox.
func init() {
	installApplyFault = func() {
		applyLandlockFunc = func(*Spec) error {
			return errors.New("injected apply failure (test)")
		}
	}
}

// skipNoLandlock skips the test on a kernel without Landlock (the product
// itself would FAIL CLOSED there — this is test robustness, not a bypass).
func skipNoLandlock(t *testing.T) {
	t.Helper()
	if !LandlockAvailable() {
		t.Skipf("kernel %s has no Landlock; wrapper behavior cannot be exercised (product fails closed here by design)", kernelRelease())
	}
}

// newProbeDirs lays out the fixture: an RW dir, an RO dir with a file, a
// secret file outside both, an allowed-socket dir, and a denied-socket dir
// (inside the secret tree).
func newProbeDirs(t *testing.T) (rwDir, roDir, secretDir, sockOKDir, sockDenyDir string) {
	t.Helper()
	base := t.TempDir()
	rwDir = filepath.Join(base, "rw")
	roDir = filepath.Join(base, "ro")
	secretDir = filepath.Join(base, "secret")
	sockOKDir = filepath.Join(base, "sockok")
	sockDenyDir = filepath.Join(secretDir, "sock")
	for _, d := range []string{rwDir, roDir, secretDir, sockOKDir, sockDenyDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(roDir, "rofile"), []byte("ro-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "secret.txt"), []byte("top-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

// TestLandlockABI pins the kernel-ABI detection against the live kernel:
// a positive ABI version and a non-zero fs mask. On this host (6.8) the
// version query must succeed via the 3-arg (size, flags) form.
func TestLandlockABI(t *testing.T) {
	a := getABI()
	if a.version == 0 {
		t.Skipf("kernel %s has no Landlock", kernelRelease())
	}
	if a.fsMask == 0 {
		t.Fatalf("ABI v%d: fsMask = 0, want a non-zero access mask", a.version)
	}
	// The bits this sandbox needs must be within the kernel's mask.
	for name, bit := range map[string]uint64{
		"read_file": uint64(bReadFile), "read_dir": uint64(bReadDir),
		"write_file": uint64(bWriteFile), "execute": uint64(bExecute),
	} {
		if bit&a.fsMask != bit {
			t.Errorf("access bit %s (0x%x) not in kernel fs mask 0x%x", name, bit, a.fsMask)
		}
	}
}

// TestComputeRules_MaskIntersection pins the legacy-ABI behavior at the
// rule level: intersecting with an ABI mask can only REMOVE bits (the
// result is more restrictive, never less) and a zeroed grant is refused.
func TestComputeRules_MaskIntersection(t *testing.T) {
	// ABI v1 mask: only read_file/write_file/execute/read_dir.
	rules, accessFs, mandatory, err := computeRules(&Spec{
		RW:  []string{"/tmp/x"},
		RO:  []string{"/tmp/y"},
		Dev: []string{"/dev"},
	}, uint64(bReadFile|bReadDir|bWriteFile|bExecute))
	if err != nil {
		t.Fatalf("computeRules (v1 mask): %v", err)
	}
	// RW grants are mandatory (a missing one refuses the launch); the
	// coarse RO support path is best-effort (a missing one is a no-op
	// skip).
	if !mandatory["/tmp/x"] {
		t.Error("rw grant not marked mandatory")
	}
	if mandatory["/tmp/y"] {
		t.Error("ro grant marked mandatory (best-effort support paths must not be)")
	}
	if mandatory["/dev"] {
		t.Error("dev grant marked mandatory (coarse system support paths are best-effort)")
	}
	if got := rules["/tmp/x"]; got != uint64(bReadFile|bReadDir|bWriteFile|bExecute) {
		t.Errorf("rw grant under v1 mask = 0x%x, want 0x%x (truncate/remove must be dropped, not kept)", got, uint64(bReadFile|bReadDir|bWriteFile|bExecute))
	}
	// The device grant under the v1 mask loses TRUNCATE: on such kernels
	// `> /dev/null` (O_TRUNC) is DENIED — more restrictive, never less
	// (documented legacy-kernel tradeoff, not a fail-open).
	if got := rules["/dev"]; got != uint64(bReadFile|bReadDir|bWriteFile|bExecute) {
		t.Errorf("dev grant under v1 mask = 0x%x, want 0x%x (truncate must be dropped)", got, uint64(bReadFile|bReadDir|bWriteFile|bExecute))
	}
	if accessFs&^uint64(bReadFile|bReadDir|bWriteFile|bExecute) != 0 {
		t.Errorf("handled_access_fs 0x%x contains bits outside the v1 mask", accessFs)
	}
	// A grant that intersects to zero must be refused, never silently
	// dropped (a zero allowed_access rule is meaningless).
	if _, _, _, err := computeRules(&Spec{RW: []string{"/tmp/x"}}, 0); err == nil {
		t.Fatal("computeRules with an empty ABI mask: accepted, want refusal")
	}
}

// TestWrapperSandboxed is the core wrapper behavior test (checks a–f): the
// child runs the REAL wrapper (Apply → in-place exec of the probe target)
// under a real Landlock ruleset and reports what the sandboxed process can
// and cannot do.
func TestWrapperSandboxed(t *testing.T) {
	skipNoLandlock(t)
	rwDir, roDir, secretDir, sockOKDir, sockDenyDir := newProbeDirs(t)
	listenUnix(t, filepath.Join(sockOKDir, "ok.sock"))
	listenUnix(t, filepath.Join(sockDenyDir, "deny.sock"))

	spec := &Spec{
		RW:      []string{rwDir},
		RO:      []string{roDir, "/bin", "/usr", "/proc/self"},
		Dev:     []string{"/dev"},
		Sockets: []string{filepath.Join(sockOKDir, "ok.sock")},
	}
	out := filepath.Join(rwDir, "probe-result.json")
	res, wc, err := runSandboxedProbe(t, spec, out, map[string]string{
		"PROBE_SECRET":    filepath.Join(secretDir, "secret.txt"),
		"PROBE_EXEC":      "/bin/true",
		"PROBE_SOCK_OK":   filepath.Join(sockOKDir, "ok.sock"),
		"PROBE_SOCK_DENY": filepath.Join(sockDenyDir, "deny.sock"),
	})
	if err != nil {
		t.Fatalf("runSandboxedProbe: %v", err)
	}
	if wc.code != 0 {
		t.Fatalf("probe child exit %d (stderr: %s)", wc.code, wc.stderr)
	}
	// (a) RW: read + write allowed.
	// (b) the planted secret is unreadable (Landlock denial = EACCES).
	// (c) RO: read allowed, write/create denied; the DEVICE grant
	// (Spec.Dev): writing /dev/null — the universal shell idiom — allowed
	// (DAC-gated: only devices the user's DAC already allows are writable).
	// (d) an allowed binary execs.
	// (e) no_new_privs is set (the privilege boundary).
	// (f) the allowed bridge-style socket connects (required behavior).
	assertProbe(t, res,
		"rwWrite", "ok",
		"rwRead", "ok",
		"secret", "EACCES",
		"roRead", "ok",
		"roWrite", "EACCES",
		"roCreate", "EACCES",
		"devNullWrite", "ok",
		"exec", "ok",
		"noNewPrivs", "1",
		"sockOk", "ok",
	)
	// (f, second half) KNOWN KERNEL LIMITATION: on the supported kernels
	// (ABI v1–v4, 5.13–6.8) Landlock does not gate unix-socket connects at
	// all (no connect-unix bit before ABI v5/6.10; 6.8 registers no
	// path-lookup hook), so a socket outside the allowed tree CANNOT be
	// denied by the sandbox on this kernel. Record what the kernel does —
	// the denial the brief asks for is unenforceable here; bridge
	// authorization is S1's job (SO_PEERCRED + nonce), not the sandbox's.
	if a := getABI(); a.version >= 5 {
		if res.SockDeny == "ok" {
			t.Logf("sockDeny: allowed on ABI v%d (connect-unix bit not handled — documented)", a.version)
		}
	} else {
		t.Logf("sockDeny on ABI v%d: %s (connects are not Landlock-gated on this kernel — documented limitation)", getABI().version, res.SockDeny)
	}
}

// TestWrapperSandboxed_InPlaceExec verifies H1 at the observable level: the
// wrapper execs IN PLACE, so the process the supervisor spawned (wc.pid) is
// the same process running the target — no grandchild. The probe writes its
// OWN pid; the parent compares it with the PID it spawned.
func TestWrapperSandboxed_InPlaceExec(t *testing.T) {
	skipNoLandlock(t)
	rwDir, roDir, _, _, _ := newProbeDirs(t)
	spec := &Spec{
		RW: []string{rwDir},
		// The test binary's own dir is harness provision (the probe target
		// must be executable in-place); it is the go-build cache, disjoint
		// from the fixture dirs.
		RO:  []string{roDir, "/bin", "/usr", "/proc/self", filepath.Dir(os.Args[0])},
		Dev: []string{"/dev"},
	}
	pidFile := filepath.Join(rwDir, "probe-pid.txt")
	in := reexecInput{Spec: *spec, Target: os.Args[0]}
	extra := map[string]string{
		probeEnv:        "1",
		"PROBE_OUT":     filepath.Join(rwDir, "probe-result.json"),
		"PROBE_RW":      rwDir,
		"PROBE_RO":      roDir,
		"PROBE_SECRET":  filepath.Join(roDir, "rofile"),
		"PROBE_EXEC":    "/bin/true",
		"PROBE_PID_OUT": pidFile,
	}
	wc, err := runWrapperChild(t, in, extra)
	if err != nil {
		t.Fatalf("runWrapperChild: %v", err)
	}
	if wc.code != 0 {
		t.Fatalf("probe child exit %d (stderr: %s)", wc.code, wc.stderr)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("probe did not write its pid: %v", err)
	}
	targetPID, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("probe pid %q not an int: %v", b, err)
	}
	if targetPID != wc.pid {
		t.Fatalf("target pid %d != spawned pid %d — the wrapper forked a grandchild instead of exec'ing in place (H1)", targetPID, wc.pid)
	}
}

// TestWrapperFailClosed is check (g): with the Landlock apply step forced to
// fail, the wrapper must (1) exit non-zero, (2) print the explicit security
// error, and (3) NEVER exec the target (the marker file must not exist).
func TestWrapperFailClosed(t *testing.T) {
	skipNoLandlock(t)
	rwDir, _, _, _, _ := newProbeDirs(t)
	marker := filepath.Join(rwDir, "should-not-exist")
	spec := &Spec{RW: []string{rwDir}, RO: []string{"/bin", "/usr"}}
	in := reexecInput{
		Spec:       *spec,
		Target:     "/bin/sh",
		Args:       []string{"-c", "touch " + marker},
		InjectFail: true,
	}
	wc, err := runWrapperChild(t, in, nil)
	if err != nil {
		t.Fatalf("runWrapperChild: %v", err)
	}
	if wc.code == 0 {
		t.Fatalf("fail-closed child exited 0 — the launch was NOT refused")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("target ran despite the failed apply (marker %s exists, stat err=%v)", marker, err)
	}
	want := "refusing to launch: sandbox could not be applied"
	if !strings.Contains(wc.stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", wc.stderr, want)
	}
	if !strings.Contains(wc.stderr, "fail closed") {
		t.Errorf("stderr = %q, want the explicit fail-closed marker", wc.stderr)
	}
}

// TestWrapperFailClosed_MissingAllowlistPath pins the H3 determinism for a
// missing allowlist path: the daemon ensures the RW paths it lists exist, so
// a missing one is a launch FAILURE — never a silent skip.
func TestWrapperFailClosed_MissingAllowlistPath(t *testing.T) {
	skipNoLandlock(t)
	rwDir, _, _, _, _ := newProbeDirs(t)
	marker := filepath.Join(rwDir, "should-not-exist")
	spec := &Spec{
		RW: []string{rwDir, filepath.Join(rwDir, "does-not-exist")},
		RO: []string{"/bin", "/usr"},
	}
	in := reexecInput{
		Spec:   *spec,
		Target: "/bin/sh",
		Args:   []string{"-c", "touch " + marker},
	}
	wc, err := runWrapperChild(t, in, nil)
	if err != nil {
		t.Fatalf("runWrapperChild: %v", err)
	}
	if wc.code == 0 {
		t.Fatalf("launch with a missing allowlist path exited 0 — the missing path was silently skipped")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("target ran despite the missing allowlist path")
	}
	if !strings.Contains(wc.stderr, "refusing to launch") || !strings.Contains(wc.stderr, "does-not-exist") {
		t.Errorf("stderr = %q, want the explicit refusal naming the missing path", wc.stderr)
	}
}

// TestWrapperFailClosed_MissingTarget pins the H3 determinism for a
// missing EXEC target: the wrapper stats the target BEFORE applying the
// sandbox and refuses to launch when the runtime binary the daemon expects
// is not there — a missing/renamed binary must never become an unsandboxed
// launch of something else.
func TestWrapperFailClosed_MissingTarget(t *testing.T) {
	skipNoLandlock(t)
	rwDir, _, _, _, _ := newProbeDirs(t)
	in := reexecInput{
		Spec:   Spec{RW: []string{rwDir}, RO: []string{"/bin", "/usr"}},
		Target: filepath.Join(rwDir, "no-such-binary"),
	}
	wc, err := runWrapperChild(t, in, nil)
	if err != nil {
		t.Fatalf("runWrapperChild: %v", err)
	}
	if wc.code == 0 {
		t.Fatal("launch with a missing target exited 0 — the refusal was not fail-closed")
	}
	if !strings.Contains(wc.stderr, "the runtime binary the daemon expects is missing") {
		t.Errorf("stderr = %q, want the explicit missing-target refusal", wc.stderr)
	}
}

// TestWrapperMissingROSkipped pins the H3 determinism for BEST-EFFORT
// coarse RO support paths: an RO path that is absent on this machine is a
// no-op grant and is skipped deterministically — refusing the whole launch
// over a cosmetic gap (a machine without ~/.nvm, /opt/homebrew, ...) would
// make the sandbox unusable. RW grants are NOT best-effort (a missing one
// refuses — TestWrapperFailClosed_MissingAllowlistPath).
func TestWrapperMissingROSkipped(t *testing.T) {
	skipNoLandlock(t)
	rwDir, _, _, _, _ := newProbeDirs(t)
	marker := filepath.Join(rwDir, "ro-skip-ran")
	spec := &Spec{
		RW: []string{rwDir},
		RO: []string{"/bin", "/usr", filepath.Join(rwDir, "absent-ro-path")},
	}
	in := reexecInput{
		Spec:   *spec,
		Target: "/bin/sh",
		Args:   []string{"-c", "touch " + marker},
	}
	wc, err := runWrapperChild(t, in, nil)
	if err != nil {
		t.Fatalf("runWrapperChild: %v", err)
	}
	if wc.code != 0 {
		t.Fatalf("launch with an absent best-effort RO path exited %d (stderr: %s) — a no-op grant must not refuse the launch", wc.code, wc.stderr)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("target did not run (marker missing: %v)", err)
	}
}

// TestWrapperParseErrors pins the wrapper's argv contract: malformed argv is
// refused before any apply (in-process safe — no sandbox is installed).
func TestWrapperParseErrors(t *testing.T) {
	if code := RunWrapperMain(nil); code == 0 {
		t.Fatal("RunWrapperMain(nil): exit 0, want a refusal")
	}
	if code := RunWrapperMain([]string{"--rw"}); code == 0 {
		t.Fatal("RunWrapperMain(--rw without path): exit 0, want a refusal")
	}
	if code := RunWrapperMain([]string{"--rw", "/tmp"}); code == 0 {
		t.Fatal("RunWrapperMain(missing --): exit 0, want a refusal")
	}
	if code := RunWrapperMain([]string{"--rw", "relative/path"}); code == 0 {
		t.Fatal("RunWrapperMain(relative path): exit 0, want a fail-closed refusal")
	}
	if code := RunWrapperMain([]string{"unexpected", "--", "/bin/true"}); code == 0 {
		t.Fatal("RunWrapperMain(unexpected arg before --): exit 0, want a refusal")
	}
}
