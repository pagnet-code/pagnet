package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Re-exec protocol
//
// Applying the sandbox is STICKY (no_new_privs + Landlock cannot be undone),
// so a test must never apply it to the test process. The tests therefore
// spawn a child that is this same test binary in one of two modes:
//
//   - PAGNET_SANDBOX_REEXEC (JSON reexecInput): the child runs the REAL
//     wrapper path — parse argv, Apply (or the injected failure), then
//     in-place syscall.Exec of the target. Its exit code is the wrapper's.
//   - PAGNET_SANDBOX_PROBE: the child (which is the exec'd TARGET, still the
//     test binary) performs the filesystem / socket / privilege checks and
//     writes the raw results as JSON to PROBE_OUT. The parent asserts the
//     expectations — the probe records, the test judges.
//
// The spec travels via env (JSON) rather than argv because the child must
// first enter wrapper mode before its own argv is interpreted; the wrapper
// code path itself is exercised verbatim (RunWrapperMain over WrapperArgs).

const (
	reexecEnv = "PAGNET_SANDBOX_REEXEC"
	probeEnv  = "PAGNET_SANDBOX_PROBE"
)

type reexecInput struct {
	Spec       Spec     `json:"spec"`
	Target     string   `json:"target"`
	Args       []string `json:"args"`
	InjectFail bool     `json:"injectFail,omitempty"` // test-only: force the Landlock step to fail
}

// installApplyFault, when non-nil (linux), forces the wrapper's Landlock
// step to fail — the test-only seam for verifying the fail-closed contract
// (H3) at the process level. On non-Linux there is no apply step to fail.
var installApplyFault func()

func TestMain(m *testing.M) {
	if env := os.Getenv(reexecEnv); env != "" {
		var in reexecInput
		if err := json.Unmarshal([]byte(env), &in); err != nil {
			fmt.Fprintln(os.Stderr, "sandbox reexec: bad input:", err)
			os.Exit(64)
		}
		if in.InjectFail && installApplyFault != nil {
			installApplyFault()
		}
		// Drop the protocol marker BEFORE the in-place exec: the wrapper
		// forwards its env to the target, and the target must not re-enter
		// wrapper mode (it would stack another ruleset layer per exec and
		// loop until the kernel's 16-layer limit — E2BIG).
		os.Unsetenv(reexecEnv)
		os.Exit(RunWrapperMain(WrapperArgs(&in.Spec, in.Target, in.Args)))
	}
	if os.Getenv(probeEnv) != "" {
		os.Exit(runProbe())
	}
	os.Exit(m.Run())
}

// probeResult is what the probe (sandboxed target) records. Every field is
// "ok", "E<errno>" (a syscall errno string), "err:<message>" for non-errno
// failures, or "skipped" — the PARENT asserts the expected value per check.
type probeResult struct {
	RWWrite      string `json:"rwWrite"`
	RWRead       string `json:"rwRead"`
	RORead       string `json:"roRead"`
	ROWrite      string `json:"roWrite"`
	ROCreate     string `json:"roCreate"`
	DevNullWrite string `json:"devNullWrite"`
	Secret       string `json:"secret"`
	Exec         string `json:"exec"`
	NoNewPrivs   string `json:"noNewPrivs"` // "0" / "1" / "err:<msg>"
	SockOK       string `json:"sockOk"`
	SockDeny     string `json:"sockDeny"`
	// F-S2-2: creation gating (the MAKE_* bits). Inside the RW subtree the
	// runtime must still be able to create (its workspace); outside every
	// grant (the secret tree) creation must be DENIED on ABIs that gate it
	// (v2+).
	RWMkdir        string `json:"rwMkdir"`
	RWSymlink      string `json:"rwSymlink"`
	RWCreateFile   string `json:"rwCreateFile"`
	DenyMkdir      string `json:"denyMkdir"`
	DenySymlink    string `json:"denySymlink"`
	DenyCreateFile string `json:"denyCreateFile"`
}

// runProbe executes the check set in the CURRENT process (the exec'd target)
// and records raw outcomes to PROBE_OUT. Exit 2 = probe infrastructure
// failure (bad env / cannot write the result) — a test harness bug.
func runProbe() int {
	get := func(k string) string { return os.Getenv(k) }
	out := get("PROBE_OUT")
	rwDir, roDir := get("PROBE_RW"), get("PROBE_RO")
	secret, execBin := get("PROBE_SECRET"), get("PROBE_EXEC")
	sockOK, sockDeny := get("PROBE_SOCK_OK"), get("PROBE_SOCK_DENY")
	if out == "" || rwDir == "" || roDir == "" || secret == "" || execBin == "" {
		fmt.Fprintln(os.Stderr, "probe: missing env (PROBE_OUT/PROBE_RW/PROBE_RO/PROBE_SECRET/PROBE_EXEC)")
		return 2
	}

	r := probeResult{}
	r.RWWrite = checkOK(os.WriteFile(filepath.Join(rwDir, "probe-w.txt"), []byte("probe"), 0o644))
	if b, err := os.ReadFile(filepath.Join(rwDir, "probe-w.txt")); err == nil && string(b) == "probe" {
		r.RWRead = "ok"
	} else {
		r.RWRead = checkOK(err)
	}
	roFile := filepath.Join(roDir, "rofile")
	if _, err := os.ReadFile(roFile); err != nil {
		r.RORead = checkOK(err)
	} else {
		r.RORead = "ok"
	}
	r.ROWrite = checkOK(os.WriteFile(roFile, []byte("nope"), 0o644))
	r.ROCreate = checkOK(os.WriteFile(filepath.Join(roDir, "probe-new.txt"), []byte("nope"), 0o644))
	r.DevNullWrite = checkOK(writeDevNull())
	if _, err := os.ReadFile(secret); err != nil {
		r.Secret = checkOK(err)
	} else {
		r.Secret = "ok"
	}
	// F-S2-2: creation (the MAKE_* bits). The runtime must create INSIDE
	// its RW subtree (workspace); outside every grant (the secret tree) it
	// must be denied on ABIs that gate creation (v2+).
	secretDir := filepath.Dir(secret)
	r.RWMkdir = checkOK(os.Mkdir(filepath.Join(rwDir, "probe-mkdir"), 0o755))
	r.RWSymlink = checkOK(os.Symlink(roFile, filepath.Join(rwDir, "probe-symlink")))
	if f, err := os.OpenFile(filepath.Join(rwDir, "probe-create"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		f.Close()
		r.RWCreateFile = "ok"
	} else {
		r.RWCreateFile = checkOK(err)
	}
	r.DenyMkdir = checkOK(os.Mkdir(filepath.Join(secretDir, "planted-mkdir"), 0o755))
	r.DenySymlink = checkOK(os.Symlink(secret, filepath.Join(secretDir, "planted-symlink")))
	if f, err := os.OpenFile(filepath.Join(secretDir, "planted-file"), os.O_WRONLY|os.O_CREATE, 0o600); err == nil {
		f.Close()
		os.Remove(filepath.Join(secretDir, "planted-file"))
		r.DenyCreateFile = "ok"
	} else {
		r.DenyCreateFile = checkOK(err)
	}
	if outBytes, err := exec.Command(execBin).CombinedOutput(); err != nil {
		r.Exec = "err:" + firstLine(err.Error()) + " out=" + firstLine(string(outBytes))
	} else {
		r.Exec = "ok"
	}
	r.NoNewPrivs = readNoNewPrivs()
	if pidOut := get("PROBE_PID_OUT"); pidOut != "" {
		if err := os.WriteFile(pidOut, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "probe: write pid:", err)
			return 2
		}
	}
	if sockOK != "" {
		r.SockOK = dialUnix(sockOK)
	} else {
		r.SockOK = "skipped"
	}
	if sockDeny != "" {
		r.SockDeny = dialUnix(sockDeny)
	} else {
		r.SockDeny = "skipped"
	}

	b, err := json.Marshal(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe: marshal:", err)
		return 2
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "probe: write result:", err)
		return 2
	}
	return 0
}

// checkOK renders an error as "ok", a canonical errno name (EACCES, ...),
// or "err:<first line>".
func checkOK(err error) string {
	if err == nil {
		return "ok"
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		return errnoName(en)
	}
	return "err:" + firstLine(err.Error())
}

// writeDevNull opens /dev/null the way a shell opens it for `> /dev/null`
// (O_WRONLY|O_CREAT|O_TRUNC — the O_TRUNC flag is gated by the Landlock
// TRUNCATE bit, which is why the Spec.Dev grant carries it) and writes to
// it. This is the check that pins the Spec.Dev grant on Linux; on
// non-Linux (no sandbox) it is expected to succeed trivially.
func writeDevNull() error {
	f, err := os.OpenFile("/dev/null", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte("probe"))
	return err
}

// errnoName maps common errnos to canonical names (stable across glibc/Go
// wording) for exact test assertions.
func errnoName(en syscall.Errno) string {
	switch en {
	case syscall.EACCES:
		return "EACCES"
	case syscall.EPERM:
		return "EPERM"
	case syscall.ENOENT:
		return "ENOENT"
	case syscall.ECONNREFUSED:
		return "ECONNREFUSED"
	case syscall.ECONNRESET:
		return "ECONNRESET"
	case syscall.EINTR:
		return "EINTR"
	default:
		return "errno(" + itoa(int(en)) + ")"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// firstLine trims a message to its first line (keeps probe output compact).
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// readNoNewPrivs returns "0"/"1" from /proc/self/status or "err:<msg>".
func readNoNewPrivs() string {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "err:" + firstLine(err.Error())
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "NoNewPrivs:") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				return fields[1]
			}
			return "err:unparseable " + line
		}
	}
	return "err:NoNewPrivs line not found"
}

// dialUnix connects to a unix socket with a short timeout; "ok" on success.
func dialUnix(path string) string {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return checkOK(err)
	}
	c.Close()
	return "ok"
}

// ---------------------------------------------------------------------------
// Parent-side harness

// listenUnix creates a unix socket listener at path (the dir must exist).
func listenUnix(t *testing.T, path string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	t.Cleanup(func() { l.Close() })
}

// wrapperChild is the outcome of one re-exec'd wrapper run. pid is the
// process the parent spawned — after the wrapper's in-place exec (H1) that
// SAME pid is the target's pid.
type wrapperChild struct {
	pid    int
	code   int
	stderr string
}

// runWrapperChild re-execs this test binary as the wrapper (real Apply or
// the injected failure), with the given target/args. The child's env is the
// parent's env plus the reexec protocol and extraEnv. It returns the child's
// exit code and stderr.
func runWrapperChild(t *testing.T, in reexecInput, extraEnv map[string]string) (wrapperChild, error) {
	t.Helper()
	if in.Target == "" {
		in.Target = os.Args[0]
	}
	inJSON, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal reexec input: %v", err)
	}
	env := os.Environ()
	env = append(env, reexecEnv+"="+string(inJSON))
	for k, v := range extraEnv {
		env = append(env, k+"="+v)
	}
	// The child is ALWAYS this test binary: it enters wrapper mode (via the
	// reexec env), applies the sandbox, and execs in.Target IN PLACE. So the
	// pid returned here is, after the in-place exec, also in.Target's pid.
	cmd := exec.Command(os.Args[0])
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return wrapperChild{}, fmt.Errorf("spawn wrapper child: %w", err)
	}
	childPID := cmd.Process.Pid
	runErr := cmd.Wait()
	wc := wrapperChild{pid: childPID, stderr: stderr.String()}
	if runErr == nil {
		return wc, nil
	}
	var ee *exec.ExitError
	if !errors.As(runErr, &ee) {
		return wc, fmt.Errorf("spawn wrapper child: %w (stderr: %s)", runErr, stderr.String())
	}
	wc.code = ee.ExitCode()
	return wc, nil
}

// runSandboxedProbe runs the wrapper with a probe target (the test binary in
// probe mode) under the given spec. PROBE_OUT must live inside an allowed RW
// dir. extraEnv carries the probe inputs that are not part of the spec
// (PROBE_SECRET, PROBE_EXEC, PROBE_SOCK_OK, PROBE_SOCK_DENY, ...).
func runSandboxedProbe(t *testing.T, spec *Spec, out string, extraEnv map[string]string) (probeResult, wrapperChild, error) {
	t.Helper()
	if err := spec.Normalize(); err != nil {
		t.Fatalf("normalize spec: %v", err)
	}
	if len(spec.RW) == 0 || len(spec.RO) == 0 {
		t.Fatalf("probe spec needs at least one RW and one RO dir")
	}
	// Harness provision: the probe target is this test binary, so its own
	// directory must be executable from inside the sandbox. Under `go test`
	// that is the go-build cache — disjoint from the t.TempDir() fixtures,
	// so the denied-secret checks stay meaningful.
	spec.RO = append(spec.RO, filepath.Dir(os.Args[0]))
	in := reexecInput{Spec: *spec, Target: os.Args[0]}
	extra := map[string]string{
		probeEnv:    "1",
		"PROBE_OUT": out,
		"PROBE_RW":  spec.RW[0],
		"PROBE_RO":  spec.RO[0],
	}
	for k, v := range extraEnv {
		extra[k] = v
	}
	wc, err := runWrapperChild(t, in, extra)
	if err != nil {
		return probeResult{}, wc, err
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return probeResult{}, wc, fmt.Errorf("read probe result (child exit %d, stderr: %s): %w", wc.code, wc.stderr, err)
	}
	var res probeResult
	if err := json.Unmarshal(b, &res); err != nil {
		return probeResult{}, wc, fmt.Errorf("unmarshal probe result: %w", err)
	}
	return res, wc, nil
}

// wantOne is a named probe expectation for assertProbe.
func wantOne(name string, want string) (string, string) { return name, want }

// assertProbe checks named recorded outcomes against expectations, e.g.
//
//	assertProbe(t, res,
//		wantOne("rwWrite", "ok"), wantOne("secret", "operation not permitted (EACCES)"))
func assertProbe(t *testing.T, res probeResult, wants ...string) {
	t.Helper()
	for i := 0; i+1 < len(wants); i += 2 {
		name, want := wants[i], wants[i+1]
		var got string
		switch name {
		case "rwWrite":
			got = res.RWWrite
		case "rwRead":
			got = res.RWRead
		case "roRead":
			got = res.RORead
		case "roWrite":
			got = res.ROWrite
		case "roCreate":
			got = res.ROCreate
		case "devNullWrite":
			got = res.DevNullWrite
		case "secret":
			got = res.Secret
		case "exec":
			got = res.Exec
		case "noNewPrivs":
			got = res.NoNewPrivs
		case "sockOk":
			got = res.SockOK
		case "sockDeny":
			got = res.SockDeny
		case "rwMkdir":
			got = res.RWMkdir
		case "rwSymlink":
			got = res.RWSymlink
		case "rwCreateFile":
			got = res.RWCreateFile
		case "denyMkdir":
			got = res.DenyMkdir
		case "denySymlink":
			got = res.DenySymlink
		case "denyCreateFile":
			got = res.DenyCreateFile
		default:
			t.Fatalf("assertProbe: unknown check %q", name)
		}
		if got != want {
			t.Errorf("probe %s = %q, want %q (full result: %+v)", name, got, want, res)
		}
	}
}
