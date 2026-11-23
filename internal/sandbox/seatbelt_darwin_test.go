//go:build darwin

package sandbox

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestDarwinPolicyParameters(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "space \"quote\\slash\n雪")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	spec := &Spec{RW: []string{path}}
	before := append([]string{}, spec.RW...)
	policy, err := GenerateDarwinPolicy(spec)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(policy.Profile, path) || len(policy.Parameters) == 0 || policy.Parameters[0] != "PATH_0="+canonical {
		t.Fatalf("path was not transported as a literal parameter: %+v", policy)
	}
	if !reflect.DeepEqual(before, spec.RW) {
		t.Fatal("generation mutated the input")
	}
	if !strings.Contains(policy.Profile, "(deny default)") || strings.Contains(policy.Profile, "(allow file-read*)") {
		t.Fatalf("unexpected baseline: %s", policy.Profile)
	}
}

func TestDarwinPolicyRejectsInvalidGrants(t *testing.T) {
	base := t.TempDir()
	secret := filepath.Join(base, "secret")
	alias := filepath.Join(base, "alias")
	file := filepath.Join(base, "file")
	dangling := filepath.Join(base, "dangling")
	deviceAlias := filepath.Join(base, "null")
	fifo := filepath.Join(base, "fifo")
	if err := os.Symlink("/dev/null", deviceAlias); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(secret, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, spec := range map[string]*Spec{
		"nil":                     nil,
		"relative":                {RW: []string{"relative"}},
		"NUL":                     {RO: []string{"/invalid\x00"}},
		"trimmed path":            {RW: []string{" " + base}},
		"missing RW":              {RW: []string{filepath.Join(base, "missing")}},
		"file RW":                 {RW: []string{file}},
		"directory Dev":           {Dev: []string{base}},
		"broad dev":               {Dev: []string{"/dev"}},
		"symlink Dev":             {Dev: []string{deviceAlias}},
		"fifo Dev":                {Dev: []string{fifo}},
		"denied device":           {Dev: []string{"/dev/null"}, Denied: []string{"/dev/null"}},
		"file Dev":                {Dev: []string{file}},
		"file socket":             {Sockets: []string{file}},
		"missing socket":          {Sockets: []string{filepath.Join(base, "missing.sock")}},
		"denied root ancestor":    {RO: []string{"/"}, Denied: []string{secret}},
		"denied symlink grant":    {RW: []string{alias}, Denied: []string{secret}},
		"denied symlink path":     {RO: []string{secret}, Denied: []string{alias}},
		"denied dangling symlink": {RW: []string{secret}, Denied: []string{dangling}},
		"denied missing suffix":   {RW: []string{secret}, Denied: []string{filepath.Join(alias, "missing")}},
		"denied device ancestor":  {Dev: []string{base}, Denied: []string{secret}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := GenerateDarwinPolicy(spec); err == nil {
				t.Fatal("accepted an invalid grant")
			}
		})
	}
}

func TestDarwinPolicyOptionalSupportAndExactFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(file, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	policy, err := GenerateDarwinPolicy(&Spec{RO: []string{file, file + "-absent"}, Dev: []string{file + "-absent"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Parameters) == 0 || !strings.Contains(policy.Profile, "(literal (param") || strings.Contains(policy.Profile, "file-write") {
		t.Fatalf("unexpected grants: %+v", policy)
	}
}

func darwinSmokeSpec(rw, ro string) *Spec {
	return &Spec{RW: []string{rw}, RO: []string{ro, "/bin", "/usr/bin", "/usr/lib", "/System"}, Dev: SystemDev()}
}

func TestDarwinPolicyExactDevices(t *testing.T) {
	want := []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"}
	if !reflect.DeepEqual(SystemDev(), want) {
		t.Fatalf("unexpected default devices: %q", SystemDev())
	}
	policy, err := GenerateDarwinPolicy(&Spec{Dev: SystemDev()})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range want {
		st, err := os.Lstat(path)
		if err != nil || st.Mode()&os.ModeCharDevice == 0 {
			t.Fatalf("default device %s is not a character device: %v", path, err)
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, param := range policy.Parameters {
			key, value, _ := strings.Cut(param, "=")
			if value == resolved && strings.Contains(policy.Profile, `(allow file-read* file-write-data (literal (param "`+key+`")))`) {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing exact read/data-write grant for %s", path)
		}
	}
	if strings.Count(policy.Profile, "(allow file-read* file-write-data ") != len(want) {
		t.Fatal("unexpected device grant count")
	}
	for _, forbidden := range []string{"subpath", "process-exec", "file-ioctl", "mach-", "pseudo-tty", "file-write*"} {
		if strings.Contains(policy.Profile, forbidden) {
			t.Fatalf("unexpected device permission: %s", forbidden)
		}
	}
}

func TestDarwinSeatbeltDevices(t *testing.T) {
	// Prove ptmx is available before testing that Seatbelt denies its open.
	// This allocates a fresh PTY and never reads a user's existing terminal.
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("unsandboxed ptmx control: %v", err)
	}
	if err := ptmx.Close(); err != nil {
		t.Fatal(err)
	}
	// Entropy is discarded; opening ptmx creates no connection to a user's tty.
	script := `set -e
printf device >/dev/null
/bin/dd if=/dev/null of=/dev/null bs=1 count=1
/bin/dd if=/dev/zero of=/dev/null bs=1 count=1
/bin/dd if=/dev/random of=/dev/null bs=1 count=1
/bin/dd if=/dev/urandom of=/dev/null bs=1 count=1
if (exec 3<>/dev/ptmx); then exit 20; fi
`
	spec := darwinSmokeSpec("", "")
	args, err := DarwinWrapperArgs(spec, "/bin/sh", []string{"-c", script})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/sandbox-exec", args...).CombinedOutput(); err != nil {
		t.Fatalf("device smoke: %v\n%s", err, out)
	}
}

func TestDarwinSeatbeltFilesystem(t *testing.T) {
	base := t.TempDir()
	rw := filepath.Join(base, "rw \"\\\n雪")
	ro := filepath.Join(base, "ro")
	secret := filepath.Join(base, "secret")
	for _, dir := range []string{rw, ro, secret} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "data"), []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(secret, filepath.Join(rw, "escape")); err != nil {
		t.Fatal(err)
	}
	program := []byte("#!/bin/sh\nexit 0\n")
	for _, dir := range []string{rw, secret} {
		if err := os.WriteFile(filepath.Join(dir, "program"), program, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// All operands travel as argv, including profile injection characters.
	script := `set -e
/bin/ls -f / >/dev/null || :
if /bin/cat /etc/passwd >/dev/null; then exit 10; fi
"$1/program" allowed >/dev/null
if "$3/program" denied >/dev/null; then exit 17; fi
/bin/cat "$1/data" >/dev/null
/bin/echo written > "$1/new"
/bin/cat "$2/data" >/dev/null
if /bin/echo denied > "$2/new"; then exit 11; fi
if /bin/cat "$3/data" >/dev/null; then exit 12; fi
if /bin/echo denied > "$3/new"; then exit 13; fi
if /bin/cat "$1/escape/data" >/dev/null; then exit 14; fi
if /bin/echo denied > "$1/escape/new"; then exit 15; fi
if /bin/ln "$3/data" "$1/leak"; then
  if /bin/cat "$1/leak" >/dev/null; then exit 16; fi
fi
/bin/mkdir "$1/dir"
/bin/rm "$1/new"
`
	spec := darwinSmokeSpec(rw, ro)
	args, err := DarwinWrapperArgs(spec, "/bin/sh", []string{"-c", script, "probe", rw, ro, secret})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/sandbox-exec", args...).CombinedOutput(); err != nil {
		t.Fatalf("filesystem smoke: %v\n%s", err, out)
	}
}

func TestDarwinSeatbeltSocket(t *testing.T) {
	// Unix socket paths are limited in length; use an isolated short directory.
	base, err := os.MkdirTemp("/tmp", "pagnet-seatbelt-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	allowed := filepath.Join(base, "allowed.sock")
	denied := filepath.Join(base, "denied.sock")
	for _, path := range []string{allowed, denied} {
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err == nil {
				conn.Close()
			}
		}()
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		conn, err := tcp.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	spec := darwinSmokeSpec("", "")
	spec.RW, spec.Sockets = nil, []string{allowed}
	spec.RO = append(spec.RO, exe)
	args, err := DarwinWrapperArgs(spec, exe, []string{"-test.run=^TestDarwinSocketProbe$"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/sandbox-exec", args...)
	cmd.Env = append(os.Environ(), "PAGNET_SEATBELT_PROBE="+allowed, "PAGNET_SEATBELT_DENIED="+denied, "PAGNET_SEATBELT_TCP="+tcp.Addr().String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("socket smoke: %v\n%s", err, out)
	}

}

func TestDarwinSocketProbe(t *testing.T) {
	allowed := os.Getenv("PAGNET_SEATBELT_PROBE")
	if allowed == "" {
		t.Skip("subprocess probe")
	}
	conn, err := net.Dial("unix", allowed)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	conn, err = net.Dial("tcp4", os.Getenv("PAGNET_SEATBELT_TCP"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if conn, err := net.Dial("unix", os.Getenv("PAGNET_SEATBELT_DENIED")); err == nil {
		conn.Close()
		t.Fatal("unlisted socket allowed")
	}
}

func TestDarwinWrapperPreservesPID(t *testing.T) {
	spec := darwinSmokeSpec("", "")
	spec.RW = nil
	args, err := DarwinWrapperArgs(spec, "/bin/sh", []string{"-c", `echo $$`})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/sandbox-exec", args...)
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != strconv.Itoa(pid) {
		t.Fatalf("wrapper PID %d, target PID %s", pid, out.String())
	}
}

func TestDarwinWrapperValidation(t *testing.T) {
	spec := &Spec{}
	for _, target := range []string{"relative", "/invalid\x00", filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		if _, err := DarwinWrapperArgs(spec, target, nil); err == nil {
			t.Fatalf("accepted target %q", target)
		}
	}
	if err := RunDarwinWrapper([]string{"--rw"}); err == nil {
		t.Fatal("accepted malformed wrapper argv")
	}
	args, err := DarwinWrapperArgs(spec, "/bin/echo", []string{"-literal", "quote \"\\\n雪"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args[len(args)-4:], []string{"--", "/bin/echo", "-literal", "quote \"\\\n雪"}) {
		t.Fatalf("target args changed: %q", args)
	}
}

func TestDarwinPolicyStartupSysctls(t *testing.T) {
	policy, err := GenerateDarwinPolicy(&Spec{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hw.pagesize", "hw.pagesize_compat", "hw.memsize", "kern.ostype", "kern.hostname", "kern.osrelease", "kern.version", "hw.machine"} {
		if strings.Count(policy.Profile, `(sysctl-name "`+name+`")`) != 1 {
			t.Fatalf("missing or duplicate exact sysctl grant for %s", name)
		}
	}
	if strings.Count(policy.Profile, "(sysctl-name ") != 8 || strings.Contains(policy.Profile, "sysctl-name-prefix") || strings.Contains(policy.Profile, "sysctl-write") || strings.Contains(policy.Profile, "(allow sysctl-read)") {
		t.Fatal("sysctl grants expanded beyond exact startup reads")
	}
	for _, forbidden := range []string{"mach-lookup", "pseudo-tty", "file-ioctl"} {
		if strings.Contains(policy.Profile, forbidden) {
			t.Fatalf("unexpected %s grant", forbidden)
		}
	}
}
