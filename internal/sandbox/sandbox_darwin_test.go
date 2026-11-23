//go:build darwin

package sandbox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/creack/pty"
	"time"
)

func TestDarwinPlatformRemainsNonIsolated(t *testing.T) {
	if MustSandbox() || Available() || LandlockAvailable() || KernelRelease() != "" {
		t.Fatal("Darwin daemon launch policy changed")
	}
	if err := Apply(&Spec{RW: []string{"relative"}}); err == nil {
		t.Fatal("Apply accepted an invalid spec")
	}
}

func darwinProductionSpec(t *testing.T) (*Spec, string, string) {
	t.Helper()
	base := t.TempDir()
	workspace, secret := filepath.Join(base, "workspace"), filepath.Join(base, "secret")
	for _, dir := range []string{workspace, secret} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(secret, "outside"), []byte("not granted"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A synthetic home avoids importing the host's actual runtime state paths.
	spec := NewSpec(Options{Workspace: workspace, Binary: "/bin/sh", Home: filepath.Join(base, "home"), Denied: []string{secret}})
	return spec, workspace, filepath.Join(secret, "outside")
}

func darwinExplicitWrapperCommand(t *testing.T, spec *Spec, target string, args []string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(reexecInput{Spec: *spec, Target: target, Args: args})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), reexecEnv+"="+string(input))
	return cmd
}

func TestDarwinProductionShellWrapper(t *testing.T) {
	spec, workspace, secret := darwinProductionSpec(t)
	script := `set -e
printf '%s\n' "$$"
echo writable > "$1/created"
/bin/cat "$1/created" >/dev/null
if /bin/cat "$2" >/dev/null; then exit 31; fi
/bin/sh -c 'if /bin/cat "$1" >/dev/null; then exit 32; fi; echo inherited > "$2/child"' child "$2" "$1"
`
	cmd := darwinExplicitWrapperCommand(t, spec, "/bin/sh", []string{"-c", script, "probe", workspace, secret})
	cmd.Dir = workspace
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("explicit production wrapper: %v\n%s", err, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != strconv.Itoa(pid) {
		t.Fatalf("wrapper PID %d, target output %q", pid, stdout.String())
	}
	if _, err := os.Stat(filepath.Join(workspace, "child")); err != nil {
		t.Fatalf("child did not execute: %v", err)
	}
}

func TestDarwinProductionLocalDNSTLS(t *testing.T) {
	spec, workspace, _ := darwinProductionSpec(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Exact helper executable access, without a broad temporary-directory grant.
	spec.RO = append(spec.RO, exe)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "seatbelt TLS")
	}))
	defer server.Close()
	dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := dns.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			questionEnd := 12
			for questionEnd < n && buf[questionEnd] != 0 {
				questionEnd += int(buf[questionEnd]) + 1
			}
			questionEnd += 5 // terminating zero, query type and class
			if questionEnd > n {
				continue
			}
			response := append([]byte{}, buf[:questionEnd]...)
			response[2], response[3] = 0x81, 0x80
			response[6], response[7] = 0, 1
			response[10], response[11] = 0, 0
			response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
			dns.WriteTo(response, addr)
		}
	}()
	cmd := darwinExplicitWrapperCommand(t, spec, exe, []string{"-test.run=^TestDarwinProductionNetworkProbe$"})
	cmd.Dir = workspace
	cmd.Env = append(cmd.Env,
		"PAGNET_DARWIN_TLS="+server.URL,
		"PAGNET_DARWIN_CERT="+base64.StdEncoding.EncodeToString(server.Certificate().Raw),
		"PAGNET_DARWIN_DNS="+dns.LocalAddr().String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("production DNS/TLS probe: %v\n%s", err, out)
	}
}

func TestDarwinProductionNetworkProbe(t *testing.T) {
	url := os.Getenv("PAGNET_DARWIN_TLS")
	if url == "" {
		t.Skip("subprocess probe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := os.ReadFile("/etc/resolv.conf"); err != nil {
		t.Fatalf("exact system resolver configuration: %v", err)
	}
	if addresses, err := net.DefaultResolver.LookupHost(ctx, "localhost"); err != nil || len(addresses) == 0 {
		t.Fatalf("system localhost lookup: %v, %v", addresses, err)
	}
	// Test a real UDP DNS exchange without external DNS service dependencies.
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", os.Getenv("PAGNET_DARWIN_DNS"))
	}}
	ips, err := resolver.LookupIP(ctx, "ip4", "seatbelt.test")
	if err != nil || len(ips) == 0 || !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("DNS exchange: %v, %v", ips, err)
	}
	certDER, err := base64.StdEncoding.DecodeString(os.Getenv("PAGNET_DARWIN_CERT"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.Status)
	}
}

// These optional probes use a temporary CLI build and an installed runtime.
// They never inherit provider credentials or point HOME at existing state.
func TestDarwinInstalledRuntimeProbe(t *testing.T) {
	cli, qwen := os.Getenv("PAGNET_DARWIN_CLI"), os.Getenv("PAGNET_DARWIN_QWEN")
	if cli == "" || qwen == "" {
		t.Skip("requires isolated CLI build and installed Qwen")
	}
	for _, probe := range []struct {
		name   string
		target string
		args   []string
	}{{"QwenVersion", qwen, []string{"--version"}},
		{"PTYChild", "/usr/bin/script", []string{"-q", "/dev/null", "/bin/sh", "-c", "test -t 0 && test -t 1 && echo seatbelt-pty"}}} {
		t.Run(probe.name, func(t *testing.T) {
			base := t.TempDir()
			home, workspace, scratch := filepath.Join(base, "home"), filepath.Join(base, "workspace"), filepath.Join(base, "tmp")
			native := filepath.Join(home, ".qwen")
			for _, dir := range []string{native, workspace, scratch} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			spec := NewSpec(Options{Workspace: workspace, Binary: probe.target, Home: home, NativeDirs: []string{native}, Scratch: []string{scratch}})
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			args := append([]string{Subcommand}, WrapperArgs(spec, probe.target, probe.args)...)
			cmd := exec.CommandContext(ctx, cli, args...)
			cmd.Dir = workspace
			cmd.Env = []string{"HOME=" + home, "PATH=/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR=" + scratch + "/", "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"), "SHELL=/bin/sh", "TERM=xterm-256color"}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\n%s", probe.name, err, out)
			}
			t.Logf("%s: %s", probe.name, strings.TrimSpace(string(out)))
		})
	}
}

func TestDarwinInheritedPTYProbe(t *testing.T) {
	for _, probe := range []struct{ name, script string }{
		{"Stdio", "echo inherited-pty-stdio"},
		{"TerminalDetection", "test -t 0 && test -t 1 && echo inherited-pty-terminal"},
		{"Termios", "/bin/stty -a >/dev/null && echo inherited-pty-termios"},
	} {
		t.Run(probe.name, func(t *testing.T) {
			if probe.name == "Termios" && os.Getenv("PAGNET_DARWIN_TERMIOS_PROBE") == "" {
				t.Skip("optional termios compatibility probe; inherited tty ioctl grants await review")
			}
			spec, workspace, _ := darwinProductionSpec(t)
			cmd := darwinExplicitWrapperCommand(t, spec, "/bin/sh", []string{"-c", probe.script})
			cmd.Dir = workspace
			master, slave, err := pty.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := cmd.Start(); err != nil {
				slave.Close()
				t.Fatal(err)
			}
			slave.Close()
			out, _ := io.ReadAll(master) // Darwin may terminate a drained PTY with EIO.
			if err := cmd.Wait(); err != nil {
				t.Fatalf("inherited PTY: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "inherited-pty-") {
				t.Fatalf("missing PTY output: %s", out)
			}
			t.Logf("%s", strings.TrimSpace(string(out)))
		})
	}
}
