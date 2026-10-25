//go:build unix

package proc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

func unsetTerminalEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"TERM", "COLORTERM", "NO_COLOR", "FORCE_COLOR"} {
		t.Setenv(key, "") // Register restoration of the original environment.
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPTYEnvLaunchCapabilities(t *testing.T) {
	unsetTerminalEnv(t)
	for _, tc := range []struct {
		name  string
		class Class
		size  *pty.Winsize
		stdio bool
		want  string
	}{
		{"interactive", ClassPTY, nil, false, "xterm-256color|truecolor|unset|unset"},
		{"endpoint-stdio", ClassEndpoint, &pty.Winsize{Rows: 24, Cols: 80}, true, "xterm-256color|truecolor|unset|unset"},
		{"endpoint-controlling-tty", ClassEndpoint, &pty.Winsize{Rows: 24, Cols: 80}, false, "xterm-256color|truecolor|unset|unset"},
		{"endpoint-machine", ClassEndpoint, nil, false, "unset|unset|unset|unset"},
		{"turn-machine", ClassTurn, nil, false, "unset|unset|unset|unset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSupervisor(t, Config{MaxActiveTurns: 4, MonitorInterval: time.Hour})
			output := filepath.Join(t.TempDir(), "terminal-env")
			cmd := exec.Command("sh", "-c", `env > "$1"`, "sh", output)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			h, err := s.Launch(context.Background(), LaunchRequest{InstanceID: tc.name, TurnID: "env-test", Runtime: "test", Class: tc.class, Cmd: cmd, PTYSize: tc.size, PTYStdio: tc.stdio})
			if err != nil {
				t.Fatal(err)
			}
			if err := h.Wait(); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]string{}
			for _, pair := range strings.Split(string(got), "\n") {
				key, value, ok := strings.Cut(pair, "=")
				if ok {
					values[key] = value
				}
			}
			var capabilities []string
			for _, key := range []string{"TERM", "COLORTERM", "NO_COLOR", "FORCE_COLOR"} {
				value, present := values[key]
				if !present {
					value = "unset"
				}
				capabilities = append(capabilities, value)
			}
			if got := strings.Join(capabilities, "|"); got != tc.want {
				t.Fatalf("child terminal capabilities=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestPTYEnvPreservesColorPreferences(t *testing.T) {
	for _, tc := range []struct {
		name      string
		inherited []string
		child     []string
		want      map[string]string
	}{
		{"explicit", nil, []string{"TERM=screen-256color", "COLORTERM=24bit", "NO_COLOR=1"}, map[string]string{"TERM": "screen-256color", "COLORTERM": "24bit", "NO_COLOR": "1"}},
		{"empty-values", nil, []string{"TERM=", "COLORTERM=", "NO_COLOR="}, map[string]string{"TERM": "", "COLORTERM": "", "NO_COLOR": ""}},
		{"dumb", nil, []string{"TERM=dumb"}, map[string]string{"TERM": "dumb"}},
		{"empty-term", nil, []string{"TERM="}, map[string]string{"TERM": ""}},
		{"inherited-filtered", []string{"TERM=screen", "COLORTERM=24bit", "NO_COLOR=1"}, nil, map[string]string{"TERM": "xterm-256color", "COLORTERM": "truecolor"}},
		{"daemon-monochrome", []string{"TERM=dumb", "NO_COLOR=1"}, nil, map[string]string{"TERM": "xterm-256color", "COLORTERM": "truecolor"}},
		{"child-overrides-inherited", []string{"TERM=dumb", "COLORTERM=24bit", "NO_COLOR=1"}, []string{"TERM=xterm", "COLORTERM=", "NO_COLOR="}, map[string]string{"TERM": "xterm", "COLORTERM": "", "NO_COLOR": ""}},
		{"no-color-with-capabilities", nil, []string{"NO_COLOR=1"}, map[string]string{"TERM": "xterm-256color", "COLORTERM": "truecolor", "NO_COLOR": "1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unsetTerminalEnv(t)
			for _, pair := range tc.inherited {
				key, value, _ := strings.Cut(pair, "=")
				t.Setenv(key, value)
			}
			cmd := exec.Command("sh")
			// Model the runtime's filtered environment rather than inheriting it.
			cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, tc.child...)
			defaultPTYEnv(cmd)
			got := map[string]string{}
			for _, pair := range cmd.Env {
				key, value, _ := strings.Cut(pair, "=")
				if key == "TERM" || key == "COLORTERM" || key == "NO_COLOR" || key == "FORCE_COLOR" {
					got[key] = value
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("color preferences=%v, want %v", got, tc.want)
			}
			for key, want := range tc.want {
				if value, present := got[key]; !present || value != want {
					t.Fatalf("%s=%q (present=%v), want %q", key, value, present, want)
				}
			}
		})
	}
}

func TestPTYEnvImplicitInheritanceUsesViewerCapabilities(t *testing.T) {
	unsetTerminalEnv(t)
	t.Setenv("TERM", "dumb")
	t.Setenv("COLORTERM", "daemon-color")
	t.Setenv("NO_COLOR", "1")
	t.Setenv("PAGNET_TEST_PTY_ENV", "preserved")
	cmd := exec.Command("sh")
	defaultPTYEnv(cmd)
	got := map[string]string{}
	for _, pair := range cmd.Env {
		key, value, _ := strings.Cut(pair, "=")
		got[key] = value
	}
	for key, want := range map[string]string{
		"TERM":                "xterm-256color",
		"COLORTERM":           "truecolor",
		"PAGNET_TEST_PTY_ENV": "preserved",
	} {
		if got[key] != want {
			t.Fatalf("%s=%q, want %q", key, got[key], want)
		}
	}
	if _, present := got["NO_COLOR"]; present {
		t.Fatal("daemon NO_COLOR inherited by PTY child")
	}
}
