package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// --- self-spawn MCP config (packaging migration step 5) ----------------------
// The bridge command is the daemon's OWN executable (<self> mcp
// worker|control): the runtime never searches PATH for a sibling
// binary. A daemon started from a source checkout (or any environment
// where the install dir never reached PATH — install.sh only nags
// about it) must still give its agents their network tools, and a
// daemon that cannot resolve its own executable must fail explicitly
// instead of handing out a bare name that spawns nothing.

func writeFakeBridge(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolveSelfExecutable(t *testing.T) {
	got, err := resolveSelfExecutable()
	if err != nil {
		t.Fatalf("resolveSelfExecutable: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("self executable %q is not absolute", got)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("resolveSelfExecutable = %q, want the canonicalized %q", got, want)
	}
}

// TestNewFailsWhenSelfUnresolvable: a daemon that cannot name its own
// binary cannot spawn its bridges — it must refuse to start with a
// clear error, never run and silently come up tool-less.
func TestNewFailsWhenSelfUnresolvable(t *testing.T) {
	_, err := newDaemon(Config{StateDir: t.TempDir()}, nil,
		func() (string, error) {
			return "", errors.New("simulated: /proc/self/exe unreadable")
		})
	if err == nil {
		t.Fatal("New started a daemon whose self executable is unresolvable")
	}
	if !strings.Contains(err.Error(), "cannot resolve own executable for MCP bridge spawn") {
		t.Fatalf("error = %q, want the explicit self-resolution failure", err)
	}
}

// TestMCPConfigSelfSpawnNoPATH is the core regression: with PATH pointed
// at a dir holding decoy bridge binaries, the config must name the
// daemon's own canonicalized executable — never a PATH-derived path,
// never a bare name. (In the test, the test binary stands in for the
// daemon binary, so "self" is the canonicalized os.Executable().)
func TestMCPConfigSelfSpawnNoPATH(t *testing.T) {
	// Decoy bridges where a PATH lookup would find them: the old
	// resolveBridge returned these. The self-spawn config must ignore
	// them entirely.
	decoyDir := t.TempDir()
	writeFakeBridge(t, decoyDir, "pagnet-mcp")
	writeFakeBridge(t, decoyDir, "pagnet-control")
	t.Setenv("PATH", decoyDir)

	d, err := New(Config{StateDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		kind, server string
		sub          []string
	}{
		{"worker", "pagnet", []string{"mcp", "worker"}},
		{"representative", "pagnet-control", []string{"mcp", "control"}},
	} {
		raw := d.mcpConfig(&InstanceRow{
			InstanceID: "inst-1",
			NetworkID:  "net-1",
			Kind:       tc.kind,
		})
		var cfg struct {
			MCPServers map[string]struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"mcpServers"`
		}
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			t.Fatalf("%s config %q: %v", tc.kind, raw, err)
		}
		srv, ok := cfg.MCPServers[tc.server]
		if !ok {
			t.Fatalf("%s kind got servers %v, want %q", tc.kind, cfg.MCPServers, tc.server)
		}
		if srv.Command != self {
			t.Fatalf("%s command = %q, want the daemon's own executable %q", tc.kind, srv.Command, self)
		}
		wantArgs := append(append([]string{}, tc.sub...), "--socket", filepath.Join(d.StateDir, "pagnetd.sock"))
		if !reflect.DeepEqual(srv.Args, wantArgs) {
			t.Fatalf("%s args = %v, want %v", tc.kind, srv.Args, wantArgs)
		}
		// No PATH-derived value may appear anywhere in the config: the
		// decoy dir would only show up if a PATH lookup had been done.
		if strings.Contains(raw, decoyDir) {
			t.Fatalf("%s config references the PATH decoy dir: %s", tc.kind, raw)
		}
	}
}

// TestMCPConfigShape pins the full JSON shape the runtime adapters
// consume (server name, command, args, identity env): a future edit
// that renames a key or drops a field would silently break every
// adapter, so the exact structure is asserted here.
func TestMCPConfigShape(t *testing.T) {
	d, err := New(Config{StateDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(d.StateDir, "pagnetd.sock")

	for _, tc := range []struct {
		kind, server string
		sub          []string
	}{
		{"worker", "pagnet", []string{"mcp", "worker"}},
		{"representative", "pagnet-control", []string{"mcp", "control"}},
	} {
		raw := d.mcpConfig(&InstanceRow{
			InstanceID: "inst-1",
			NetworkID:  "net-1",
			Kind:       tc.kind,
		})
		var got map[string]any
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("%s config %q: %v", tc.kind, raw, err)
		}
		wantArgs := make([]any, 0, len(tc.sub)+2)
		for _, a := range tc.sub {
			wantArgs = append(wantArgs, a)
		}
		wantArgs = append(wantArgs, "--socket", sock)
		want := map[string]any{
			"mcpServers": map[string]any{
				tc.server: map[string]any{
					"command": self,
					"args":    wantArgs,
					"env": map[string]any{
						"PAGNET_INSTANCE_ID": "inst-1",
						"PAGNET_NETWORK_ID":  "net-1",
					},
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			wantRaw, _ := json.Marshal(want)
			t.Fatalf("%s config shape drifted:\n got  %s\n want %s", tc.kind, raw, wantRaw)
		}
	}
}
