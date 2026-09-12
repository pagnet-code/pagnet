package daemon

import (
	"archive/tar"
	"compress/gzip"
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

// --- the bridges must arrive with the release -----------------------------------
// Resolution is worthless if the host never received the binary. A worker
// gets its binaries one of two ways: install.sh unpacking the whole tarball,
// or a self-update — which extracted pagnetd only, so an auto-updated worker
// could never gain a bridge at all.

func writeReleaseTarball(t *testing.T, dir string, names ...string) string {
	t.Helper()
	path := filepath.Join(dir, "release.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, n := range names {
		body := []byte("#!/bin/sh\n# " + n + "\n")
		hdr := &tar.Header{Name: n, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractReleaseBinaries(t *testing.T) {
	t.Run("keeps pagnetd and both bridges, leaves the rest", func(t *testing.T) {
		tarPath := writeReleaseTarball(t, t.TempDir(),
			"pagnet", "pagnetd", "pagnet-mcp", "pagnet-control", "pagnet-fake-runtime", "README")
		out := t.TempDir()
		got, err := extractReleaseBinaries(tarPath, out)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if want := filepath.Join(out, "pagnetd"); got != want {
			t.Fatalf("returned %q, want %q", got, want)
		}
		// The CLI may be running in the operator's shell and the fake runtime
		// is --debug-only: a self-update must not swap either out.
		for _, n := range bridgeBinaries {
			st, err := os.Stat(filepath.Join(out, n))
			if err != nil {
				t.Fatalf("bridge %s not extracted: %v", n, err)
			}
			if st.Mode().Perm()&0o100 == 0 {
				t.Fatalf("bridge %s is not executable: %v", n, st.Mode())
			}
		}
		for _, n := range []string{"pagnet", "pagnet-fake-runtime", "README"} {
			if _, err := os.Stat(filepath.Join(out, n)); err == nil {
				t.Fatalf("%s must not be extracted by a self-update", n)
			}
		}
	})

	t.Run("a pre-bridge tarball still updates", func(t *testing.T) {
		tarPath := writeReleaseTarball(t, t.TempDir(), "pagnet", "pagnetd", "pagnet-fake-runtime")
		if _, err := extractReleaseBinaries(tarPath, t.TempDir()); err != nil {
			t.Fatalf("old tarball must not break the update: %v", err)
		}
	})

	t.Run("no pagnetd is fatal", func(t *testing.T) {
		tarPath := writeReleaseTarball(t, t.TempDir(), "pagnet", "pagnet-mcp")
		if _, err := extractReleaseBinaries(tarPath, t.TempDir()); err == nil {
			t.Fatal("want an error when the tarball has no pagnetd")
		}
	})
}

func TestInstallBridges(t *testing.T) {
	newDaemon := func(t *testing.T) *Daemon {
		t.Helper()
		d, err := New(Config{StateDir: t.TempDir()}, nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { d.Close() })
		return d
	}

	t.Run("installs beside the daemon binary", func(t *testing.T) {
		d := newDaemon(t)
		staging := d.updateStagingDir()
		if err := os.MkdirAll(staging, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, n := range bridgeBinaries {
			writeFakeBridge(t, staging, n)
		}
		install := t.TempDir()
		d.installBridges(install)
		for _, n := range bridgeBinaries {
			st, err := os.Stat(filepath.Join(install, n))
			if err != nil {
				t.Fatalf("%s not installed next to pagnetd: %v", n, err)
			}
			if st.Mode().Perm()&0o100 == 0 {
				t.Fatalf("%s installed non-executable: %v", n, st.Mode())
			}
		}
	})

	t.Run("nothing staged leaves the install dir untouched", func(t *testing.T) {
		d := newDaemon(t)
		install := t.TempDir()
		d.installBridges(install) // an old tarball: warn, never fail, never fabricate
		entries, err := os.ReadDir(install)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("install dir got %v from an empty staging dir", entries)
		}
	})

	t.Run("running from the staging copy is a no-op", func(t *testing.T) {
		d := newDaemon(t)
		staging := d.updateStagingDir()
		if err := os.MkdirAll(staging, 0o700); err != nil {
			t.Fatal(err)
		}
		kept := writeFakeBridge(t, staging, "pagnet-mcp")
		d.installBridges(staging) // must not copy a file onto itself and lose it
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("staged bridge was destroyed: %v", err)
		}
	})
}
