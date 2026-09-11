package daemon

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// --- resolveBridge / mcpConfig -----------------------------------------------
// A bare bridge name is a PATH lookup performed by the RUNTIME, which
// inherits the daemon's PATH unchanged. A daemon started from a source
// checkout (or any environment where ~/.local/bin never reached PATH —
// install.sh only nags about it) therefore spawned nothing and the instance
// came up with no network tools and no error. These tests pin the
// resolution to something the operator never has to fix by hand.

func writeFakeBridge(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolveBridge(t *testing.T) {
	t.Run("PATH hit wins and comes back absolute", func(t *testing.T) {
		want := writeFakeBridge(t, t.TempDir(), "pagnet-mcp")
		t.Setenv("PATH", filepath.Dir(want))
		if got := resolveBridge("pagnet-mcp"); got != want {
			t.Fatalf("resolveBridge = %q, want %q", got, want)
		}
	})

	t.Run("falls back to the directory holding the daemon", func(t *testing.T) {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		// The test binary stands in for pagnetd: a bridge beside it is what
		// the release tarball and a `make build` checkout both provide.
		want := writeFakeBridge(t, filepath.Dir(exe), "pagnet-control")
		t.Cleanup(func() { os.Remove(want) })
		t.Setenv("PATH", t.TempDir()) // an empty PATH: nothing to find there
		if got := resolveBridge("pagnet-control"); got != want {
			t.Fatalf("resolveBridge = %q, want %q", got, want)
		}
	})

	t.Run("nothing found keeps the bare name", func(t *testing.T) {
		// No PATH hit, and the daemon's own dir holds no bridge: return the
		// name unchanged so the spawn failure surfaces where it used to
		// rather than being masked by a path to a file that is not there.
		t.Setenv("PATH", t.TempDir())
		if got := resolveBridge("pagnet-mcp"); got != "pagnet-mcp" {
			t.Fatalf("resolveBridge = %q, want the bare name", got)
		}
	})
}

func TestMCPConfigCommandsAreResolvable(t *testing.T) {
	worker := writeFakeBridge(t, t.TempDir(), "pagnet-mcp")
	control := writeFakeBridge(t, filepath.Dir(worker), "pagnet-control")
	t.Setenv("PATH", filepath.Dir(worker))

	d, err := New(Config{StateDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	for _, tc := range []struct {
		kind, server, command string
	}{
		{"worker", "pagnet", worker},
		{"representative", "pagnet-control", control},
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
		if srv.Command != tc.command {
			t.Fatalf("%s command = %q, want the resolved %q", tc.kind, srv.Command, tc.command)
		}
		if !filepath.IsAbs(srv.Command) {
			t.Fatalf("%s command %q is not absolute", tc.kind, srv.Command)
		}
		wantSocket := []string{"--socket", filepath.Join(d.StateDir, "pagnetd.sock")}
		if len(srv.Args) != 2 || srv.Args[0] != wantSocket[0] || srv.Args[1] != wantSocket[1] {
			t.Fatalf("%s args = %v, want %v", tc.kind, srv.Args, wantSocket)
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
