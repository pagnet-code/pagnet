package main

// `pagnet update` (packaging migration, step 6): the manual self-update
// against a local fake release server — the binary on disk is replaced
// with the tarball's pagnet member, a wrong artifact is refused without
// touching the install, and the daemon-liveness probe distinguishes a
// live daemon from a stale socket file.

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pagnet-code/pagnet/internal/release"
)

// writeUpdateTarball builds a flat pagnet-*.tar.gz with the given member
// names (each a tiny shell script) in dir.
func writeUpdateTarball(t *testing.T, dir string, names ...string) string {
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

// fakeReleaseServer serves the layout the verified updater expects: a
// release manifest at /download/pagnet-release-manifest-latest.json (with
// the given version) and the versioned platform tarball at
// /download/pagnet-<version>-<os>-<arch>.tar.gz. The manifest is unsigned
// (garbage signature): the tests exercise the download/extract mechanics
// via the dev-only PAGNET_ALLOW_UNSIGNED_RELEASES fallback, and the
// signature-verification path is covered by the internal/release tests.
func fakeReleaseServer(t *testing.T, version, tarPath string) *httptest.Server {
	t.Helper()
	manifest := release.Manifest{
		Version:   version,
		Created:   "2026-09-16T00:00:00Z",
		Assets:    []release.Asset{{Name: release.TarballNameFor(version, runtime.GOOS, runtime.GOARCH), SHA256: "unsigned"}},
		KeyID:     release.KeyID,
		Signature: "unsigned-test-manifest",
	}
	mb, _ := json.Marshal(&manifest)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/download/" + release.ManifestName("latest"):
			_, _ = w.Write(mb)
		case "/download/" + release.TarballNameFor(version, runtime.GOOS, runtime.GOARCH):
			http.ServeFile(w, r, tarPath)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestUpdateBinaryAt(t *testing.T) {
	const version = "v1.2.3"
	t.Setenv(release.EnvAllowUnsigned, "1")
	tarPath := writeUpdateTarball(t, t.TempDir(), "pagnet", "LICENSE", "README.md")
	ts := fakeReleaseServer(t, version, tarPath)

	install := t.TempDir()
	fake := filepath.Join(install, "pagnet")
	if err := os.WriteFile(fake, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := updateBinaryAt(ts.URL, fake); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := os.ReadFile(fake)
	if err != nil {
		t.Fatal(err)
	}
	if want := "#!/bin/sh\n# pagnet\n"; string(got) != want {
		t.Fatalf("replaced with %q, want the tarball's pagnet member", got)
	}
	st, err := os.Stat(fake)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("replaced binary mode = %v, want 0755", st.Mode())
	}
	// No staging leftovers in the install dir.
	entries, err := os.ReadDir(install)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("install dir has %d entries, want exactly 1 (the binary)", len(entries))
	}
}

func TestUpdateBinaryAt_MissingBinary(t *testing.T) {
	// A tarball without the pagnet member (a foreign or broken artifact):
	// the update fails and the installed binary is left untouched —
	// never a partial replace.
	const version = "v1.2.3"
	t.Setenv(release.EnvAllowUnsigned, "1")
	tarPath := writeUpdateTarball(t, t.TempDir(), "pagnetd", "pagnet-mcp")
	ts := fakeReleaseServer(t, version, tarPath)

	install := t.TempDir()
	fake := filepath.Join(install, "pagnet")
	if err := os.WriteFile(fake, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := updateBinaryAt(ts.URL, fake); err == nil {
		t.Fatal("want an error when the tarball has no pagnet member")
	}
	got, err := os.ReadFile(fake)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old binary" {
		t.Fatalf("a failed update touched the installed binary: %q", got)
	}
}

func TestUpdateBinaryAt_DownloadError(t *testing.T) {
	// The server serves no manifest (404): the verified updater refuses
	// before downloading anything; clean error, target untouched.
	t.Setenv(release.EnvAllowUnsigned, "")
	ts := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)

	install := t.TempDir()
	fake := filepath.Join(install, "pagnet")
	if err := os.WriteFile(fake, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := updateBinaryAt(ts.URL, fake); err == nil {
		t.Fatal("want an error when the manifest 404s")
	}
	got, err := os.ReadFile(fake)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old binary" {
		t.Fatalf("a failed update touched the installed binary: %q", got)
	}
}

// TestDaemonRunning: the liveness probe behind the restart hint — a live
// daemon answers the auth probe, a stale socket file (crashed daemon)
// does not, and no socket file at all is not running.
func TestDaemonRunning(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "pagnetd.sock")

	t.Run("no socket", func(t *testing.T) {
		if daemonRunning(dir) {
			t.Fatal("no socket file: must report not running")
		}
	})
	t.Run("stale socket", func(t *testing.T) {
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		_ = l.Close() // leaves the socket file behind, no listener
		if daemonRunning(dir) {
			t.Fatal("stale socket (no listener): must report not running")
		}
	})
	t.Run("live daemon", func(t *testing.T) {
		_ = os.Remove(sock)
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return // listener closed
				}
				go func(c net.Conn) {
					defer c.Close()
					buf := make([]byte, 256)
					_, _ = c.Read(buf)
					_, _ = c.Write([]byte(`{"type":"error","error":"unknown instance"}` + "\n"))
				}(c)
			}
		}()
		if !daemonRunning(dir) {
			t.Fatal("live daemon: must report running")
		}
	})
}
