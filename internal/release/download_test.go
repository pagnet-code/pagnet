package release

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

// newDownloadServer serves a release manifest and a tarball from an
// in-memory control-plane /download/ endpoint. manifestJSON may be "" to
// make the manifest 404 (the missing-manifest case).
func newDownloadServer(t *testing.T, version, manifestJSON, tarball string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/download/" + ManifestName(version):
			if manifestJSON == "" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(manifestJSON))
		case "/download/" + TarballNameFor(version, runtime.GOOS, runtime.GOARCH):
			_, _ = w.Write([]byte(tarball))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

// A manifest whose signature does not verify is refused BEFORE the tarball
// is downloaded: the update is refused with a clean error and nothing is
// written to dst. This is the core tamper-resistance guarantee.
func TestDownloadVerified_RefusesBadSignature(t *testing.T) {
	t.Setenv(EnvAllowUnsigned, "")
	m := Manifest{
		Version:   "v1.2.3",
		Created:   "2026-09-16T00:00:00Z",
		Assets:    []Asset{{Name: TarballNameFor("v1.2.3", runtime.GOOS, runtime.GOARCH), SHA256: "deadbeef"}},
		KeyID:     KeyID,
		Signature: "not-a-real-signature",
	}
	b, _ := json.Marshal(&m)
	ts := newDownloadServer(t, "v1.2.3", string(b), "tarball-bytes")

	dst := t.TempDir() + "/refused.tar.gz"
	err := DownloadVerified(ts.URL, "v1.2.3", dst, false)
	if err == nil {
		t.Fatal("a manifest with a bad signature must be refused")
	}
	if !strings.Contains(err.Error(), "not trustworthy") {
		t.Fatalf("expected a trust refusal, got: %v", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("the tarball must not be downloaded when the manifest is untrusted: %v", statErr)
	}
}

// A missing manifest (404) is refused with a clean error.
func TestDownloadVerified_RefusesMissingManifest(t *testing.T) {
	t.Setenv(EnvAllowUnsigned, "")
	ts := newDownloadServer(t, "v9.9.9", "", "tarball-bytes")
	err := DownloadVerified(ts.URL, "v9.9.9", t.TempDir()+"/x.tar.gz", false)
	if err == nil {
		t.Fatal("a missing manifest must be refused")
	}
	if !strings.Contains(err.Error(), "no release manifest") {
		t.Fatalf("expected a missing-manifest error, got: %v", err)
	}
}

// The dev-only unsigned fallback (PAGNET_ALLOW_UNSIGNED_RELEASES=1) skips
// verification and downloads the tarball. This is how a local dev control
// plane that serves unsigned builds can still be updated.
func TestDownloadVerified_UndersignedFallbackDownloads(t *testing.T) {
	t.Setenv(EnvAllowUnsigned, "1")
	m := Manifest{
		Version:   "v1.2.3",
		Created:   "2026-09-16T00:00:00Z",
		Assets:    []Asset{{Name: TarballNameFor("v1.2.3", runtime.GOOS, runtime.GOARCH), SHA256: "whatever"}},
		KeyID:     KeyID,
		Signature: "skipped",
	}
	b, _ := json.Marshal(&m)
	const tarball = "the-tarball-bytes"
	ts := newDownloadServer(t, "v1.2.3", string(b), tarball)

	dst := t.TempDir() + "/release.tar.gz"
	if err := DownloadVerified(ts.URL, "v1.2.3", dst, false); err != nil {
		t.Fatalf("the unsigned fallback must download: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != tarball {
		t.Fatalf("downloaded %q, want the served tarball", got)
	}
}

// The HTTPS policy is enforced on the release download: a non-loopback
// plain-HTTP server URL is refused (the httptest server is loopback, so
// this asserts the loopback allowance; the non-loopback refusal is covered
// by the netpolicy tests).
func TestDownloadVerified_AllowsLoopbackHTTP(t *testing.T) {
	t.Setenv(EnvAllowUnsigned, "1")
	m := Manifest{
		Version:   "v1.2.3",
		Created:   "2026-09-16T00:00:00Z",
		Assets:    []Asset{{Name: TarballNameFor("v1.2.3", runtime.GOOS, runtime.GOARCH), SHA256: "x"}},
		KeyID:     KeyID,
		Signature: "skipped",
	}
	b, _ := json.Marshal(&m)
	ts := newDownloadServer(t, "v1.2.3", string(b), "bytes")
	// ts.URL is http://127.0.0.1:PORT (loopback) — must be allowed.
	if err := DownloadVerified(ts.URL, "v1.2.3", t.TempDir()+"/r.tar.gz", false); err != nil {
		t.Fatalf("loopback http must be allowed for release download: %v", err)
	}
}

// DownloadLatestVerified resolves the version from the latest manifest and
// downloads the versioned tarball.
func TestDownloadLatestVerified_ResolvesVersion(t *testing.T) {
	t.Setenv(EnvAllowUnsigned, "1")
	const version = "v2.0.0"
	m := Manifest{
		Version:   version,
		Created:   "2026-09-16T00:00:00Z",
		Assets:    []Asset{{Name: TarballNameFor(version, runtime.GOOS, runtime.GOARCH), SHA256: "x"}},
		KeyID:     KeyID,
		Signature: "skipped",
	}
	b, _ := json.Marshal(&m)
	const tarball = "latest-tarball-bytes"
	// Serve the manifest under the "latest" name and the tarball under the
	// versioned name (the layout the release pipeline publishes).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/download/" + ManifestName("latest"):
			_, _ = w.Write(b)
		case "/download/" + TarballNameFor(version, runtime.GOOS, runtime.GOARCH):
			_, _ = w.Write([]byte(tarball))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)

	dst := t.TempDir() + "/release.tar.gz"
	if err := DownloadLatestVerified(ts.URL, dst, false); err != nil {
		t.Fatalf("latest verified download: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != tarball {
		t.Fatalf("downloaded %q, want the versioned tarball", got)
	}
}
