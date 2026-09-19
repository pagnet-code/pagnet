package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTarball(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// collectAssets: versioned tarballs + their byte-identical pagnet-latest-*
// twins are both listed (the auto-updater verifies the versioned name, the
// installer verifies the stable latest name).

func TestCollectAssetsVersionedAndLatest(t *testing.T) {
	dir := t.TempDir()
	writeTarball(t, dir, "pagnet-v1.2.3-linux-amd64.tar.gz", "linux-amd64-bytes")
	writeTarball(t, dir, "pagnet-v1.2.3-darwin-arm64.tar.gz", "darwin-arm64-bytes")
	// The stable copies: byte-identical twins (make release is a plain cp).
	writeTarball(t, dir, "pagnet-latest-linux-amd64.tar.gz", "linux-amd64-bytes")
	writeTarball(t, dir, "pagnet-latest-darwin-arm64.tar.gz", "darwin-arm64-bytes")
	// Unrelated files must be ignored.
	writeTarball(t, dir, "pagnet-v0.9.0-linux-amd64.tar.gz", "older release")
	writeTarball(t, dir, "notes.txt", "not a tarball")

	assets, err := collectAssets(dir, "v1.2.3")
	if err != nil {
		t.Fatalf("collectAssets: %v", err)
	}
	if len(assets) != 4 {
		t.Fatalf("want 4 assets (2 versioned + 2 latest), got %d: %v", len(assets), assets)
	}
	// Sorted by name: latest-* before v1.2.3-*.
	wantNames := []string{
		"pagnet-latest-darwin-arm64.tar.gz",
		"pagnet-latest-linux-amd64.tar.gz",
		"pagnet-v1.2.3-darwin-arm64.tar.gz",
		"pagnet-v1.2.3-linux-amd64.tar.gz",
	}
	for i, name := range wantNames {
		if assets[i].Name != name {
			t.Errorf("asset[%d].Name = %s, want %s", i, assets[i].Name, name)
		}
		got, err := sha256File(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("sha256File %s: %v", name, err)
		}
		if assets[i].SHA256 != got {
			t.Errorf("asset[%d].SHA256 = %s, want %s", i, assets[i].SHA256, got)
		}
	}
	// Each latest entry must carry the hash of its versioned twin.
	byName := make(map[string]string, len(assets))
	for _, a := range assets {
		byName[a.Name] = a.SHA256
	}
	if byName["pagnet-latest-linux-amd64.tar.gz"] != byName["pagnet-v1.2.3-linux-amd64.tar.gz"] {
		t.Error("latest entry must carry its versioned twin's hash (linux/amd64)")
	}
	if byName["pagnet-latest-darwin-arm64.tar.gz"] != byName["pagnet-v1.2.3-darwin-arm64.tar.gz"] {
		t.Error("latest entry must carry its versioned twin's hash (darwin/arm64)")
	}
}

func TestCollectAssetsNoLatestCopies(t *testing.T) {
	// A dir with only the versioned tarballs is still valid: the manifest
	// covers the updater; the installer warns (it does what it always did
	// for a manifest without the stable name).
	dir := t.TempDir()
	writeTarball(t, dir, "pagnet-v1.2.3-linux-amd64.tar.gz", "bytes")
	assets, err := collectAssets(dir, "v1.2.3")
	if err != nil {
		t.Fatalf("collectAssets: %v", err)
	}
	if len(assets) != 1 || assets[0].Name != "pagnet-v1.2.3-linux-amd64.tar.gz" {
		t.Fatalf("want exactly the versioned asset, got %v", assets)
	}
}

func TestCollectAssetsStaleLatestRefused(t *testing.T) {
	// A latest copy that is NOT the byte-identical twin of the versioned
	// tarball (a stale copy from an earlier build) must not be signed:
	// signing it would make the manual install path trust the wrong bytes.
	dir := t.TempDir()
	writeTarball(t, dir, "pagnet-v1.2.3-linux-amd64.tar.gz", "new-bytes")
	writeTarball(t, dir, "pagnet-latest-linux-amd64.tar.gz", "STALE-bytes")
	if _, err := collectAssets(dir, "v1.2.3"); err == nil {
		t.Fatal("want an error for a stale latest copy, got nil")
	}
}

func TestCollectAssetsLatestWithoutTwin(t *testing.T) {
	// A latest copy whose versioned twin is absent from this release is a
	// broken layout (make release always writes both) — refuse.
	dir := t.TempDir()
	writeTarball(t, dir, "pagnet-v1.2.3-linux-amd64.tar.gz", "bytes")
	writeTarball(t, dir, "pagnet-latest-darwin-amd64.tar.gz", "orphan")
	if _, err := collectAssets(dir, "v1.2.3"); err == nil {
		t.Fatal("want an error for a latest copy without its versioned twin, got nil")
	}
}

func TestCollectAssetsNoTarballs(t *testing.T) {
	dir := t.TempDir()
	writeTarball(t, dir, "pagnet-latest-linux-amd64.tar.gz", "orphan")
	if _, err := collectAssets(dir, "v1.2.3"); err == nil {
		t.Fatal("want an error when no versioned tarball exists, got nil")
	}
}
