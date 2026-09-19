// pagnet-release-sign signs a release manifest for the pagnet release
// pipeline. It scans a directory for the release version's tarballs
// (pagnet-<version>-<os>-<arch>.tar.gz) and the stable
// pagnet-latest-<os>-<arch>.tar.gz copies `make release` lays down
// alongside them, computes each one's sha256, builds the canonical
// manifest, signs it with the Ed25519 private key (from
// $PAGNET_RELEASE_SIGNING_KEY, the base64 seed), and writes
// pagnet-release-manifest-<version>.json.
//
// Both consumers must be able to verify what they download: the auto-updater
// (internal/release) looks up the VERSIONED tarball name, the curl|bash
// installer (install.sh) downloads the stable LATEST-named tarball and
// checks its sha256 against the manifest — so the manifest lists both, and
// each latest copy must be byte-identical to its versioned twin.
//
// The manifest is the trust anchor for the client's auto-update: the
// updater verifies this signature against the public key pinned in
// internal/release before installing anything. The private key is a GitHub
// repo secret and never ships with the client.
//
// Usage:
//
//	PAGNET_RELEASE_SIGNING_KEY=<base64 seed> \
//	  go run ./cmd/pagnet-release-sign --version v1.2.3 --dir dist
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pagnet-code/pagnet/internal/release"
)

func main() {
	var (
		version string
		dir     string
		out     string
	)
	flag.StringVar(&version, "version", "", "release version (e.g. v1.2.3); required")
	flag.StringVar(&dir, "dir", "dist", "directory containing the release tarballs")
	flag.StringVar(&out, "out", "", "output manifest path (default <dir>/pagnet-release-manifest-<version>.json)")
	flag.Parse()

	if version == "" {
		fatalf("--version is required")
	}
	seedB64 := os.Getenv("PAGNET_RELEASE_SIGNING_KEY")
	if seedB64 == "" {
		fatalf("PAGNET_RELEASE_SIGNING_KEY is not set (the base64 Ed25519 seed)")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedB64))
	if err != nil {
		fatalf("PAGNET_RELEASE_SIGNING_KEY is not valid base64: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		fatalf("PAGNET_RELEASE_SIGNING_KEY must decode to %d bytes, got %d", ed25519.SeedSize, len(seed))
	}

	assets, err := collectAssets(dir, version)
	if err != nil {
		fatalf("%v", err)
	}

	m := release.Manifest{
		Version: version,
		Created: release.Now(),
		Assets:  assets,
	}
	if err := release.SignManifest(&m, seed); err != nil {
		fatalf("sign: %v", err)
	}

	if out == "" {
		out = filepath.Join(dir, release.ManifestName(version))
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		fatalf("write: %v", err)
	}
	fmt.Printf("signed manifest for %s (%d assets) -> %s\n", version, len(assets), out)
}

// collectAssets returns the manifest's asset list for version from dir:
// every versioned tarball (pagnet-<version>-<os>-<arch>.tar.gz) AND, when
// present, the stable pagnet-latest-<os>-<arch>.tar.gz copies. Both are
// listed because both consumers must verify what they download: the
// auto-updater looks up the versioned name, the installer downloads the
// stable latest name (install.sh). A latest copy is admitted only as the
// byte-identical twin of a versioned tarball in this release — a stale or
// tampered latest copy would otherwise be signed (and then trusted) by
// the manual install path.
func collectAssets(dir, version string) ([]release.Asset, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}
	prefix := "pagnet-" + version + "-"
	var assets []release.Asset
	bySuffix := make(map[string]release.Asset) // "os-arch.tar.gz" -> versioned asset
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		sum, err := sha256File(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("sha256 %s: %w", name, err)
		}
		asset := release.Asset{Name: name, SHA256: sum}
		assets = append(assets, asset)
		bySuffix[strings.TrimPrefix(name, prefix)] = asset
	}
	if len(assets) == 0 {
		return nil, fmt.Errorf("no tarballs matching %s*.tar.gz in %s", prefix, dir)
	}
	const latestPrefix = "pagnet-latest-"
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, latestPrefix) || !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		suffix := strings.TrimPrefix(name, latestPrefix)
		twin, ok := bySuffix[suffix]
		if !ok {
			return nil, fmt.Errorf("latest copy %s has no versioned twin %s%s.tar.gz", name, prefix, suffix)
		}
		sum, err := sha256File(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("sha256 %s: %w", name, err)
		}
		if sum != twin.SHA256 {
			return nil, fmt.Errorf("latest copy %s differs from its versioned twin %s — refusing to sign", name, twin.Name)
		}
		assets = append(assets, release.Asset{Name: name, SHA256: sum})
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].Name < assets[j].Name })
	return assets, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pagnet-release-sign: "+format+"\n", args...)
	os.Exit(1)
}
