// pagnet-release-sign signs a release manifest for the pagnet release
// pipeline. It scans a directory for the release version's tarballs
// (pagnet-<version>-<os>-<arch>.tar.gz), computes each one's sha256, builds
// the canonical manifest, signs it with the Ed25519 private key (from
// $PAGNET_RELEASE_SIGNING_KEY, the base64 seed), and writes
// pagnet-release-manifest-<version>.json.
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

	// Collect the version's tarballs: pagnet-<version>-<os>-<arch>.tar.gz.
	// The pagnet-latest-* copies are excluded (they are byte-identical to
	// the versioned tarballs and are not manifest assets).
	entries, err := os.ReadDir(dir)
	if err != nil {
		fatalf("read dir: %v", err)
	}
	prefix := "pagnet-" + version + "-"
	var assets []release.Asset
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		sum, err := sha256File(filepath.Join(dir, name))
		if err != nil {
			fatalf("sha256 %s: %v", name, err)
		}
		assets = append(assets, release.Asset{Name: name, SHA256: sum})
	}
	if len(assets) == 0 {
		fatalf("no tarballs matching %s*.tar.gz in %s", prefix, dir)
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].Name < assets[j].Name })

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
