// Signed release manifests (client-hardening wave 2).
//
// Every release publishes, alongside its tarballs, a manifest
// (pagnet-release-manifest-<version>.json) carrying the sha256 of each
// asset and an Ed25519 signature over the manifest's canonical JSON. The
// auto-updater and `pagnet update` verify the signature against the
// pinned public key BEFORE installing anything: a release that is not
// signed by the pinned key — or whose tarball does not hash to the
// manifest — is refused with a clean error and the current build keeps
// running. This is the default and only production update path.
//
// The signature covers the canonical JSON of the manifest with the
// signature and keyId fields removed: object keys sorted alphabetically
// at every level, no whitespace, arrays in order. Canonicalization is
// lossless with respect to the on-disk formatting, so a pretty-printed or
// re-key-ordered manifest file still verifies against the same signature.
//
// The dev-only escape hatch PAGNET_ALLOW_UNSIGNED_RELEASES=1 skips
// verification (env only, no flag) and prints a loud one-line warning to
// stderr each time it is honored. It exists so a local dev control plane
// that serves unsigned builds can still be updated; it is never for
// production.

package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/internal/netpolicy"
)

// KeyID identifies the pinned release-signing key. A manifest whose keyId
// does not match is refused even if the signature verifies (a different
// key must never be silently accepted).
const KeyID = "pagnet-2026-09"

// releasePublicKey is the base64 Ed25519 PUBLIC key pinned into the
// client. It verifies every release manifest. The matching private key is
// a GitHub repo secret (PAGNET_RELEASE_SIGNING_KEY) and never ships with
// the client.
const releasePublicKey = "6GcJMXDi8Itn4ei8cAogMXwKu/3IJimZT48y3Lfxscw="

// EnvAllowUnsigned is the dev-only environment variable that permits
// skipping release-manifest verification (off by default; env only).
const EnvAllowUnsigned = "PAGNET_ALLOW_UNSIGNED_RELEASES"

// Manifest is a signed release manifest, published alongside the release
// tarballs as pagnet-release-manifest-<version>.json.
type Manifest struct {
	Version   string  `json:"version"`
	Created   string  `json:"created"`
	Assets    []Asset `json:"assets"`
	KeyID     string  `json:"keyId"`
	Signature string  `json:"signature"`
}

// Asset is one release artifact: its served name and the sha256 of its
// bytes (lowercase hex).
type Asset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// ManifestName is the served name of the release manifest for version
// (version may be "latest" for the stable copy published alongside the
// pagnet-latest-* tarballs).
func ManifestName(version string) string {
	return "pagnet-release-manifest-" + version + ".json"
}

// TarballNameFor is the served name of the versioned release tarball for
// version on goos/goarch.
func TarballNameFor(version, goos, goarch string) string {
	return "pagnet-" + version + "-" + goos + "-" + goarch + ".tar.gz"
}

// CanonicalJSON returns the canonical JSON bytes of the manifest with the
// signature and keyId fields removed: object keys sorted alphabetically at
// every level, no whitespace, arrays in order. This is the exact byte
// string the Ed25519 signature covers. json.Marshal sorts map keys, so the
// output is deterministic and independent of the manifest's on-disk
// formatting.
func CanonicalJSON(m Manifest) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		return nil, err
	}
	delete(generic, "keyId")
	delete(generic, "signature")
	return json.Marshal(generic)
}

// SignManifest sets m.KeyID and m.Signature: the Ed25519 signature of
// CanonicalJSON(m) under the private key with seed (ed25519.SeedSize
// bytes). Used by the release signing tool, not by the updater.
func SignManifest(m *Manifest, seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("signing key seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	canon, err := CanonicalJSON(*m)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), canon)
	m.KeyID = KeyID
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyManifest verifies that m.KeyID matches the pinned key and that the
// Ed25519 signature over CanonicalJSON(m) is valid under the pinned public
// key. Any mismatch is an error: the manifest is not trustworthy.
func VerifyManifest(m *Manifest) error {
	pub, err := base64.StdEncoding.DecodeString(releasePublicKey)
	if err != nil {
		return fmt.Errorf("pinned public key is not valid base64: %w", err)
	}
	return verifyManifestWithKey(m, ed25519.PublicKey(pub), KeyID)
}

// verifyManifestWithKey is the key-parameterized core of VerifyManifest:
// it checks m.KeyID against keyID and the Ed25519 signature over
// CanonicalJSON(m) against pub. Split out so the verification logic is
// unit-testable with a test keypair (the production path pins the release
// key).
func verifyManifestWithKey(m *Manifest, pub ed25519.PublicKey, keyID string) error {
	if m.KeyID != keyID {
		return fmt.Errorf("manifest keyId %q does not match the expected key %q", m.KeyID, keyID)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("manifest signature is not valid base64: %w", err)
	}
	canon, err := CanonicalJSON(*m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canon, sig) {
		return errors.New("manifest signature verification failed")
	}
	return nil
}

// VerifyAsset reports whether data's sha256 matches the manifest's entry
// for name. A missing asset or a hash mismatch is an error.
func (m *Manifest) VerifyAsset(name string, data []byte) error {
	for _, a := range m.Assets {
		if a.Name != name {
			continue
		}
		got := sha256.Sum256(data)
		gotHex := hex.EncodeToString(got[:])
		if !strings.EqualFold(gotHex, a.SHA256) {
			return fmt.Errorf("sha256 mismatch for %s: downloaded %s, manifest has %s", name, gotHex, a.SHA256)
		}
		return nil
	}
	return fmt.Errorf("asset %s not listed in the release manifest", name)
}

// allowUnsignedReleases reports whether the dev-only
// PAGNET_ALLOW_UNSIGNED_RELEASES opt-in is set.
func allowUnsignedReleases() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvAllowUnsigned))) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// warnUnsigned prints the loud one-line warning to stderr. It is printed
// EACH time the unsigned fallback is honored (not once per process) so a
// dev loop that keeps updating unsigned cannot drift into complacency.
func warnUnsigned() {
	fmt.Fprintln(os.Stderr,
		"pagnet: WARNING: PAGNET_ALLOW_UNSIGNED_RELEASES=1 — release manifest "+
			"verification SKIPPED (development only, never for production)")
}

// fetchManifest downloads the manifest for version from serverURL's
// /download/ and, unless allowUnsigned, verifies it (keyId + signature).
func fetchManifest(serverURL, version string, allowUnsigned bool) (*Manifest, error) {
	u := strings.TrimSuffix(serverURL, "/") + "/download/" + ManifestName(version)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: DownloadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no release manifest for version %s at %s", version, u)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch release manifest: http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse release manifest: %w", err)
	}
	if allowUnsigned {
		warnUnsigned()
		return &m, nil
	}
	if err := VerifyManifest(&m); err != nil {
		return nil, fmt.Errorf("release manifest for %s is not trustworthy: %w", version, err)
	}
	return &m, nil
}

// downloadFile fetches serverURL/download/name into dst.
func downloadFile(serverURL, name, dst string) error {
	u := strings.TrimSuffix(serverURL, "/") + "/download/" + name
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: DownloadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, werr := io.Copy(f, resp.Body)
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	return werr
}

// verifyDownloaded checks the sha256 of the file at dst against the
// manifest's entry for name.
func verifyDownloaded(m *Manifest, name, dst string) error {
	data, err := os.ReadFile(dst)
	if err != nil {
		return err
	}
	return m.VerifyAsset(name, data)
}

// DownloadVerified is the production update path for a KNOWN version: it
// enforces the HTTPS policy on serverURL, fetches and verifies the signed
// manifest for version, downloads the platform's versioned tarball, and
// verifies its sha256 against the manifest. Any failure is a clean error
// and the update is refused. The dev-only PAGNET_ALLOW_UNSIGNED_RELEASES=1
// env skips verification (with a loud warning) for local dev control
// planes.
func DownloadVerified(serverURL, version, dst string, flagInsecure bool) error {
	if err := netpolicy.Check(serverURL, flagInsecure); err != nil {
		return err
	}
	allowUnsigned := allowUnsignedReleases()
	m, err := fetchManifest(serverURL, version, allowUnsigned)
	if err != nil {
		return err
	}
	tarName := TarballNameFor(version, runtime.GOOS, runtime.GOARCH)
	if err := downloadFile(serverURL, tarName, dst); err != nil {
		return fmt.Errorf("download %s: %w", tarName, err)
	}
	if allowUnsigned {
		return nil
	}
	return verifyDownloaded(m, tarName, dst)
}

// DownloadLatestVerified is the production update path when the version is
// NOT known (the manual `pagnet update` command): it enforces the HTTPS
// policy, fetches and verifies the stable pagnet-release-manifest-latest
// manifest, resolves the version from it, then downloads and verifies the
// versioned platform tarball. The latest manifest is a copy of the current
// version's manifest, so its assets name the versioned tarballs.
func DownloadLatestVerified(serverURL, dst string, flagInsecure bool) error {
	if err := netpolicy.Check(serverURL, flagInsecure); err != nil {
		return err
	}
	allowUnsigned := allowUnsignedReleases()
	m, err := fetchManifest(serverURL, "latest", allowUnsigned)
	if err != nil {
		return err
	}
	if m.Version == "" {
		return errors.New("latest release manifest has no version")
	}
	tarName := TarballNameFor(m.Version, runtime.GOOS, runtime.GOARCH)
	if err := downloadFile(serverURL, tarName, dst); err != nil {
		return fmt.Errorf("download %s: %w", tarName, err)
	}
	if allowUnsigned {
		return nil
	}
	return verifyDownloaded(m, tarName, dst)
}

// Now is the manifest's created timestamp source (RFC3339, UTC). Split out
// so the signing tool and tests share one clock format.
func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
