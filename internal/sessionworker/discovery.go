package sessionworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// LoadControllerBootstrap discovers an existing owner-local worker without
// creating state, taking its ownership lock, or opening its SQLite journal.
// The expected authority comes from the authenticated controller, never from
// the manifest. Callers must clear the returned key after mutual authentication.
func LoadControllerBootstrap(dir string, expected Scope) (Bootstrap, []byte, error) {
	fail := func() (Bootstrap, []byte, error) {
		return Bootstrap{}, nil, errors.New("existing private worker identity is unavailable or mismatched")
	}
	if !filepath.IsAbs(dir) || expected.InstanceID == "" || expected.Generation == "" || expected.AccountID == "" || expected.TenantID == "" || expected.HostID == "" || expected.ServerURL == "" {
		return fail()
	}
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (p == filepath.Clean(dir) && info.Mode().Perm() != 0700) {
			return fail()
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	raw, err := readPrivateFile(filepath.Join(dir, "bootstrap.json"), 128<<10)
	if err != nil {
		return fail()
	}
	var b Bootstrap
	if decodeClosed(raw, &b) != nil || b.Protocol != Protocol || b.Scope != expected {
		return fail()
	}
	key, err := readPrivateFile(filepath.Join(dir, "control.key"), 32)
	if err != nil || len(key) != 32 {
		clear(key)
		return fail()
	}
	return b, key, nil
}

// NativeProfileFingerprint binds the immutable profile in the manifest to a
// fresh worker snapshot. Native environment values remain memory-only.
func NativeProfileFingerprint(spec NativeSpec) string {
	raw, _ := json.Marshal(spec)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
