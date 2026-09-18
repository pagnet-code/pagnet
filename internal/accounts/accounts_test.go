package accounts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLegacy writes a legacy flat daemon config to <root>/config.yaml.
func writeLegacy(t *testing.T, root, content string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestMigrateLegacy: a legacy flat config migrates to the default account
// context with EVERY field preserved (no credential loss), and the
// machine-wide config is rewritten to hold only the current account.
func TestMigrateLegacy(t *testing.T) {
	root := t.TempDir()
	legacy := "serverUrl: https://cp.example\n" +
		"credential: hostcred-secret\n" +
		"hostId: h-123\n" +
		"hostName: lince\n" +
		"token: pgn-derived-secret\n" +
		"currentNetwork: backend\n"
	writeLegacy(t, root, legacy)

	migrated, err := MigrateLegacy(root)
	if err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}
	if !migrated {
		t.Fatal("MigrateLegacy = false, want true (legacy state present)")
	}

	// The legacy bytes are preserved verbatim in accounts/default/config.yaml.
	defPath := ConfigPath(root, DefaultAccount)
	got, err := os.ReadFile(defPath)
	if err != nil {
		t.Fatalf("read migrated config: %v", err)
	}
	if string(got) != legacy {
		t.Fatalf("migrated config = %q,\nwant the legacy bytes verbatim:\n%q", got, legacy)
	}
	// 0600 (the credential lives here).
	info, err := os.Stat(defPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("migrated config perms = %o, want 0600", perm)
	}

	// The machine-wide config now holds ONLY the current account (no
	// credential, no host identity).
	g, err := LoadGlobal(root)
	if err != nil {
		t.Fatalf("LoadGlobal: %v", err)
	}
	if g.CurrentAccount != DefaultAccount {
		t.Fatalf("currentAccount = %q, want %q", g.CurrentAccount, DefaultAccount)
	}
	globalBytes, _ := os.ReadFile(filepath.Join(root, "config.yaml"))
	for _, secret := range []string{"hostcred-secret", "pgn-derived-secret", "h-123"} {
		if strings.Contains(string(globalBytes), secret) {
			t.Fatalf("machine-wide config leaked %q: %s", secret, globalBytes)
		}
	}
}

// TestMigrateLegacyIdempotent: a second run is a no-op (accounts exist).
func TestMigrateLegacyIdempotent(t *testing.T) {
	root := t.TempDir()
	writeLegacy(t, root, "serverUrl: https://cp.example\ncredential: c1\n")
	if _, err := MigrateLegacy(root); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateLegacy(root)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("second MigrateLegacy = true, want false (already migrated)")
	}
}

// TestMigrateLegacyNoLegacy: an empty state dir is left untouched.
func TestMigrateLegacyNoLegacy(t *testing.T) {
	root := t.TempDir()
	migrated, err := MigrateLegacy(root)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("MigrateLegacy on an empty dir = true, want false")
	}
}

// TestMigrateLegacyNonLegacy: a config that already holds only the global
// fields (currentAccount/labels) is not legacy and is left alone.
func TestMigrateLegacyNonLegacy(t *testing.T) {
	root := t.TempDir()
	writeLegacy(t, root, "currentAccount: default\n")
	migrated, err := MigrateLegacy(root)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("MigrateLegacy on a non-legacy config = true, want false")
	}
}

// TestActiveAccount: the --account override wins, then currentAccount, then
// the default.
func TestActiveAccount(t *testing.T) {
	root := t.TempDir()
	if got := ActiveAccount(root, "work"); got != "work" {
		t.Fatalf("override = %q, want work", got)
	}
	if got := ActiveAccount(root, ""); got != DefaultAccount {
		t.Fatalf("no current = %q, want %q", got, DefaultAccount)
	}
	if err := SetCurrent(root, "work"); err != nil {
		t.Fatal(err)
	}
	if got := ActiveAccount(root, ""); got != "work" {
		t.Fatalf("current = %q, want work", got)
	}
	// The override still wins over the current account.
	if got := ActiveAccount(root, "personal"); got != "personal" {
		t.Fatalf("override over current = %q, want personal", got)
	}
}

// TestTwoAccountsSeparateDirs: two accounts on the same server have separate
// config dirs (their credentials + host identity never share a file).
func TestTwoAccountsSeparateDirs(t *testing.T) {
	root := t.TempDir()
	personal := ConfigDir(root, "personal")
	work := ConfigDir(root, "work")
	if personal == work {
		t.Fatalf("personal and work share a dir: %s", personal)
	}
	for _, dir := range []string{personal, work} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(ConfigPath(root, "personal"), []byte("serverUrl: https://cp.example\ncredential: personal-cred\nhostId: h-p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ConfigPath(root, "work"), []byte("serverUrl: https://cp.example\ncredential: work-cred\nhostId: h-w\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pb, _ := os.ReadFile(ConfigPath(root, "personal"))
	wb, _ := os.ReadFile(ConfigPath(root, "work"))
	if string(pb) == string(wb) {
		t.Fatal("the two accounts' configs are identical — they must stay separate")
	}
	if !strings.Contains(string(pb), "personal-cred") || !strings.Contains(string(wb), "work-cred") {
		t.Fatal("each account must keep its own credential")
	}
}

// TestValidateName: the slug rules.
func TestValidateName(t *testing.T) {
	for _, ok := range []string{"default", "work", "personal", "a.b-c_1"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("ValidateName(%q) = %v, want ok", ok, err)
		}
	}
	for _, bad := range []string{"", "Work", "has space", "-lead", "a/b", strings.Repeat("a", 65)} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("ValidateName(%q) = nil, want an error", bad)
		}
	}
}
