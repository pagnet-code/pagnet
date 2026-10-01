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

func TestGlobalAccountStateRejectsFlatAndMalformedConfig(t *testing.T) {
	for _, raw := range []string{"serverUrl: https://cp.example\ncredential: host-secret\n", "currentAccount: [broken", "currentAccount: default\n---\ncurrentAccount: another\n"} {
		root := t.TempDir()
		writeLegacy(t, root, raw)
		if _, err := ActiveAccount(root, ""); err == nil {
			t.Fatal("obsolete or malformed global state silently selected account")
		}
		after, _ := os.ReadFile(filepath.Join(root, "config.yaml"))
		if string(after) != raw {
			t.Fatal("account lookup rewrote old state")
		}
		if Exists(root, DefaultAccount) {
			t.Fatal("flat credentials were migrated")
		}
	}
}

func TestActiveAccount(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct{ override, want string }{{"work", "work"}, {"", DefaultAccount}} {
		got, err := ActiveAccount(root, tc.override)
		if err != nil || got != tc.want {
			t.Fatalf("account=%q err=%v", got, err)
		}
	}
	if err := SetCurrent(root, "work"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ override, want string }{{"", "work"}, {"personal", "personal"}} {
		got, err := ActiveAccount(root, tc.override)
		if err != nil || got != tc.want {
			t.Fatalf("account=%q err=%v", got, err)
		}
	}
	if _, err := ActiveAccount(root, "../../escape"); err == nil {
		t.Fatal("unsafe explicit account accepted")
	}
	writeLegacy(t, root, "currentAccount: ../../escape\n")
	if _, err := ActiveAccount(root, ""); err == nil {
		t.Fatal("unsafe stored account accepted")
	}
}

func TestExistingAccountsRequireExplicitSelection(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(ConfigDir(root, "work"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := ActiveAccount(root, ""); err == nil {
		t.Fatal("existing account state silently selected default")
	}
	got, err := ActiveAccount(root, "work")
	if err != nil || got != "work" {
		t.Fatalf("explicit account unavailable %q %v", got, err)
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
