//go:build unix

package runtimeprofile

import (
	"github.com/pagnet-code/pagnet/domain"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateProfileValidationAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	p := Profile{Name: "claude-work", Runtime: domain.RuntimeClaudeCode, Env: map[string]string{"CLAUDE_CONFIG_DIR": "~/.claude-work", "API_KEY": "private-secret"}, Args: []string{"literal;$(do-not-evaluate)"}}
	if err := Save(path, File{Version: 1, Profiles: []Profile{p}}); err != nil {
		t.Fatal(err)
	}
	file, err := Load(path)
	if err != nil || len(file.Profiles) != 1 || file.Profiles[0].Digest() != p.Digest() {
		t.Fatalf("round trip: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private mode %v %v", info, err)
	}
	changed := p
	changed.Env = map[string]string{"CLAUDE_CONFIG_DIR": "~/.claude-other"}
	if changed.Digest() == p.Digest() {
		t.Fatal("account change retained digest")
	}
	env := p.Environment()
	if strings.Contains(strings.Join(env, "\n"), "CLAUDE_CONFIG_DIR=~") {
		t.Fatal("directory tilde not resolved")
	}
	for _, key := range []string{"PAGNET_TOKEN", "PAGNET_BRIDGE_NONCE", "HOME", "LD_PRELOAD", "BASH_ENV"} {
		t.Run(key, func(t *testing.T) {
			bad := p
			bad.Env = map[string]string{key: "secret"}
			if err := (File{Version: 1, Profiles: []Profile{bad}}).Validate(); err == nil {
				t.Fatal("reserved key accepted")
			}
		})
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("public configuration accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(filepath.Dir(path), "linked.json")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(symlink); err == nil {
		t.Fatal("symlink config accepted")
	}
}
func TestProfileRejectsShellCommandsAndUnknownFormat(t *testing.T) {
	for _, p := range []Profile{{Name: "work", Runtime: domain.RuntimeClaudeCode, Executable: "claude --dangerous"}, {Name: "../bad", Runtime: domain.RuntimeClaudeCode}, {Name: "work", Runtime: "custom-shell"}, {Name: "work", Runtime: domain.RuntimeClaudeCode, Env: map[string]string{"CLAUDE_CONFIG_DIR": "relative"}}} {
		if err := (File{Version: 1, Profiles: []Profile{p}}).Validate(); err == nil {
			t.Fatalf("invalid profile accepted: %#v", p)
		}
	}
	path := filepath.Join(t.TempDir(), Filename)
	if err := os.WriteFile(path, []byte(`{"version":1,"profiles":[],"secret":"should-not-echo"}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || strings.Contains(err.Error(), "should-not-echo") {
		t.Fatalf("invalid format leaked content: %v", err)
	}
}
