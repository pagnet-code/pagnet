//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
)

func TestActualLocalInitCLIStableOfflineAndProjectModePreserved(t *testing.T) {
	private, e := os.MkdirTemp("", "pgn-init-cli-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	private, e = filepath.EvalSymlinks(private)
	if e != nil {
		t.Fatal(e)
	}
	root, _ := filepath.Abs("../..")
	binary := filepath.Join(private, "pagnet")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/pagnet")
	build.Dir = root
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatalf("actual CLI build %v: %s", e, output)
	}
	home, project := filepath.Join(private, "home"), filepath.Join(private, "project")
	for _, dir := range []string{home, project} {
		if e = os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "local initialization must not use cloud", 500)
	}))
	defer server.Close()
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(t.Context(), binary, args...)
		cmd.Dir = project
		cmd.Env = append(os.Environ(), "HOME="+home, "PAGNET_SERVER="+server.URL, "PAGNET_TOKEN=never-read-local-cli-token")
		return cmd.CombinedOutput()
	}
	raw, e := run("init", "--local", "--json", "--non-interactive")
	if e != nil {
		t.Fatalf("explicit local init failed %v: %s", e, raw)
	}
	var first struct{ Status, Domain, Directory, Socket string }
	if e = json.Unmarshal(raw, &first); e != nil || first.Status != "initialized" {
		t.Fatal("invalid bounded initialization status", e, string(raw))
	}
	authority, socket := filepath.Join(home, ".pagnet", "fabric", "local"), filepath.Join(home, ".pagnet", "run", "fabric", "local.sock")
	if first.Directory != authority || first.Socket != socket {
		t.Fatal("default paths differ")
	}
	if _, e = os.Stat(filepath.Join(project, ".pagnet.yaml")); !os.IsNotExist(e) {
		t.Fatal("local init touched project manifest")
	}
	for _, name := range []string{".claude", ".qwen", ".codex"} {
		if _, e = os.Stat(filepath.Join(home, name)); !os.IsNotExist(e) {
			t.Fatal("local init created runtime state", name)
		}
	}
	loaded, e := localinstallation.Load(t.Context(), authority, registry.Options{})
	if e != nil {
		t.Fatal(e)
	}
	settings, e := fabricnode.LoadInstalledServiceSettings(t.Context(), loaded)
	if e != nil || settings == nil || *settings != fabricnode.DefaultInstalledServiceSettings() {
		t.Fatal("explicit local init lacks default service infrastructure", e)
	}
	original := loaded.Store.AuthorityIdentity()
	loaded.Close()
	raw, e = run("init", "--local", "--local-socket", filepath.Join(private, "replacement.sock"), "--json")
	if e != nil {
		t.Fatalf("repeat failed %v %s", e, raw)
	}
	var repeat struct{ Status, Domain, Directory, Socket string }
	if e = json.Unmarshal(raw, &repeat); e != nil || repeat.Status != "already_installed" || repeat.Domain != first.Domain || repeat.Socket != socket {
		t.Fatal("repeat falsely reported replacement requested path", e, string(raw))
	}
	loaded, e = localinstallation.Load(t.Context(), authority, registry.Options{})
	if e != nil {
		t.Fatal(e)
	}
	settings, e = fabricnode.LoadInstalledServiceSettings(t.Context(), loaded)
	if e != nil || settings == nil || *settings != fabricnode.DefaultInstalledServiceSettings() {
		t.Fatal("repeat changed retained service configuration", e)
	}
	if loaded.Store.AuthorityIdentity().StoreID != original.StoreID {
		t.Fatal("repeat changed root")
	}
	loaded.Close()
	raw, e = run("init", "--local", "--silent")
	if e != nil || len(raw) != 0 {
		t.Fatal("silent init emitted prose", e, string(raw))
	}
	for _, args := range [][]string{{"init", "--local", "--runtime", "claude"}, {"init", "--local", "--network", "cloud"}, {"init", "--local", "--role", "reviewer"}, {"init", "--local", "--ai"}, {"init", "--local-dir", authority}} {
		if raw, e = run(args...); e == nil {
			t.Fatal("incompatible initialization modes accepted", args)
		}
		if bytes.Contains(raw, []byte("never-read-local-cli-token")) {
			t.Fatal("credential appeared in local error")
		}
	}
	// Existing project-only behavior remains separate and writes its YAML.
	raw, e = run("init", "--network", "project-network", "--runtime", "claude", "--role", "reviewer")
	if e != nil {
		t.Fatalf("project mode regressed %v: %s", e, raw)
	}
	manifest, e := os.ReadFile(filepath.Join(project, ".pagnet.yaml"))
	if e != nil || !bytes.Contains(manifest, []byte("project-network")) || !bytes.Contains(manifest, []byte("reviewer")) {
		t.Fatal("project init fields not preserved", e)
	}
	if calls.Load() != 0 {
		t.Fatal("local init contacted control plane", calls.Load())
	}
	// Missing original key blocks the actual command and remains missing.
	if e = os.Remove(filepath.Join(authority, "installation.key")); e != nil {
		t.Fatal(e)
	}
	raw, e = run("init", "--local")
	if e == nil || !strings.Contains(string(raw), "existing identity and keys were preserved") {
		t.Fatal("incomplete setup was not clearly rejected", e, string(raw))
	}
	if _, e = os.Stat(filepath.Join(authority, "installation.key")); !os.IsNotExist(e) {
		t.Fatal("CLI regenerated missing encryption key")
	}
}
func TestLocalFabricPathsExplicitAndDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	authority, socket, e := localFabricPaths("", "")
	if e != nil || authority != filepath.Join(home, ".pagnet", "fabric", "local") || socket != filepath.Join(home, ".pagnet", "run", "fabric", "local.sock") {
		t.Fatal("default local paths differ", e)
	}
	authority, socket, e = localFabricPaths("explicit-root", "explicit.sock")
	if e != nil || !filepath.IsAbs(authority) || !filepath.IsAbs(socket) || filepath.Base(authority) != "explicit-root" {
		t.Fatal("explicit paths not canonicalized", e)
	}
}

func TestLocalInitRejectsOverlongSocketBeforeAnyInstallationState(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "not-created", "authority")
	socket := filepath.Join(parent, strings.Repeat("x", 200), "node.sock")
	command := initCmd()
	command.SetContext(t.Context())
	command.SetArgs([]string{"--local", "--local-dir", directory, "--local-socket", socket})
	err := command.Execute()
	var typed *fabric.Error
	if !errors.As(err, &typed) || typed.Code != fabric.CodeInvalidInput || !strings.Contains(typed.Message, "shorter socket path") {
		t.Fatal("socket limit not reported before init", err)
	}
	if _, err = os.Lstat(filepath.Join(parent, "not-created")); !os.IsNotExist(err) {
		t.Fatal("invalid socket initialized immutable state or parents", err)
	}
}
