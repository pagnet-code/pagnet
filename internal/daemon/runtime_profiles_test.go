//go:build unix

package daemon

import (
	"encoding/json"
	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/runtimeprofile"
	"github.com/pagnet-code/pagnet/transport"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedProfilesExecuteSeparateEnvironmentAndLiteralArgs(t *testing.T) {
	d := newTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()
	binary := filepath.Join(t.TempDir(), "custom-claude")
	script := `#!/bin/sh
printf '%s\n' "$CLAUDE_CONFIG_DIR" "$PROFILE_PRIVATE" "$@" > "$CLAUDE_CONFIG_DIR/trace"
cat > /dev/null
printf '%s\n' '{"type":"system","subtype":"init","session_id":"native-session"}' '{"type":"result","session_id":"native-session","is_error":false,"result":"done"}'
`
	if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	file := runtimeprofile.File{Version: 1}
	for _, name := range []string{"claude-work", "claude-shared"} {
		file.Profiles = append(file.Profiles, runtimeprofile.Profile{Name: name, Runtime: domain.RuntimeClaudeCode, Executable: binary, Args: []string{"literal;$(no-shell)"}, Env: map[string]string{"CLAUDE_CONFIG_DIR": filepath.Join(t.TempDir(), name), "PROFILE_PRIVATE": name + "-secret"}})
	}
	if err := runtimeprofile.Save(filepath.Join(d.StateDir, runtimeprofile.Filename), file); err != nil {
		t.Fatal(err)
	}
	if err := d.loadRuntimeProfiles(); err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(d.buildInventoryPayload().RuntimeProfiles)
	if strings.Contains(string(public), "secret") || strings.Contains(string(public), binary) || strings.Contains(string(public), "CLAUDE_CONFIG_DIR") {
		t.Fatalf("profile settings uploaded %s", public)
	}
	for _, p := range file.Profiles {
		instance := domain.NewID().String()
		driveLaunch(t, d, server, transport.LaunchAgentPayload{CommandID: "launch-" + p.Name, InstanceID: instance, Runtime: string(p.Runtime), Profile: p.Name, Kind: "representative"})
		driveDeliver(t, d, server, transport.NetworkEventPayload{CommandID: "deliver-" + p.Name, InstanceID: instance, Kind: "channel", ConversationID: "chat", Body: "hello"})
		trace, err := os.ReadFile(filepath.Join(p.Env["CLAUDE_CONFIG_DIR"], "trace"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(trace), p.Name+"-secret") || !strings.Contains(string(trace), "literal;$(no-shell)") {
			t.Fatalf("profile environment/arguments lost: %s", trace)
		}
		row, ok, err := d.state.GetInstance(instance)
		if err != nil || !ok {
			t.Fatal(err)
		}
		d.runtimeProfiles[p.Name].config.Env = map[string]string{"CLAUDE_CONFIG_DIR": "changed"}
		if err := d.checkRuntimeProfile(row, false); err == nil {
			t.Fatal("changed profile resumed existing native session")
		}
	}
	if d.runtimeProfiles["claude-work"].adapter == d.runtimeProfiles["claude-shared"].adapter {
		t.Fatal("profiles shared mutable adapter")
	}
	if d.adapters[domain.RuntimeClaudeCode].(*agentruntime.Claude).Binary == binary {
		t.Fatal("profile replaced default adapter")
	}
}
func TestNativeProfileDriverKeysAndStateContainment(t *testing.T) {
	d := newTestDaemon(t)
	binary := filepath.Join(t.TempDir(), "native-cli")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	file := runtimeprofile.File{Version: 1, Profiles: []runtimeprofile.Profile{{Name: "qwen-work", Runtime: domain.RuntimeQwenCode, Executable: binary}, {Name: "qwen-shared", Runtime: domain.RuntimeQwenCode, Executable: binary}, {Name: "codex-work", Runtime: domain.RuntimeCodex, Executable: binary}}}
	path := filepath.Join(d.StateDir, runtimeprofile.Filename)
	if err := runtimeprofile.Save(path, file); err != nil {
		t.Fatal(err)
	}
	if err := d.loadRuntimeProfiles(); err != nil {
		t.Fatal(err)
	}
	for _, p := range file.Profiles {
		row := &InstanceRow{Runtime: string(p.Runtime), Profile: p.Name}
		drv := d.sessionDriverFor(row)
		if drv == nil || drv.Name() == p.Runtime {
			t.Fatal("profile driver was not isolated")
		}
		if d.sessions.DriverFor(p.Runtime) == drv {
			t.Fatal("profile replaced native default")
		}
	}
	public := d.detectRuntimes()
	for _, runtime := range public {
		if strings.Contains(runtime.Runtime, "@") {
			t.Fatal("internal driver alias escaped inventory")
		}
	}
	file.Profiles[0].NativeDirs = []string{filepath.Dir(d.StateDir)}
	if err := runtimeprofile.Save(path, file); err != nil {
		t.Fatal(err)
	}
	if err := d.loadRuntimeProfiles(); err == nil {
		t.Fatal("profile granted daemon state")
	}
}
