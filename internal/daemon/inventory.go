package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"agentnet/internal/domain"
	"agentnet/internal/transport"
)

// sendInventory reports detected runtimes and workspaces to the control
// plane. Sent on (re)connect — which also triggers the server's reconnect
// wake re-evaluation (§75: pending wakes/commands are re-sent and we
// deduplicate locally by CommandID) — and on host.request_inventory.
func (d *Daemon) sendInventory(conn *websocket.Conn) {
	payload := transport.InventoryPayload{
		HostID:       d.stateID(),
		Runtimes:     d.detectRuntimes(),
		Workspaces:   d.scanWorkspaces(),
		AllowedRoots: d.AllowedRoots,
	}
	_ = d.send(conn, transport.MsgHostInventory, payload)
}

// stateID returns the host id the daemon enrolled with (kept in KV state so
// it survives restarts). Empty when unknown (fresh state dir).
func (d *Daemon) stateID() string {
	if v, ok := d.state.KVGet("host_id"); ok {
		return v
	}
	return ""
}

// detectRuntimes reports every runtime this daemon can drive. The fake
// runtime is always available (its binary is resolved per turn); real
// runtimes are reported when their binary is on PATH.
func (d *Daemon) detectRuntimes() []transport.RuntimeInstallation {
	out := []transport.RuntimeInstallation{
		{Runtime: string(domain.RuntimeFake)},
	}
	for _, rn := range []domain.RuntimeName{
		domain.RuntimeQwenCode, domain.RuntimeClaudeCode, domain.RuntimeOpenCode,
	} {
		bin := string(rn)
		if p, err := exec.LookPath(bin); err == nil {
			out = append(out, transport.RuntimeInstallation{
				Runtime: string(rn),
				Path:    p,
				Version: runtimeVersion(p),
			})
		}
	}
	return out
}

func runtimeVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, flag := range []string{"--version", "-v"} {
		cmd := exec.CommandContext(ctx, path, flag)
		out, err := cmd.Output()
		if err == nil {
			return firstLine(string(out))
		}
	}
	return ""
}

// scanWorkspaces walks the allowed roots (depth-limited) for git
// repositories and reports each with branch + canonical remote key.
func (d *Daemon) scanWorkspaces() []transport.WorkspaceReport {
	seen := map[string]bool{}
	var out []transport.WorkspaceReport
	for _, root := range d.AllowedRoots {
		abs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		_ = filepath.WalkDir(abs, func(path string, ent os.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			rel, _ := filepath.Rel(abs, path)
			if rel != "." && len(strings.Split(rel, string(os.PathSeparator))) > 2 {
				if !ent.IsDir() {
					return nil
				}
				return filepath.SkipDir // depth limit: root/<one>/<two>
			}
			if !ent.IsDir() {
				return nil
			}
			if _, err := os.Stat(filepath.Join(path, ".git")); err != nil {
				return nil
			}
			if seen[path] {
				return filepath.SkipDir
			}
			seen[path] = true
			out = append(out, gitWorkspaceReport(path))
			return filepath.SkipDir // don't nest inside a repo
		})
	}
	return out
}

func gitWorkspaceReport(dir string) transport.WorkspaceReport {
	wr := transport.WorkspaceReport{Path: dir}
	remote := gitOutput(dir, "remote", "get-url", "origin")
	branch := gitOutput(dir, "branch", "--show-current")
	wr.Remote = remote
	wr.Branch = branch
	if remote != "" {
		if key, ok := domain.NormalizeGitRemote(remote); ok && key != "" {
			wr.ResourceKey = key
		}
	}
	return wr
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

func gitOutput(dir string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
