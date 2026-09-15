package daemon

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
)

// sendInventory reports detected runtimes and workspaces to the control
// plane. Sent on (re)connect — which also triggers the server's reconnect
// wake re-evaluation (§75: pending wakes/commands are re-sent and we
// deduplicate locally by CommandID) — and on host.request_inventory.
func (d *Daemon) sendInventory(conn *websocket.Conn) {
	var workspaces []transport.WorkspaceReport
	if !d.NoScan {
		workspaces = d.scanWorkspaces()
	}
	payload := transport.InventoryPayload{
		HostID:       d.stateID(),
		Runtimes:     d.detectRuntimes(),
		Workspaces:   workspaces,
		AllowedRoots: d.allowedRoots(),
	}
	// Report the host's stable E2EE public identity (plan §11.5) so the
	// control plane knows the host is crypto-capable and can address it for
	// Private Network activation/enrollment. Public keys only — the private
	// keys never leave the host. Best-effort: a failure to ensure the
	// identity omits the block (the host is simply not crypto-capable yet)
	// and never fails the inventory report.
	if id, err := d.cryptoManager().hostIdentity(); err == nil {
		payload.Crypto = &transport.InventoryCrypto{
			X25519Pub:  base64.StdEncoding.EncodeToString(id.X25519Pub),
			Ed25519Pub: base64.StdEncoding.EncodeToString(id.Ed25519Pub),
		}
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

// detectRuntimes reports every runtime this daemon can actually drive,
// resolving each CLI binary with the SAME lookup the adapter uses at
// launch — the canonical runtime name is not the binary name (qwen-code →
// `qwen`), so probing names directly would report runtimes we cannot run
// (or miss ones we can).
func (d *Daemon) detectRuntimes() []transport.RuntimeInstallation {
	out := make([]transport.RuntimeInstallation, 0, len(d.adapters))
	for name, a := range d.adapters {
		if p, ok := a.BinaryPath(); ok {
			ri := transport.RuntimeInstallation{
				Runtime: string(name),
				Path:    p,
				Version: runtimeVersion(p),
			}
			// Phase 5: report the adapter's OBSERVED native-interaction
			// capability flags (the persisted compatibility matrix, plan
			// §8.6). A non-implementer reports no capabilities (the
			// conservative "cannot observe" default).
			if obs, ok := a.(agentruntime.InteractionObserver); ok {
				ri.Capabilities = &transport.RuntimeCapabilities{
					ObserveInteractions: obs.ObserveInteractions(),
					NativeInteractiveUI: obs.NativeInteractiveUI(),
					DeferredInteraction: deferMap(obs),
					RemoteResolve:       remoteResolveMap(obs),
				}
			}
			out = append(out, ri)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Runtime < out[j].Runtime })
	return out
}

// interactionKinds is the set of kinds the capability maps are probed for
// (the adapter decides per kind; an absent kind is "not supported").
var interactionKinds = []string{
	"question", "permission", "plan_approval", "authentication", "confirmation", "other",
}

func deferMap(obs agentruntime.InteractionObserver) map[string]bool {
	m := map[string]bool{}
	for _, k := range interactionKinds {
		if obs.SupportsDeferredInteraction(k) {
			m[k] = true
		}
	}
	return m
}

func remoteResolveMap(obs agentruntime.InteractionObserver) map[string]bool {
	m := map[string]bool{}
	for _, k := range interactionKinds {
		if obs.SupportsRemoteResolve(k) {
			m[k] = true
		}
	}
	return m
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
	for _, root := range d.allowedRoots() {
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
