package main

// `pagnet run [dir|resource]` — quick launch (spec §73, addendum).
//
// Local (zero-config, the default): inside a git repository it detects the
// remote, ensures the resource/workspace/agent exist, and starts an
// instance ON THIS HOST via the local daemon.
//
// Remote (addendum): `--host <h>` launches on another registered host —
// the control plane brokers the launch over that host's existing outbound
// daemon connection. The target workspace is matched by the logical
// resource (or given explicitly with --workspace); when several workspaces
// match, the choices are listed instead of guessing. The MVP never clones
// automatically.
//
// Shorthand: -r/--runtime -p/--role -n/--network -H/--host.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/pagnet-code/pagnet/domain"
)

func runCmd() *cobra.Command {
	var (
		network, name, role, access, stateDir string
		runtimeName, runtimeProfile           string
		host, workspace                       string
	)
	cmd := &cobra.Command{
		Use:   "run [dir|resource]",
		Short: "Quick launch: start an agent on this host (or --host <h>)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI(stateDir)
			if err != nil {
				return err
			}
			if c.cfg.Credential == "" || c.cfg.HostID == "" {
				return errors.New("no pagnet host config found; run `pagnet enroll --server <url>` first")
			}
			local := c.cfg.HostID

			// 1. Resolve the target host.
			targetID, targetName := local, c.cfg.HostName
			if host != "" {
				th, err := c.hostByName(host)
				if err != nil {
					return err
				}
				targetID, targetName = th.ID, th.Name
			}

			// 2. Determine the logical resource.
			//    - local dir (default): git remote of this directory
			//    - resource key: launched as-is (may combine with --host)
			var absDir, remote, key string
			switch {
			case len(args) == 0 && host == "":
				absDir, _ = filepath.Abs(".")
			case len(args) == 0:
				return errors.New("remote launch needs a directory (`run . --host owl`) or a resource (`run github.com/o/r --host owl`)")
			case isLocalDir(args[0]):
				absDir, _ = filepath.Abs(args[0])
			default:
				key = args[0]
			}
			if absDir != "" && isGitRepo(absDir) {
				remote, key, err = gitResourceKey(absDir)
				if err != nil {
					return err
				}
			}
			// Non-git directory (fresh or non-repository project): the
			// workspace is just a path under an allowed root — no logical
			// resource, launch works the same.

			// Optional project config (spec §13) — never required for a
			// basic launch; provides the network and agent defaults below.
			var yamlCfg *pagnetYAML
			if absDir != "" {
				if y, yerr := loadAgentnetYAML(absDir); yerr == nil {
					yamlCfg = y
				}
			}

			// 3. Network selection: flag > .pagnet.yaml > saved default
			//    > only network.
			if network == "" && yamlCfg != nil && yamlCfg.Network != "" {
				network = yamlCfg.Network
			}
			netID, netName, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}

			// 4. The target host must be online (it executes the launch).
			td, err := c.hostDetail(targetID)
			if err != nil {
				return err
			}
			if td.Status != "online" {
				return fmt.Errorf("host %s is %s — start `pagnet -d` there first", td.Name, td.Status)
			}

			if runtimeProfile != "" {
				if !domain.ValidRuntimeProfileName(runtimeProfile) {
					return fmt.Errorf("invalid runtime profile name")
				}
				matched := false
				for _, p := range td.RuntimeProfiles {
					if p.Name == runtimeProfile && p.Available && (runtimeName == "" || domain.CanonicalRuntime(runtimeName) == domain.RuntimeName(p.Runtime)) {
						runtimeName = p.Runtime
						matched = true
						break
					}
				}
				if !matched {
					return fmt.Errorf("runtime profile %q is not available on host %s", runtimeProfile, td.Name)
				}
			}
			// 5. Pick the workspace on the target host.
			workspaceID := ""
			switch {
			case workspace != "":
				workspaceID = findWorkspace(td.Workspaces, workspace)
				if workspaceID == "" {
					return fmt.Errorf("workspace %s is not registered for host %s (is it under an allowed root?)", workspace, td.Name)
				}
			case absDir != "" && targetID == local:
				// Local path: registered by the daemon inventory; if new,
				// ask for a rescan and wait for it to appear.
				workspaceID = findWorkspace(td.Workspaces, absDir)
				if workspaceID == "" {
					if err := c.post("/api/v1/hosts/"+td.ID+"/rescan", map[string]any{}, nil); err != nil {
						return fmt.Errorf("rescan: %w", err)
					}
					workspaceID = waitForWorkspace(c, td.ID, absDir, 20*time.Second)
				}
				if workspaceID == "" && !isGitRepo(absDir) {
					// Non-git directories are invisible to the inventory
					// scan (git repos only) — register directly.
					var w struct {
						ID string `json:"ID"`
					}
					if err := c.post("/api/v1/hosts/"+td.ID+"/workspaces",
						map[string]any{"path": absDir}, &w); err != nil {
						return fmt.Errorf("register workspace: %w", err)
					}
					workspaceID = w.ID
				}
				if workspaceID == "" {
					return fmt.Errorf("workspace %s is not registered for this host (is it under an allowed root?)", absDir)
				}
			default:
				// Remote host (or a bare resource key): match by the
				// logical resource — never guess.
				keys := c.resourceKeys()
				matches := make([]string, 0, 2)
				for _, ws := range td.Workspaces {
					k := ""
					if ws.ResourceID != nil {
						k = keys[*ws.ResourceID]
					}
					if k == key {
						matches = append(matches, ws.Path)
					}
				}
				switch len(matches) {
				case 1:
					workspaceID = findWorkspace(td.Workspaces, matches[0])
				case 0:
					return fmt.Errorf("no workspace for resource %s on host %s — register it there first (the MVP does not clone automatically)", key, td.Name)
				default:
					fmt.Fprintf(os.Stderr, "Resource %s has multiple workspaces on %s:\n\n", key, td.Name)
					for i, m := range matches {
						fmt.Fprintf(os.Stderr, "%d. %s\n", i+1, m)
					}
					fmt.Fprintln(os.Stderr, "\nSpecify: --workspace <path>")
					return errors.New("ambiguous workspace")
				}
			}

			// 6. Resource (idempotent: created from the key if new).
			//    Non-git directories have no logical resource: skip.
			var res struct {
				ID string `json:"ID"`
			}
			if key != "" {
				body := map[string]any{"key": key}
				if remote != "" {
					body["remote"] = remote
				}
				if err := c.post("/api/v1/networks/"+netID+"/resources", body, &res); err != nil {
					return fmt.Errorf("resource: %w", err)
				}
			}

			// 7. Agent definition (created if new; bound to the resource).
			//    Defaults: flags > .pagnet.yaml agent entry > <repo|dir>[-<role>].
			agentName := name
			base := key
			if base == "" {
				base = filepath.Base(absDir)
			}
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			if agentName == "" && yamlCfg != nil {
				for _, e := range yamlCfg.Agents {
					if e.Name == base || e.Name == base+"-"+role ||
						(e.Role == "" && role == "" && len(yamlCfg.Agents) == 1) {
						agentName = e.Name
						if !cmd.Flags().Changed("runtime") && e.Runtime != "" {
							runtimeName = e.Runtime
						}
						if role == "" {
							role = e.Role
						}
						break
					}
				}
			}
			if agentName == "" {
				agentName = base
				if role != "" {
					agentName += "-" + role
				}
			}
			var agents []struct {
				ID   string `json:"ID"`
				Name string `json:"Name"`
			}
			if err := c.get("/api/v1/networks/"+netID+"/agents", &agents); err != nil {
				return err
			}
			defID := ""
			for _, a := range agents {
				if a.Name == agentName {
					defID = a.ID
				}
			}
			// A NEW definition carries the resolved concrete runtime
			// (autoPickRuntime — the console's "Auto" behavior, from the
			// host's reported inventory); the create body and the launch
			// below agree on it (console parity). An EXISTING definition
			// keeps its saved default: with no --runtime the launch omits
			// the runtime and the server falls back to the definition's.
			createdNow := false
			createRuntime := ""
			if defID == "" {
				createRuntime = runtimeName
				if createRuntime == "" {
					createRuntime = autoPickRuntime(td.Runtimes)
					if createRuntime == "" {
						return fmt.Errorf("host %s reports no runtimes — install an agent runtime (qwen-code, claude-code, opencode, codex) or start its daemon with --debug (the fake runtimes)", targetName)
					}
				}
				var created struct {
					ID string `json:"ID"`
				}
				if err := c.post("/api/v1/networks/"+netID+"/agents",
					agentCreateBody(agentName, createRuntime, access, res.ID), &created); err != nil {
					return fmt.Errorf("create agent: %w", err)
				}
				defID = created.ID
				createdNow = true
			}

			// 8. Launch the instance on the target host.
			var inst struct {
				ID     string `json:"ID"`
				Status string `json:"Status"`
			}
			launchBody := map[string]any{"hostId": targetID, "workspaceId": workspaceID}
			if runtimeProfile != "" {
				launchBody["profile"] = runtimeProfile
			}
			launchRuntime := runtimeName
			if createdNow && launchRuntime == "" {
				launchRuntime = createRuntime
			}
			if launchRuntime != "" {
				launchBody["runtime"] = launchRuntime
			}
			if err := c.post("/api/v1/networks/"+netID+"/agents/"+defID+"/launch", launchBody, &inst); err != nil {
				return fmt.Errorf("launch: %w", err)
			}

			// 9. Wait until the daemon has applied the launch.
			status := inst.Status
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				var cur struct {
					Instance struct {
						Status string `json:"Status"`
					} `json:"instance"`
				}
				if err := c.get("/api/v1/networks/"+netID+"/agents/"+defID+"/instances/"+inst.ID, &cur); err != nil {
					return err
				}
				status = cur.Instance.Status
				if status == "idle" || status == "working" || status == "hibernated" {
					break
				}
				time.Sleep(time.Second)
			}

			fmt.Printf("git remote:   %s\n", orDash(remote))
			fmt.Printf("resource:     %s  (%s)\n", key, res.ID)
			fmt.Printf("host:         %s  (%s)\n", targetName, targetID)
			fmt.Printf("workspace:    %s  (%s)\n", td.WorkspacePath(workspaceID), workspaceID)
			fmt.Printf("network:      %s  (%s)\n", netName, netID)
			fmt.Printf("agent:        %s  (%s)\n", agentName, defID)
			fmt.Printf("instance:     %s  (status=%s)\n", inst.ID, status)
			fmt.Println("the daemon injects the pagnet MCP bridge + coordination contract into the runtime")
			fmt.Println("this command exits now — the agent keeps running on the host daemon")
			fmt.Printf("watch it in the web console (Agents page → %s), or join its terminal: pagnet attach %s\n",
				agentName, agentName)
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network id, name, or slug (default: the saved/only network)")
	cmd.Flags().StringVar(&name, "name", "", "agent name (default: <repo>[-<role>])")
	cmd.Flags().StringVar(&runtimeProfile, "profile", "", "named runtime execution profile configured on the target host")
	cmd.Flags().StringVarP(&runtimeName, "runtime", "r", "",
		"runtime for the agent (qwen|claude|opencode|codex|fake); empty = resolved from the host's reported runtimes (real runtimes first, the console's Auto behavior; fake is debug-only)")
	cmd.Flags().StringVarP(&role, "role", "p", "",
		"role suffix for the default agent name (e.g. coder: <repo>-coder; V2 agents have no profile field — the suffix only shapes the name)")
	cmd.Flags().StringVarP(&host, "host", "H", "", "launch on this host (name or id) instead of this one")
	cmd.Flags().StringVar(&workspace, "workspace", "", "explicit workspace path on the target host")
	cmd.Flags().StringVar(&access, "access", "read_write", "workspace access: read_write | read_only (second+ RW agents get a git worktree)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "daemon state dir with the login (default ~/.pagnet)")
	return cmd
}

// agentCreateBody builds the V2 agent-creation body for
// POST /networks/{id}/agents. The server decodes it strictly
// (DisallowUnknownFields): name, description, mission, instruction, runtime,
// model, executionMode, ownershipScope, visibility, executionSettings,
// responsibilities, groupIds (+ the E2EE id/envelope/aad pair) are the ONLY
// accepted fields — there is NO profile or capabilities field (V1 shapes).
// Capabilities are declared by the agent's ENDPOINT at runtime, never at
// creation (console parity: pagnet-web agentCreateBody).
// resourceID, when set, binds the agent to the logical resource
// (responsibilities); non-git workspaces have none and omit it.
func agentCreateBody(name, runtime, access, resourceID string) map[string]any {
	body := map[string]any{
		"name":              name,
		"runtime":           runtime,
		"executionSettings": map[string]any{"access": access},
	}
	if resourceID != "" {
		body["responsibilities"] = []any{
			map[string]any{
				"resourceId": resourceID,
				"actions":    []string{"implement", "review", "advise"},
			},
		}
	}
	return body
}

// runtimePreference is the Auto-pick order over a host's reported runtimes.
// It is the same order the console uses (pagnet-web lib/runtimes.ts
// PREFERENCE) and the order the daemon falls through on an empty launch
// runtime (internal/daemon doLaunch) — one product behavior, three surfaces.
var runtimePreference = []string{"qwen-code", "claude-code", "opencode", "codex"}

// debugRuntimeNames are the deterministic test runtimes that exist only on
// a daemon running in debug mode (the fake runtimes).
var debugRuntimeNames = map[string]bool{"fake": true, "fake-persistent": true}

// autoPickRuntime resolves the concrete runtime for an empty --runtime the
// same way the console's "Auto" does (pagnet-web autoRuntime): dedupe the
// host's reported runtimes, order the real ones by preference then
// first-seen (debug runtimes last), and pick the first REAL runtime — or
// the first reported one when the host offers debug runtimes only (a
// development worker with nothing else installed; the daemon's empty-runtime
// fallback never auto-selects fake, so the concrete pick must come from
// here). "" when the host reports no runtimes at all.
func autoPickRuntime(reported []hostRuntime) string {
	seen := map[string]bool{}
	uniq := make([]string, 0, len(reported))
	for _, r := range reported {
		if r.Runtime == "" || seen[r.Runtime] {
			continue
		}
		seen[r.Runtime] = true
		uniq = append(uniq, r.Runtime)
	}
	if len(uniq) == 0 {
		return ""
	}
	rank := func(name string) int {
		for i, p := range runtimePreference {
			if name == p {
				return i
			}
		}
		if debugRuntimeNames[name] {
			return len(runtimePreference) + 1
		}
		return len(runtimePreference)
	}
	sorted := make([]string, len(uniq))
	copy(sorted, uniq)
	sort.SliceStable(sorted, func(i, j int) bool { return rank(sorted[i]) < rank(sorted[j]) })
	for _, r := range sorted {
		if !debugRuntimeNames[r] {
			return r
		}
	}
	return sorted[0]
}

func (h *cliHost) WorkspacePath(wsID string) string {
	for _, ws := range h.Workspaces {
		if ws.ID == wsID {
			return ws.Path
		}
	}
	return "-"
}

func isLocalDir(p string) bool {
	if _, err := os.Stat(p); err != nil {
		return false
	}
	return true
}

func isGitRepo(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// findWorkspace matches a workspace by exact path.
func findWorkspace(wss []wsEntry, path string) string {
	for _, ws := range wss {
		if ws.Path == path {
			return ws.ID
		}
	}
	return ""
}

// waitForWorkspace polls the host for a newly-scanned workspace.
func waitForWorkspace(c *cliCtx, hostID, path string, d time.Duration) string {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		h, err := c.hostDetail(hostID)
		if err != nil {
			continue
		}
		if id := findWorkspace(h.Workspaces, path); id != "" {
			return id
		}
	}
	return ""
}

func gitRemote(dir string) (string, error) {
	if out, err := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").CombinedOutput(); err != nil ||
		strings.TrimSpace(string(out)) != "true" {
		return "", fmt.Errorf("%s is not a git repository", dir)
	}
	remote := "origin"
	if out, err := exec.Command("git", "-C", dir, "remote").Output(); err == nil {
		if remotes := strings.Fields(strings.TrimSpace(string(out))); len(remotes) > 0 {
			remote = remotes[0]
		}
	}
	url, err := exec.Command("git", "-C", dir, "remote", "get-url", remote).Output()
	if err != nil {
		return "", fmt.Errorf("%s has no git remote (add one, e.g. `git remote add origin <url>`)", dir)
	}
	return strings.TrimSpace(string(url)), nil
}

// gitResourceKey is the canonical resource key of the repository at dir.
func gitResourceKey(dir string) (remote, key string, err error) {
	remote, err = gitRemote(dir)
	if err != nil {
		return "", "", err
	}
	key, ok := domain.NormalizeGitRemote(remote)
	if !ok {
		return "", "", fmt.Errorf("git remote %q does not normalize to a canonical resource key", remote)
	}
	return remote, key, nil
}
