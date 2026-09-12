package main

// The spec §55 command surface (ps/agents/hosts/networks/tasks/inbox,
// stop, restart, open, init, doctor) — thin frontends over the same REST
// endpoints the web UI uses. `ps` is an alias of `status` (see commands.go);
// `host connect/status/disconnect` and the service installer stay out of
// the MVP (accepted gap, docs/IMPLEMENTATION_STATUS.md).

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"pagnet/internal/config"
)

// --- §55 list verbs: agents / hosts / networks / tasks ----------------------
// (the full `list <target>` command in commands.go reuses runList)

func simpleListCmd(use, target, short string) *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			return runList(c, target, network)
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network for network-scoped listings (default: the saved/only network)")
	return cmd
}

func agentsCmd() *cobra.Command {
	return simpleListCmd("agents", "agents", "List agents in the network (§55 `pagnet agents`)")
}

func hostsCmd() *cobra.Command {
	return simpleListCmd("hosts", "hosts", "List hosts (§55 `pagnet hosts`)")
}

func networksCmd() *cobra.Command {
	return simpleListCmd("networks", "networks", "List networks (§55 `pagnet networks`)")
}

func tasksCmd() *cobra.Command {
	return simpleListCmd("tasks", "tasks", "List tasks (§55 `pagnet tasks`)")
}

// --- stop / restart <agent> -------------------------------------------------

func instanceActionCmd(action, short string) *cobra.Command {
	var network, instanceID string
	cmd := &cobra.Command{
		Use:   action + " <agent>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
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
				if a.Name == args[0] {
					defID = a.ID
					break
				}
			}
			if defID == "" {
				return fmt.Errorf("agent %q not found in this network", args[0])
			}
			var insts []struct {
				ID     string `json:"ID"`
				Status string `json:"Status"`
			}
			if err := c.get("/api/v1/networks/"+netID+"/agents/"+defID+"/instances", &insts); err != nil {
				return err
			}
			if len(insts) == 0 {
				return fmt.Errorf("agent %s has no instances (launch one first: `pagnet run .`)", args[0])
			}
			iid := instanceID
			if iid == "" {
				if len(insts) == 1 {
					iid = insts[0].ID
				} else {
					// Several instances: pick the one this action most
					// sensibly applies to (stop: the active one; restart:
					// the stopped/failed one). --instance overrides.
					rank := stopRank
					if action == "restart" {
						rank = restartRank
					}
					best, bestRank := "", 1<<30
					for _, i := range insts {
						r := 100
						if v, ok := rank[i.Status]; ok {
							r = v
						}
						if r < bestRank {
							best, bestRank = i.ID, r
						}
					}
					iid = best
				}
			}
			// 202 Accepted: the command is dispatched to the host daemon,
			// so poll for the resulting status instead of trusting a body.
			if err := c.post("/api/v1/networks/"+netID+"/agents/"+defID+"/instances/"+iid+"/"+action,
				map[string]any{}, nil); err != nil {
				return err
			}
			settle := stopSettle
			if action == "restart" {
				settle = restartSettle
			}
			status := "(dispatched)"
			// A stop queues behind an in-flight turn (per-instance FIFO),
			// so allow a full turn's worth of time before giving up.
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				var cur struct {
					Instance struct {
						Status string `json:"Status"`
					} `json:"instance"`
				}
				if err := c.get("/api/v1/networks/"+netID+"/agents/"+defID+"/instances/"+iid, &cur); err == nil {
					if settle[cur.Instance.Status] {
						status = cur.Instance.Status
						break
					}
				}
				time.Sleep(time.Second)
			}
			fmt.Printf("%s %s: instance %s -> %s\n", action, args[0], iid, status)
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	cmd.Flags().StringVar(&instanceID, "instance", "", "specific instance id (default: the most relevant one)")
	return cmd
}

var stopRank = map[string]int{
	"working": 0, "waking": 0, "starting": 1, "idle": 2,
	"rate_limited": 3, "auth_required": 3, "blocked": 4,
	"hibernated": 5, "stopped": 6, "failed": 7,
}

var restartRank = map[string]int{
	"stopped": 0, "failed": 1, "blocked": 2, "unreachable": 3,
	"working": 4, "waking": 4, "idle": 5, "hibernated": 6,
}

// Terminal-ish statuses each action is considered to have settled into.
var stopSettle = map[string]bool{
	"stopped": true, "hibernated": true, "stopped_by_host": true,
}

var restartSettle = map[string]bool{
	"working": true, "idle": true, "waking": true, "starting": true,
	"blocked": true, "failed": true,
}

func stopCmd() *cobra.Command {
	return instanceActionCmd("stop", "Stop an agent instance (§55 `pagnet stop <agent>`)")
}

func restartCmd() *cobra.Command {
	return instanceActionCmd("restart", "Restart an agent instance, re-delivering its inbox (§55 `pagnet restart <agent>`)")
}

// --- inbox ------------------------------------------------------------------

// inboxCmd lists the pending inbound work across the network's instances
// (§55 `pagnet inbox`) — the durable queues an agent would pick up.
func inboxCmd() *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:   "inbox",
		Short: "Pending inbound messages across the network's instances",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			var agents []struct {
				ID   string `json:"ID"`
				Name string `json:"Name"`
			}
			if err := c.get("/api/v1/networks/"+netID+"/agents", &agents); err != nil {
				return err
			}
			rows := make([][]string, 0, 8)
			for _, a := range agents {
				var insts []struct {
					ID     string `json:"ID"`
					Status string `json:"Status"`
				}
				if err := c.get("/api/v1/networks/"+netID+"/agents/"+a.ID+"/instances", &insts); err != nil {
					return err
				}
				for _, i := range insts {
					var msgs []struct {
						ID              string `json:"ID"`
						Kind            string `json:"Kind"`
						SenderAgentName string `json:"SenderAgentName"`
						Parts           []struct {
							Kind string  `json:"kind"`
							Text *string `json:"text"`
						} `json:"Parts"`
					}
					if err := c.get("/api/v1/networks/"+netID+"/agents/"+a.ID+"/instances/"+i.ID+"/inbox?limit=50", &msgs); err != nil {
						return err
					}
					for _, m := range msgs {
						body := ""
						for _, p := range m.Parts {
							if p.Text != nil {
								body = *p.Text
								break
							}
						}
						body = strings.ReplaceAll(body, "\n", " ")
						if len(body) > 60 {
							body = body[:57] + "..."
						}
						rows = append(rows, []string{a.Name, i.ID, m.Kind, orDash(m.SenderAgentName), orDash(body)})
					}
				}
			}
			if len(rows) == 0 {
				fmt.Println("no pending inbox messages")
				return nil
			}
			printTable([]string{"AGENT", "INSTANCE", "KIND", "FROM", "MESSAGE"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	return cmd
}

// --- open [directory] ---------------------------------------------------------

// openCmd prints (and opens) the web UI focused on this host, the workspace
// containing the directory, and its git resource (§55 `pagnet open .`).
func openCmd() *cobra.Command {
	var webURL, stateDir string
	cmd := &cobra.Command{
		Use:   "open [directory]",
		Short: "Open the web UI focused on this host, workspace, and git resource",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI(stateDir)
			if err != nil {
				return err
			}
			if c.cfg.HostID == "" {
				return errors.New("no pagnet host config found; run `pagnet enroll --token <enrollment-token>` first")
			}
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			absDir, _ := filepath.Abs(dir)
			if _, err := os.Stat(absDir); err != nil {
				return fmt.Errorf("%s: %w", dir, err)
			}
			td, err := c.hostDetail(c.cfg.HostID)
			if err != nil {
				return err
			}
			wsID := findWorkspace(td.Workspaces, absDir)
			if wsID == "" {
				// Maybe newly registered: ask for a rescan and wait.
				_ = c.post("/api/v1/hosts/"+td.ID+"/rescan", map[string]any{}, nil)
				wsID = waitForWorkspace(c, td.ID, absDir, 20*time.Second)
			}
			if wsID == "" {
				return fmt.Errorf("workspace %s is not registered on this host (is it under an allowed root?)", absDir)
			}
			u := strings.TrimSuffix(webURL, "/") + "/hosts/" + td.ID + "?workspace=" + wsID
			if _, key, err := gitResourceKey(absDir); err == nil {
				u += "&resource=" + key
			}
			fmt.Println(u)
			if err := openBrowser(u); err != nil {
				fmt.Println("(could not open a browser:", err.Error(), "- open the URL above)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&webURL, "web-url", "http://localhost:13000", "web UI base URL")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "daemon state dir with the login (default ~/.pagnet)")
	return cmd
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // don't block on the browser's lifetime
	return nil
}

// --- init --------------------------------------------------------------------

// pagnetYAML is the optional project config (spec §13). It is never
// required for a basic launch; `run` reads the network and agent defaults
// from it when present.
type pagnetYAML struct {
	Version     int    `yaml:"version"`
	Network     string `yaml:"network,omitempty"`
	Description string `yaml:"description,omitempty"`
	Agents      []struct {
		Name             string `yaml:"name"`
		Runtime          string `yaml:"runtime"`
		Role             string `yaml:"role,omitempty"`
		Responsibilities []struct {
			Resource string   `yaml:"resource"`
			Actions  []string `yaml:"actions"`
		} `yaml:"responsibilities"`
	} `yaml:"agents"`
}

// loadAgentnetYAML reads .pagnet.yaml from dir ("" when absent).
func loadAgentnetYAML(dir string) (*pagnetYAML, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ".pagnet.yaml"))
	if err != nil {
		return nil, err
	}
	var y pagnetYAML
	if err := yaml.Unmarshal(raw, &y); err != nil {
		return nil, err
	}
	return &y, nil
}

func initCmd() *cobra.Command {
	var ai bool
	var networkName, runtimeName, role string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate .pagnet.yaml in this directory (spec §13)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ai {
				return errors.New("--ai (AI-assisted init) is not part of the MVP (spec §13: optional)")
			}
			absDir, _ := filepath.Abs(".")
			if _, err := os.Stat(filepath.Join(absDir, ".pagnet.yaml")); err == nil {
				return errors.New(".pagnet.yaml already exists (edit it instead of re-running init)")
			}
			repoName := filepath.Base(absDir)
			key := "auto:git"
			if _, k, err := gitResourceKey(absDir); err == nil {
				key = k
			}
			rt := runtimeName
			if rt == "" {
				rt = "qwen"
			}
			name := repoName
			if role != "" {
				name += "-" + role
			}
			netName := networkName
			if netName == "" {
				if c, err := newCLI(""); err == nil {
					if _, label, err := c.resolveNetwork(""); err == nil {
						netName = label
					}
				}
			}
			if netName == "" {
				netName = "default"
			}
			desc := ""
			if b, err := os.ReadFile(filepath.Join(absDir, "README.md")); err == nil {
				for _, line := range strings.Split(string(b), "\n") {
					line = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(line), "#"))
					if line != "" {
						desc = line
						break
					}
				}
			}
			cfg := pagnetYAML{
				Version:     1,
				Network:     netName,
				Description: desc,
				Agents: []struct {
					Name             string `yaml:"name"`
					Runtime          string `yaml:"runtime"`
					Role             string `yaml:"role,omitempty"`
					Responsibilities []struct {
						Resource string   `yaml:"resource"`
						Actions  []string `yaml:"actions"`
					} `yaml:"responsibilities"`
				}{
					{
						Name:    name,
						Runtime: rt,
						Role:    role,
						Responsibilities: []struct {
							Resource string   `yaml:"resource"`
							Actions  []string `yaml:"actions"`
						}{
							{Resource: key, Actions: []string{"implement", "review", "advise"}},
						},
					},
				},
			}
			b, err := yaml.Marshal(cfg)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(absDir, ".pagnet.yaml"), b, 0o644); err != nil {
				return err
			}
			fmt.Println("wrote .pagnet.yaml:")
			fmt.Println(string(b))
			fmt.Println("never required for a basic launch; `pagnet run .` picks up these defaults")
			return nil
		},
	}
	cmd.Flags().BoolVar(&ai, "ai", false, "AI-assisted setup (not part of the MVP; spec §13)")
	cmd.Flags().StringVar(&networkName, "network", "", "network name to record (default: the saved/only network)")
	cmd.Flags().StringVarP(&runtimeName, "runtime", "r", "qwen", "suggested runtime (qwen|claude|fake)")
	cmd.Flags().StringVarP(&role, "role", "p", "", "role for the suggested agent (e.g. coder)")
	return cmd
}

// --- doctor -------------------------------------------------------------------

// doctorCmd diagnoses the local pagnet setup (spec §55 `pagnet doctor`).
// Required checks fail the exit code; runtime/docker presence is reported
// for information (not every host runs every runtime).
func doctorCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose the local pagnet setup (server, host, runtimes)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			failed := 0
			check := func(name string, ok bool, detail string) {
				mark := "ok"
				if !ok {
					mark = "FAIL"
					failed++
				}
				fmt.Printf("%-4s %-24s %s\n", mark, name, detail)
			}
			info := func(name, detail string) {
				fmt.Printf("     %-24s %s\n", name, detail)
			}

			// Config (may legitimately be absent — doctor still runs).
			if stateDir == "" {
				home, _ := os.UserHomeDir()
				stateDir = filepath.Join(home, ".pagnet")
			}
			cfg, _ := config.LoadDaemon(stateDir)
			server := serverURL
			if root != nil && root.PersistentFlags().Lookup("server") != nil &&
				!root.PersistentFlags().Changed("server") && cfg.ServerURL != "" {
				server = cfg.ServerURL
			}

			// 1. Server reachable?
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(server + "/healthz")
			if err != nil {
				check("server reachable", false, fmt.Sprintf("%s: %v", server, err))
				fmt.Println("\ndiagnosis failed: the control plane is unreachable")
				return errors.New("server unreachable")
			} else {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				if resp.StatusCode == 200 {
					check("server reachable", true, fmt.Sprintf("%s (%s)", server, strings.TrimSpace(string(body))))
				} else {
					check("server reachable", false, fmt.Sprintf("%s: http %d", server, resp.StatusCode))
					fmt.Println("\ndiagnosis failed: the control plane answered with an error")
					return errors.New("server unhealthy")
				}
			}

			// 2. REST token (user/admin) — host credentials are WSS-only
			// and never authenticate the CLI.
			restToken := userToken
			if restToken == "" {
				restToken = loadUserToken(stateDir)
			}
			if restToken != "" {
				req2, _ := http.NewRequest(http.MethodGet, server+"/api/v1/hosts", nil)
				req2.Header.Set("Authorization", "Bearer "+restToken)
				r2, err := client.Do(req2)
				if err != nil {
					check("REST token", false, err.Error())
				} else {
					io.Copy(io.Discard, io.LimitReader(r2.Body, 4096))
					r2.Body.Close()
					if r2.StatusCode == 200 {
						check("REST token", true, "accepted")
					} else {
						check("REST token", false, fmt.Sprintf("http %d — run `pagnet login` or check --token / $PAGNET_TOKEN", r2.StatusCode))
					}
				}
			} else {
				info("REST token", "none set — run `pagnet login` (or use --token / $PAGNET_TOKEN)")
			}

			// 3. Host login stored for the daemon?
			if cfg.Credential == "" || cfg.HostID == "" {
				check("host login stored", false, "no host login stored — run `pagnet enroll --token <enrollment-token>`")
			} else {
				check("host login stored", true, "credential + host id present (the daemon uses it over WSS)")
			}

			// 4. Daemon running (server's view of this host)?
			if cfg.HostID != "" {
				c := &cliCtx{base: server, cfg: cfg, token: userToken}
				d, err := c.hostDetail(cfg.HostID)
				if err != nil {
					check("daemon running", false, "cannot fetch host: "+err.Error())
				} else if d.Status == "online" {
					detail := "host online"
					if d.LastBeat != nil {
						detail += " (last heartbeat " + *d.LastBeat + ")"
					}
					check("daemon running", true, detail)
				} else {
					check("daemon running", false, "host is "+d.Status+" — start `pagnet -d`")
				}
			} else {
				check("daemon running", false, "no host id in config")
			}

			// 5. Default network exists?
			c := &cliCtx{base: server, cfg: cfg, token: userToken}
			if id, label, err := c.resolveNetwork(""); err != nil {
				check("default network", false, err.Error())
			} else {
				check("default network", true, label+" ("+id+")")
			}

			// 6. Tools (required: git; informational: runtimes, docker).
			if _, err := exec.LookPath("git"); err != nil {
				check("git installed", false, "not found in PATH (worktrees and RW isolation need it)")
			} else {
				check("git installed", true, "found")
			}
			for _, tool := range []string{"qwen", "claude", "docker"} {
				if _, err := exec.LookPath(tool); err == nil {
					info(tool+" installed", "found")
				} else {
					info(tool+" installed", "not found (only needed for that runtime)")
				}
			}

			// 7. Allowed roots resolvable?
			for _, r := range cfg.AllowedRoots {
				if fi, err := os.Stat(r); err != nil || !fi.IsDir() {
					check("allowed root "+r, false, "does not exist")
				} else {
					check("allowed root "+r, true, "ok")
				}
			}

			if failed > 0 {
				return fmt.Errorf("%d check(s) failed", failed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "daemon state dir with the login (default ~/.pagnet)")
	return cmd
}
