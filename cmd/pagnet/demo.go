package main

// `pagnet demo` — seed a demo network with fake agents and sample tasks so
// the web UI has live data to show (spec §97 "fake runtime works fully";
// backs the Makefile `demo` target).
//
// It is an ADMIN operation (it creates networks and launches instances), so
// it authenticates with the admin bearer token (--admin-token, default
// $PAGNET_ADMIN_TOKEN). In local development mode (loopback) no token is
// needed. It reuses the same launch flow as `pagnet run`: create/reuse a
// network, pick an online host, create resources + agent definitions, launch
// fake instances, and delegate sample tasks. Idempotent: re-runs reuse
// live instances and never duplicate the sample tasks.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func demoCmd() *cobra.Command {
	var network, adminToken, webURL string
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Seed a demo network with fake agents and sample tasks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if adminToken == "" {
				adminToken = os.Getenv("PAGNET_ADMIN_TOKEN")
			}
			// Standalone admin client: no host login required. The admin
			// bearer token authenticates the REST calls; empty means dev
			// loopback auto-admin.
			if serverURL == "" {
				return errors.New("no control plane URL — set --server / $PAGNET_SERVER")
			}
			c := &cliCtx{base: serverURL, token: adminToken}
			return runDemo(c, network, webURL)
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "demo", "network name/slug to seed (default demo)")
	cmd.Flags().StringVar(&adminToken, "admin-token", "", "admin bearer token (default $PAGNET_ADMIN_TOKEN; empty = dev loopback)")
	cmd.Flags().StringVar(&webURL, "web-url", "http://localhost:13000", "web UI URL to print at the end")
	return cmd
}

func runDemo(c *cliCtx, network, webURL string) error {
	// The demo seeds FAKE agents, and the fake runtime is registered only
	// in debug mode. Enable debug in this process's environment so the
	// demo is unambiguously a debug tool (and any daemon sharing this
	// environment registers the fake runtime); the host daemon that
	// executes the launches must be running with debug too (pagnet
	// daemon --debug / PAGNET_DEBUG=1) for the fake agents to actually
	// run.
	_ = os.Setenv("PAGNET_DEBUG", "1")

	// 1. Network (create if missing).
	var nets []struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
		Slug string `json:"Slug"`
	}
	if err := c.get("/api/v1/networks", &nets); err != nil {
		return fmt.Errorf("list networks: %w", err)
	}
	netID, netName := "", ""
	for i := range nets {
		if nets[i].Name == network || nets[i].Slug == network {
			netID, netName = nets[i].ID, nets[i].Name
			break
		}
	}
	if netID == "" {
		var created struct {
			ID string `json:"ID"`
		}
		if err := c.post("/api/v1/networks", map[string]any{
			"name": network, "slug": slugify(network), "description": "pagnet demo network",
		}, &created); err != nil {
			return fmt.Errorf("create network: %w", err)
		}
		netID, netName = created.ID, network
		fmt.Printf("network:   %s (created)\n", netName)
	} else {
		fmt.Printf("network:   %s (%s)\n", netName, netID)
	}

	// 2. An online host with a registered workspace (executes the launches).
	var hosts []cliHost
	if err := c.get("/api/v1/hosts", &hosts); err != nil {
		return fmt.Errorf("list hosts: %w", err)
	}
	hostID, hostName, workspaceID := "", "", ""
	for i := range hosts {
		if hosts[i].Status != "online" {
			continue
		}
		hd, err := c.hostDetail(hosts[i].ID)
		if err != nil || len(hd.Workspaces) == 0 {
			continue
		}
		hostID, hostName, workspaceID = hd.ID, hd.Name, hd.Workspaces[0].ID
		break
	}
	if hostID == "" {
		return fmt.Errorf("no online host with a registered workspace — start `pagnet -d` (with a git repository under an allowed root) and re-run")
	}
	fmt.Printf("host:      %s (%s)\n", hostName, hostID)
	fmt.Printf("workspace: %s\n", workspaceID)

	// 3. Agents: resource + definition (idempotent) + fake instance launch.
	type demoAgent struct {
		name, role string
	}
	agents := []demoAgent{{"demo-planner", "planner"}, {"demo-coder", "coder"}, {"demo-reviewer", "reviewer"}}
	type launched struct {
		name, defID, instID string
	}
	var insts []launched
	for _, a := range agents {
		var res struct {
			ID string `json:"ID"`
		}
		if err := c.post("/api/v1/networks/"+netID+"/resources", map[string]any{"key": "demo-software"}, &res); err != nil {
			return fmt.Errorf("resource: %w", err)
		}
		defID, err := c.ensureAgentDef(netID, a.name, a.role, res.ID)
		if err != nil {
			return err
		}
		// Idempotent: reuse a live instance, launch only when there is
		// none (or only stopped/failed ones left).
		var insts0 []struct {
			ID     string `json:"ID"`
			Status string `json:"Status"`
		}
		if err := c.get("/api/v1/networks/"+netID+"/agents/"+defID+"/instances", &insts0); err != nil {
			return fmt.Errorf("list instances %s: %w", a.name, err)
		}
		instID := ""
		for _, i := range insts0 {
			if i.Status != "stopped" && i.Status != "failed" {
				instID = i.ID
				break
			}
		}
		switch {
		case instID != "":
			fmt.Printf("agent:     %-14s def=%s instance=%s (reused)\n", a.name, defID, instID)
		default:
			var inst struct {
				ID string `json:"ID"`
			}
			if err := c.post("/api/v1/networks/"+netID+"/agents/"+defID+"/launch",
				map[string]any{"hostId": hostID, "workspaceId": workspaceID, "runtime": "fake"}, &inst); err != nil {
				return fmt.Errorf("launch %s: %w (the fake runtime is debug-only — run the host daemon with --debug or PAGNET_DEBUG=1)", a.name, err)
			}
			instID = inst.ID
			fmt.Printf("agent:     %-14s def=%s instance=%s\n", a.name, defID, instID)
		}
		insts = append(insts, launched{name: a.name, defID: defID, instID: instID})
	}

	// 4. Wait until the daemon has applied the launches.
	deadline := time.Now().Add(30 * time.Second)
	for _, l := range insts {
		for time.Now().Before(deadline) {
			var cur struct {
				Instance struct {
					Status string `json:"Status"`
				} `json:"instance"`
			}
			if err := c.get("/api/v1/networks/"+netID+"/agents/"+l.defID+"/instances/"+l.instID, &cur); err != nil {
				break
			}
			if s := cur.Instance.Status; s == "idle" || s == "working" || s == "hibernated" {
				break
			}
			time.Sleep(time.Second)
		}
	}

	// 5. Sample tasks, one per agent (routed to the named agent).
	//    Idempotent: a task with the same title is not re-created.
	type demoTask struct{ title, objective, agent string }
	tasks := []demoTask{
		{"Plan the demo feature", "Produce a short implementation plan for a demo feature.", "demo-planner"},
		{"Implement the demo feature", "Implement the demo feature described by the plan.", "demo-coder"},
		{"Review the implementation", "Review the implementation and report any issues.", "demo-reviewer"},
	}
	var existing []struct {
		ID    string `json:"ID"`
		Title string `json:"Title"`
	}
	if err := c.get("/api/v1/networks/"+netID+"/tasks?limit=200", &existing); err != nil {
		return fmt.Errorf("list tasks: %w", err)
	}
	have := map[string]string{}
	for _, e := range existing {
		have[e.Title] = e.ID
	}
	for _, t := range tasks {
		if id, ok := have[t.title]; ok {
			fmt.Printf("task:      %-28s -> %s (%s, existing)\n", t.title, t.agent, id)
			continue
		}
		var out struct {
			ID string `json:"ID"`
		}
		if err := c.post("/api/v1/networks/"+netID+"/tasks", map[string]any{
			"title": t.title, "objective": t.objective,
			"acceptanceCriteria": []string{"completed"},
			"targetAgent":        t.agent,
		}, &out); err != nil {
			return fmt.Errorf("delegate %q: %w", t.title, err)
		}
		fmt.Printf("task:      %-28s -> %s (%s)\n", t.title, t.agent, out.ID)
	}

	fmt.Printf("\nDone. Open the web UI to watch the demo:\n  %s\n", webURL)
	fmt.Println("The fake agents echo their turns; real qwen/claude agents drive full task state.")
	fmt.Println("The fake runtime is debug-only: the host daemon must run with --debug or PAGNET_DEBUG=1.")
	return nil
}

// ensureAgentDef returns the agent definition id for name, creating it (bound
// to resourceID) when absent.
func (c *cliCtx) ensureAgentDef(netID, name, role, resourceID string) (string, error) {
	var agents []struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
	}
	if err := c.get("/api/v1/networks/"+netID+"/agents", &agents); err != nil {
		return "", fmt.Errorf("list agents: %w", err)
	}
	for _, a := range agents {
		if a.Name == name {
			return a.ID, nil
		}
	}
	var created struct {
		ID string `json:"ID"`
	}
	if err := c.post("/api/v1/networks/"+netID+"/agents", map[string]any{
		"name":    name,
		"runtime": "fake",
		"profile": role,
		"capabilities": []any{
			map[string]any{"id": "code", "name": "code", "description": "reads and writes code in this repository"},
		},
		"executionSettings": map[string]any{"access": "read_write"},
		"responsibilities": []any{
			map[string]any{"resourceId": resourceID, "actions": []string{"implement", "review", "advise"}},
		},
	}, &created); err != nil {
		return "", fmt.Errorf("create agent %s: %w", name, err)
	}
	return created.ID, nil
}

// slugify derives a URL slug from a name (shared with `network create`).
func slugify(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteRune('-')
			lastDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "demo"
	}
	return slug
}
