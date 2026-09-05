package main

// The everyday CLI verbs (spec §55 command surface): list, status, send,
// delegate, task, artifact.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func listCmd() *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:   "list <networks|hosts|agents|tasks|messages|instances>",
		Short: "List objects in the control plane",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			return runList(c, args[0], network)
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network for network-scoped listings (default: the saved/only network)")
	return cmd
}

// runList is the `list <target>` body, shared with the §55 top-level
// verbs (agents/hosts/networks/tasks in cli_surface.go).
func runList(c *cliCtx, target, network string) error {
	switch target {
	case "networks":
		var out []struct {
			ID   string `json:"ID"`
			Name string `json:"Name"`
			Slug string `json:"Slug"`
		}
		if err := c.get("/api/v1/networks", &out); err != nil {
			return err
		}
		rows := make([][]string, 0, len(out))
		for _, n := range out {
			rows = append(rows, []string{n.Name, n.Slug, n.ID})
		}
		printTable([]string{"NAME", "SLUG", "ID"}, rows)
	case "hosts":
		var out []cliHost
		if err := c.get("/api/v1/hosts", &out); err != nil {
			return err
		}
		rows := make([][]string, 0, len(out))
		for _, h := range out {
			rows = append(rows, []string{h.Name, h.Status, orDash(h.OS) + "/" + orDash(h.Arch), h.ID})
		}
		printTable([]string{"NAME", "STATUS", "OS", "ID"}, rows)
	case "agents", "tasks", "messages", "instances":
		netID, _, err := c.resolveNetwork(network)
		if err != nil {
			return err
		}
		switch target {
		case "agents":
			var out []struct {
				ID      string `json:"ID"`
				Name    string `json:"Name"`
				Kind    string `json:"Kind"`
				Runtime string `json:"DefaultRuntime"`
				Profile string `json:"Profile"`
			}
			if err := c.get("/api/v1/networks/"+netID+"/agents", &out); err != nil {
				return err
			}
			rows := make([][]string, 0, len(out))
			for _, a := range out {
				rows = append(rows, []string{a.Name, a.Kind, a.Runtime, a.Profile, a.ID})
			}
			printTable([]string{"NAME", "KIND", "RUNTIME", "PROFILE", "ID"}, rows)
		case "tasks":
			var out []struct {
				ID       string `json:"ID"`
				Title    string `json:"Title"`
				Status   string `json:"Status"`
				Assigned string `json:"AssignedAgentName"`
				Target   string `json:"TargetAgentName"`
			}
			if err := c.get("/api/v1/networks/"+netID+"/tasks?limit=200", &out); err != nil {
				return err
			}
			rows := make([][]string, 0, len(out))
			for _, t := range out {
				rows = append(rows, []string{t.ID, t.Status, orDash(t.Target), orDash(t.Assigned), t.Title})
			}
			printTable([]string{"ID", "STATUS", "TARGET", "ASSIGNED", "TITLE"}, rows)
		case "messages":
			var out []struct {
				ID    string `json:"ID"`
				Kind  string `json:"Kind"`
				From  string `json:"SenderAgentName"`
				To    string `json:"RecipientAgentName"`
				Deliv any    `json:"DeliveredAt"`
			}
			if err := c.get("/api/v1/networks/"+netID+"/messages?limit=100", &out); err != nil {
				return err
			}
			rows := make([][]string, 0, len(out))
			for _, m := range out {
				state := "delivered"
				if m.Deliv == nil {
					state = "pending"
				}
				rows = append(rows, []string{m.ID, m.Kind, orDash(m.From), orDash(m.To), state})
			}
			printTable([]string{"ID", "KIND", "FROM", "TO", "STATE"}, rows)
		case "instances":
			rows, err := c.instanceRows(netID)
			if err != nil {
				return err
			}
			printTable([]string{"AGENT", "INSTANCE", "STATUS", "HOST", "RUNTIME", "LAST ACTIVITY"}, rows)
		}
	default:
		return fmt.Errorf("unknown list target %q (networks|hosts|agents|tasks|messages|instances)", target)
	}
	return nil
}

// instanceRows lists every worker instance of a network with its host.
func (c *cliCtx) instanceRows(netID string) ([][]string, error) {
	var agents []struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
	}
	if err := c.get("/api/v1/networks/"+netID+"/agents", &agents); err != nil {
		return nil, err
	}
	hostNames := map[string]string{}
	var hosts []cliHost
	if err := c.get("/api/v1/hosts", &hosts); err != nil {
		return nil, err
	}
	for _, h := range hosts {
		hostNames[h.ID] = h.Name
	}
	rows := make([][]string, 0, 8)
	for _, a := range agents {
		var insts []struct {
			ID             string  `json:"ID"`
			HostID         string  `json:"HostID"`
			Status         string  `json:"Status"`
			Runtime        string  `json:"Runtime"`
			LastActivityAt string  `json:"LastActivityAt"`
			RetryAt        *string `json:"AvailabilityRetryAt"`
		}
		if err := c.get("/api/v1/networks/"+netID+"/agents/"+a.ID+"/instances", &insts); err != nil {
			return nil, err
		}
		for _, i := range insts {
			status := i.Status
			if i.RetryAt != nil {
				status += " (retry " + *i.RetryAt + ")"
			}
			rows = append(rows, []string{a.Name, i.ID, status, hostNames[i.HostID], i.Runtime, orDash(i.LastActivityAt)})
		}
	}
	return rows, nil
}

func statusCmd() *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:     "status",
		Aliases: []string{"ps"}, // spec §55 `pagnet ps`
		Short:   "Show network/host/agent status (§55 `pagnet ps`)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			var stats struct {
				Networks       int `json:"networks"`
				HostsOnline    int `json:"hostsOnline"`
				HostsOffline   int `json:"hostsOffline"`
				AgentsOnline   int `json:"agentsOnline"`
				AgentsBusy     int `json:"agentsBusy"`
				AgentsIdle     int `json:"agentsIdle"`
				AgentsSleeping int `json:"agentsSleeping"`
				AgentsRateLim  int `json:"agentsRateLimited"`
				AgentsFailed   int `json:"agentsFailed"`
				TasksPending   int `json:"tasksPending"`
				TasksWorking   int `json:"tasksWorking"`
				TasksBlocked   int `json:"tasksBlocked"`
				TasksFailed    int `json:"tasksFailed"`
			}
			if err := c.get("/api/v1/stats/overview", &stats); err != nil {
				return err
			}
			fmt.Println("overview:")
			fmt.Printf("  networks: %d   hosts: %d online / %d offline\n",
				stats.Networks, stats.HostsOnline, stats.HostsOffline)
			fmt.Printf("  agents: %d working, %d idle, %d sleeping, %d rate-limited, %d failed\n",
				stats.AgentsBusy, stats.AgentsIdle, stats.AgentsSleeping, stats.AgentsRateLim, stats.AgentsFailed)
			fmt.Printf("  tasks:  %d pending, %d working, %d blocked, %d failed\n",
				stats.TasksPending, stats.TasksWorking, stats.TasksBlocked, stats.TasksFailed)

			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			rows, err := c.instanceRows(netID)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Println("no agent instances in this network yet")
				return nil
			}
			fmt.Println("\ninstances:")
			printTable([]string{"AGENT", "INSTANCE", "STATUS", "HOST", "RUNTIME", "LAST ACTIVITY"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network for the instance list (default: the saved/only network)")
	return cmd
}

func sendCmd() *cobra.Command {
	var network, kind string
	cmd := &cobra.Command{
		Use:   "send <agent> <message...>",
		Short: "Send a network message to an agent",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			var m struct {
				ID          string  `json:"ID"`
				RecipientID *string `json:"RecipientInstanceID"`
			}
			if err := c.post("/api/v1/networks/"+netID+"/messages", map[string]any{
				"recipientAgent": args[0],
				"kind":           kind,
				"text":           strings.Join(args[1:], " "),
			}, &m); err != nil {
				return err
			}
			fmt.Printf("message %s sent to %s (delivery: durable; the agent is woken if sleeping)\n", m.ID, args[0])
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	cmd.Flags().StringVar(&kind, "kind", "ASK", "message kind: ASK|REPLY|NOTICE|STATUS")
	return cmd
}

func delegateCmd() *cobra.Command {
	var network, title, objective string
	var criteria []string
	cmd := &cobra.Command{
		Use:   "delegate <agent>",
		Short: "Create and delegate a task to an agent",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if !cmd.Flags().Changed("objective") {
				return errors.New("--objective is required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			if title == "" {
				title = objective
			}
			var t struct {
				ID     string `json:"ID"`
				Status string `json:"Status"`
			}
			if err := c.post("/api/v1/networks/"+netID+"/tasks", map[string]any{
				"targetAgent":        args[0],
				"title":              title,
				"objective":          objective,
				"acceptanceCriteria": criteria,
			}, &t); err != nil {
				return err
			}
			fmt.Printf("task %s (%s) delegated to %s\n", t.ID, t.Status, args[0])
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	cmd.Flags().StringVar(&title, "title", "", "task title (default: the objective)")
	cmd.Flags().StringVar(&objective, "objective", "", "what the task must achieve (required)")
	cmd.Flags().StringArrayVar(&criteria, "criteria", nil, "acceptance criterion (repeatable)")
	return cmd
}

func taskCmd() *cobra.Command {
	var network, reason string
	cmd := &cobra.Command{
		Use:   "task <list|show|status>",
		Short: "Inspect and update tasks",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List tasks",
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
			var out []struct {
				ID       string `json:"ID"`
				Title    string `json:"Title"`
				Status   string `json:"Status"`
				Assigned string `json:"AssignedAgentName"`
				Target   string `json:"TargetAgentName"`
			}
			if err := c.get("/api/v1/networks/"+netID+"/tasks?limit=200", &out); err != nil {
				return err
			}
			rows := make([][]string, 0, len(out))
			for _, t := range out {
				rows = append(rows, []string{t.ID, t.Status, orDash(t.Target), orDash(t.Assigned), t.Title})
			}
			printTable([]string{"ID", "STATUS", "TARGET", "ASSIGNED", "TITLE"}, rows)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "show <task>",
		Short: "Show one task",
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
			var t map[string]any
			if err := c.get("/api/v1/networks/"+netID+"/tasks/"+args[0], &t); err != nil {
				return err
			}
			for _, k := range []string{"ID", "Title", "Objective", "Status", "TargetAgentName", "AssignedAgentName", "FailureReason", "CreatedAt"} {
				if v, ok := t[k]; ok {
					fmt.Printf("%-18s %v\n", k+":", v)
				}
			}
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "status <task> <new-status>",
		Short: "Update a task status (--reason required for blocked/completed/failed)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			body := map[string]any{"status": args[1]}
			if reason != "" {
				body["reason"] = reason
			}
			var t struct {
				ID     string `json:"ID"`
				Status string `json:"Status"`
			}
			if err := c.post("/api/v1/networks/"+netID+"/tasks/"+args[0]+"/status",
				body, &t); err != nil {
				return err
			}
			fmt.Printf("task %s is now %s\n", t.ID, t.Status)
			return nil
		},
	})
	cmd.PersistentFlags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	cmd.PersistentFlags().StringVar(&reason, "reason", "", "reason for the status change (required for blocked/completed/failed)")
	return cmd
}

func artifactCmd() *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:   "artifact <list|show>",
		Short: "Fetch published artifacts",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List artifacts",
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
			var out []struct {
				ID    string `json:"ID"`
				Type  string `json:"Type"`
				Label string `json:"Label"`
				URI   string `json:"URI"`
			}
			if err := c.get("/api/v1/networks/"+netID+"/artifacts?limit=100", &out); err != nil {
				return err
			}
			rows := make([][]string, 0, len(out))
			for _, a := range out {
				rows = append(rows, []string{a.ID, a.Type, a.Label, a.URI})
			}
			printTable([]string{"ID", "TYPE", "LABEL", "URI"}, rows)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "show <artifact>",
		Short: "Show one artifact",
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
			var a map[string]any
			if err := c.get("/api/v1/networks/"+netID+"/artifacts/"+args[0], &a); err != nil {
				return err
			}
			for _, k := range []string{"ID", "Type", "Label", "URI", "TaskID", "CreatedAt"} {
				if v, ok := a[k]; ok {
					fmt.Printf("%-12s %v\n", k+":", v)
				}
			}
			return nil
		},
	})
	cmd.PersistentFlags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	return cmd
}
