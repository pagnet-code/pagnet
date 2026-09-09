package main

// `pagnet workspaces [--host <h>] [--resource <key>]` — list launch
// targets across registered hosts (addendum: Listing launch targets).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func workspacesCmd() *cobra.Command {
	var host, resource string
	cmd := &cobra.Command{
		Use:   "workspaces",
		Short: "List workspaces (launch targets) across hosts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			keys := c.resourceKeys()

			// Which hosts to list.
			var hosts []cliHost
			if host != "" {
				h, err := c.hostByName(host)
				if err != nil {
					return err
				}
				hosts = []cliHost{*h}
			} else {
				if err := c.get("/api/v1/hosts", &hosts); err != nil {
					return err
				}
			}

			rows := make([][]string, 0, 8)
			for i := range hosts {
				h := &hosts[i]
				// The list endpoint omits workspaces; fetch per host.
				detail, err := c.hostDetail(h.ID)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: host %s: %v\n", h.Name, err)
					continue
				}
				for _, ws := range detail.Workspaces {
					key := ""
					if ws.ResourceID != nil {
						key = keys[*ws.ResourceID]
					}
					if resource != "" && key != resource {
						continue
					}
					branch := ws.Branch
					if branch == "" {
						branch = "-"
					}
					rows = append(rows, []string{h.Name, key, ws.Path, branch, h.Status})
				}
			}
			if len(rows) == 0 {
				fmt.Println("no matching workspaces (hosts report workspaces after a scan; run `pagnetd`)")
				return nil
			}
			printTable([]string{"HOST", "RESOURCE", "WORKSPACE", "BRANCH", "HOST STATUS"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "only workspaces on this host (name or id)")
	cmd.Flags().StringVar(&resource, "resource", "", "only workspaces of this resource (canonical key)")
	cmd.AddCommand(workspaceRemoveCmd())
	return cmd
}

// `pagnet workspaces remove <path> [--host <h>]` — remove a workspace
// registration (the directory itself is untouched). Discovered git
// repositories reappear on the next inventory scan; explicitly added
// non-git workspaces stay gone until re-added.
func workspaceRemoveCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "remove <path>",
		Short: "Remove a workspace registration (the directory itself is untouched)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			abs, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			var targets []cliHost
			switch {
			case host != "":
				h, err := c.hostByName(host)
				if err != nil {
					return err
				}
				targets = []cliHost{*h}
			case c.cfg.HostID != "":
				h, err := c.hostDetail(c.cfg.HostID)
				if err != nil {
					return err
				}
				targets = []cliHost{*h}
			default:
				return errors.New("no pagnet host config found; pass --host <name>")
			}
			removed := 0
			for i := range targets {
				h := &targets[i]
				detail, err := c.hostDetail(h.ID)
				if err != nil {
					return err
				}
				for _, ws := range detail.Workspaces {
					if ws.Path != abs {
						continue
					}
					if err := c.del("/api/v1/hosts/" + h.ID + "/workspaces/" + ws.ID); err != nil {
						return fmt.Errorf("remove %s from host %s: %w", abs, h.Name, err)
					}
					fmt.Printf("removed workspace %s from host %s\n", ws.Path, h.Name)
					removed++
				}
			}
			if removed == 0 {
				return fmt.Errorf("workspace %s not found on host %s", abs, targets[0].Name)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "remove from this host (default: this machine's host)")
	return cmd
}
