package main

// `pagnet workspaces [--host <h>] [--resource <key>]` — list launch
// targets across registered hosts (addendum: Listing launch targets).

import (
	"fmt"
	"os"

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
	return cmd
}
