package main

// `pagnet host <action>` — host lifecycle actions the flat `pagnet hosts`
// list does not cover. `host rm` is the control-plane delete (the web
// console's "Delete host"): it stops the host's running agents and removes
// the host row (credential, roots, workspaces, instances); a Pagnet service
// running on that machine receives host.unenrolled and stops itself.
// Self-decommissioning THIS machine is `pagnet unenroll`.

import (
	"fmt"

	"github.com/spf13/cobra"
)

func hostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Manage a host (delete a remote host with `rm`)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a host and its agents, workspaces, and credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			h, err := c.hostByName(args[0])
			if err != nil {
				return err
			}
			if err := c.del("/api/v1/hosts/" + h.ID); err != nil {
				return err
			}
			fmt.Printf("host %q deleted (%s); running agents stopped\n", h.Name, h.ID)
			return nil
		},
	})
	return cmd
}
