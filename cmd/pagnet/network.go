package main

// `pagnet network use <name>` — set the default network for subsequent
// commands (addendum: Network selection). `pagnet network list` shows
// the available networks.

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/pagnet-code/pagnet/internal/config"
)

func networkCmd() *cobra.Command {
	var slug, description string
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a network (§55 `pagnet network create`)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			s := slug
			if s == "" {
				s = slugify(args[0])
			}
			body := map[string]any{"name": args[0], "slug": s}
			if description != "" {
				body["description"] = description
			}
			var created struct {
				ID   string `json:"ID"`
				Name string `json:"Name"`
			}
			if err := c.post("/api/v1/networks", body, &created); err != nil {
				return err
			}
			fmt.Printf("network:   %s (%s)\n", created.Name, created.ID)
			return nil
		},
	}
	create.Flags().StringVar(&slug, "slug", "", "network slug (default: derived from the name)")
	create.Flags().StringVar(&description, "description", "", "network description")

	cmd := &cobra.Command{
		Use:   "network",
		Short: "Manage networks (select the default with `use`)",
	}
	cmd.AddCommand(
		create,
		networkMembersCmd(),
		&cobra.Command{
			Use:   "use <name>",
			Short: "Set the default network (id, name, or slug)",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := newCLI("")
				if err != nil {
					return err
				}
				id, label, err := c.resolveNetwork(args[0])
				if err != nil {
					return err
				}
				if err := config.SaveCurrentNetwork(c.stateDir, id); err != nil {
					return err
				}
				fmt.Printf("default network: %s (%s)\n", label, id)
				return nil
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List networks",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				c, err := newCLI("")
				if err != nil {
					return err
				}
				var nets []struct {
					ID   string `json:"ID"`
					Name string `json:"Name"`
					Slug string `json:"Slug"`
				}
				if err := c.get("/api/v1/networks", &nets); err != nil {
					return err
				}
				rows := make([][]string, 0, len(nets))
				for _, n := range nets {
					marker := ""
					if c.cfg.CurrentNetwork == n.ID {
						marker = "*"
					}
					rows = append(rows, []string{marker, n.Name, n.Slug, n.ID})
				}
				printTable([]string{"", "NAME", "SLUG", "ID"}, rows)
				return nil
			},
		},
		&cobra.Command{
			Use:   "rename <name> <new-name>",
			Short: "Rename a network (id, name, or slug)",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := newCLI("")
				if err != nil {
					return err
				}
				id, label, err := c.resolveNetwork(args[0])
				if err != nil {
					return err
				}
				if err := c.put("/api/v1/networks/"+id, map[string]any{"name": args[1]}); err != nil {
					return err
				}
				fmt.Printf("network %q renamed to %q (%s)\n", label, args[1], id)
				return nil
			},
		},
		&cobra.Command{
			Use:   "delete <name>",
			Short: "Delete a network and its agents, tasks, and messages",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := newCLI("")
				if err != nil {
					return err
				}
				id, label, err := c.resolveNetwork(args[0])
				if err != nil {
					return err
				}
				if err := c.del("/api/v1/networks/" + id); err != nil {
					return err
				}
				// If the deleted network was the saved default, clear it so
				// the next command does not resolve a dead network.
				if c.cfg.CurrentNetwork == id {
					if err := config.SaveCurrentNetwork(c.stateDir, ""); err != nil {
						return err
					}
				}
				fmt.Printf("network %q deleted (%s)\n", label, id)
				return nil
			},
		},
	)
	return cmd
}
