package main

// `pagnet network use <name>` — set the default network for subsequent
// commands (addendum: Network selection). `pagnet network list` shows
// the available networks.

import (
	"fmt"

	"github.com/spf13/cobra"

	"pagnet/internal/config"
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
	)
	return cmd
}
