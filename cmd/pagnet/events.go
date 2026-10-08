// The `pagnet events` observation surface (E4.4 spec): list and live-watch
// the network's events. Event payloads are encrypted end-to-end on the
// publisher's host (D6) and stay that way at the control plane — the
// listing and the watch stream carry only the envelope metadata (id,
// type, target, time), never payload content.

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func eventsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Observe network events (the payload is encrypted end-to-end)",
		Long: `Observe a network's events:

  pagnet events list    the network's recent events (envelope metadata only)
  pagnet events watch   live-tail the event stream (SSE, filtered)

Event payloads are encrypted end-to-end on the publisher's host and are
never listed or streamed in plaintext — these surfaces show the envelope
metadata (id, type, target, time) only. Publishing stays at
` + "`pagnet event publish`" + `.`,
	}
	cmd.AddCommand(eventsListCmd(), eventsWatchCmd())
	return cmd
}

func eventsListCmd() *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the network's recent events (envelope metadata only; the payload stays encrypted)",
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
			return runEventsListing(c, netID)
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	return cmd
}

func eventsWatchCmd() *cobra.Command {
	var (
		network   string
		eventType string
	)
	cmd := &cobra.Command{
		Use:   "watch [--type pattern]",
		Short: "Live-tail the network's events (SSE stream, filtered)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEventWatch(cmd, network, eventType)
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "only events of this network (default: all)")
	cmd.Flags().StringVar(&eventType, "type", "", "only events matching this type pattern (* wildcards)")
	return cmd
}

// eventsListingRow is one envelope-metadata row of the events listing.
// The dual JSON tags accept both the V2 lowercase and the legacy
// capitalized domain fields, exactly as the stream decoder does.
type eventsListingRow struct {
	ID           string  `json:"id"`
	IDLegacy     string  `json:"ID"`
	Type         string  `json:"type"`
	TypeLegacy   string  `json:"Type"`
	Target       *string `json:"targetPrincipalId"`
	TargetLegacy *string `json:"TargetAgentName"`
	Time         *string `json:"createdAt"`
	TimeLegacy   *string `json:"Timestamp"`
}

// runEventsListing is the shared network-events listing body, used by both
// `pagnet list events` and `pagnet events list`. It prints envelope
// metadata only: the payload is E2EE and is never fetched or rendered.
func runEventsListing(c *cliCtx, netID string) error {
	var out []eventsListingRow
	if err := c.get("/api/v1/networks/"+netID+"/events?limit=100", &out); err != nil {
		return err
	}
	if jsonOut {
		return printJSON(out)
	}
	if len(out) == 0 {
		fmt.Println("no events in this network yet")
		return nil
	}
	rows := make([][]string, 0, len(out))
	for _, e := range out {
		id := e.ID
		if id == "" {
			id = e.IDLegacy
		}
		typ := e.Type
		if typ == "" {
			typ = e.TypeLegacy
		}
		var target, ts string
		if e.Target != nil {
			target = *e.Target
		} else if e.TargetLegacy != nil {
			target = *e.TargetLegacy
		}
		if e.Time != nil {
			ts = *e.Time
		} else if e.TimeLegacy != nil {
			ts = *e.TimeLegacy
		}
		rows = append(rows, []string{id, typ, orDash(target), orDash(ts)})
	}
	printTable([]string{"ID", "TYPE", "TARGET", "TIME"}, rows)
	return nil
}
