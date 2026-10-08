// The `pagnet trace <invocation>` inspection command (E4.4): it reads the
// daemon's bounded durable trace store and prints the invocation's
// recorded spans — metadata only (names, stages, phases, dispositions,
// durations). The store never records payloads, secrets, prompts or
// credentials, so there is nothing to redact on the way out: the printed
// fields are exactly the bounded metadata the store holds.

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	otel "github.com/pagnet-code/pagnet/internal/telemetry"
)

func traceCmd() *cobra.Command {
	var (
		stateDir string
		limit    int
	)
	cmd := &cobra.Command{
		Use:   "trace <invocation>",
		Short: "Inspect the recorded spans of one invocation (metadata only)",
		Long: `Print the spans the daemon durably recorded for one invocation:
the span names, stages, phases, dispositions and durations, oldest
first.

The trace store is metadata-only BY CONSTRUCTION — the daemon records
only the bounded pagnet.* span metadata (no payloads, secrets, prompts
or credentials) and prunes it by the configured retention (default 30
days, bounded row cap). Nothing is ever printed that was not durably
recorded as bounded metadata.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := machineStateDir(stateDir)
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			spans, err := readInvocationSpans(ctx, root, args[0], limit)
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(spans)
			}
			if len(spans) == 0 {
				fmt.Printf("no recorded spans for invocation %s (traces are retained locally for the daemon's configured retention)\n", args[0])
				return nil
			}
			fmt.Printf("invocation %s (%d recorded span%s):\n", args[0], len(spans), plural(len(spans)))
			rows := make([][]string, 0, len(spans))
			for _, sp := range spans {
				rows = append(rows, []string{
					time.Unix(0, sp.Start).UTC().Format("2006-01-02 15:04:05.000"),
					sp.Name,
					orDash(sp.Stage),
					orDash(sp.Phase),
					orDash(sp.Disposition),
					sp.Duration().Round(time.Millisecond).String(),
					sp.SpanID,
				})
			}
			printTable([]string{"START (UTC)", "SPAN", "STAGE", "PHASE", "DISPOSITION", "DURATION", "SPAN ID"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "daemon state dir (default ~/.pagnet)")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum spans to print (1-10000, default 100)")
	return cmd
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// readInvocationSpans opens the daemon's durable trace store (read-only;
// a missing store is the honest no-traces state, not an error) and lists
// the invocation's recorded spans.
func readInvocationSpans(ctx context.Context, root, invocation string, limit int) ([]otel.SpanRecord, error) {
	store, err := otel.OpenTraceStoreReadonly(filepath.Join(root, "telemetry"))
	if err != nil {
		if errors.Is(err, otel.ErrStoreMissing) {
			return []otel.SpanRecord{}, nil // no store yet = no recorded spans (not an error)
		}
		return nil, fmt.Errorf("open trace store: %w", err)
	}
	defer store.Close()
	return store.SpansForInvocation(ctx, invocation, limit)
}
