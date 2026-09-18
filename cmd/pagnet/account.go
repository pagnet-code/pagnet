package main

// `pagnet account` — manage the CLI's Pagnet account contexts (personal /
// work). An account is a directory under ~/.pagnet/accounts/<name>/ holding
// its own server, host identity + credential, and user credential. One
// CURRENT account is the default for commands and the running service.
//
// The CLI may hold several accounts for the same server URL; host IDs and
// credentials never leak across accounts. "account" is the user-facing word
// (NOT "profiles" — Agent Profiles already exist).

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/pagnet-code/pagnet/internal/accounts"
	"github.com/pagnet-code/pagnet/internal/config"
)

func accountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Manage Pagnet accounts (list, current, use)",
	}
	cmd.AddCommand(accountListCmd(), accountCurrentCmd(), accountUseCmd())
	return cmd
}

// accountRow is one account's display data (never a credential).
type accountRow struct {
	Account string `json:"account"`
	Server  string `json:"server,omitempty"`
	Current bool   `json:"current"`
}

// accountRows loads every account context's name + server (the server is
// read from each account's config; no credential is read or shown).
func accountRows(root string) ([]accountRow, error) {
	names, err := accounts.List(root)
	if err != nil {
		return nil, err
	}
	current := accounts.ActiveAccount(root, accountFlag)
	rows := make([]accountRow, 0, len(names))
	for _, n := range names {
		row := accountRow{Account: n, Current: n == current}
		if cfg, err := config.LoadDaemon(accounts.ConfigDir(root, n)); err == nil {
			row.Server = cfg.ServerURL
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func accountListCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List accounts (ACCOUNT  SERVER  CURRENT)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root := machineStateDir(stateDir)
			if _, err := accounts.MigrateLegacy(root); err != nil {
				return err
			}
			rows, err := accountRows(root)
			if err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(cmd, rows)
			}
			if len(rows) == 0 {
				fmt.Println("no accounts yet — run `pagnet login` to sign in")
				return nil
			}
			table := make([][]string, 0, len(rows))
			for _, r := range rows {
				marker := " "
				if r.Current {
					marker = "*"
				}
				table = append(table, []string{r.Account, orDash(r.Server), marker})
			}
			printTable([]string{"ACCOUNT", "SERVER", "CURRENT"}, table)
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "state dir (default ~/.pagnet)")
	return cmd
}

func accountCurrentCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "current",
		Short: "Show the current account",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root := machineStateDir(stateDir)
			if _, err := accounts.MigrateLegacy(root); err != nil {
				return err
			}
			cur := accounts.ActiveAccount(root, accountFlag)
			if jsonOut {
				return writeJSON(cmd, map[string]string{"account": cur})
			}
			fmt.Println(cur)
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "state dir (default ~/.pagnet)")
	return cmd
}

func accountUseCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "use <name>",
		Short: "Switch the current account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := machineStateDir(stateDir)
			name := args[0]
			if _, err := accounts.MigrateLegacy(root); err != nil {
				return err
			}
			if !accounts.Exists(root, name) {
				return fmt.Errorf("account %q does not exist (run `pagnet account list`)", name)
			}
			prev := accounts.ActiveAccount(root, "")
			if err := accounts.SetCurrent(root, name); err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(cmd, map[string]string{"account": name})
			}
			fmt.Printf("Account switched to %s.\n", name)
			// A daemon running under a DIFFERENT account keeps its own host;
			// note the restart without killing it.
			if prev != name && daemonRunning(root) {
				fmt.Println("Restart Pagnet to run this host under that account.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "state dir (default ~/.pagnet)")
	return cmd
}

// writeJSON emits v as indented JSON on the command's stdout.
func writeJSON(cmd *cobra.Command, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(b))
	return nil
}
