package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	"github.com/spf13/cobra"
)

// localFabricPaths is shared by explicit local initialization/serve/client
// composition. Defaults are private Pagnet paths, independent of cloud accounts.
func localFabricPaths(authority, socket string) (string, string, error) {
	if authority == "" || socket == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", "", e
		}
		if authority == "" {
			authority = filepath.Join(home, ".pagnet", "fabric", "local")
		}
		if socket == "" {
			socket = filepath.Join(home, ".pagnet", "run", "fabric", "local.sock")
		}
	}
	authority, e := filepath.Abs(authority)
	if e != nil {
		return "", "", e
	}
	socket, e = filepath.Abs(socket)
	if e != nil {
		return "", "", e
	}
	return authority, socket, nil
}
func configureLocalFabricInit(cmd *cobra.Command) {
	var local bool
	var directory, socket string
	projectInit := cmd.RunE
	cmd.Flags().BoolVar(&local, "local", false, "initialize this operator's private local Pagnet installation")
	cmd.Flags().StringVar(&directory, "local-dir", "", "local authority directory (default ~/.pagnet/fabric/local; requires --local)")
	cmd.Flags().StringVar(&socket, "local-socket", "", "local private socket (default ~/.pagnet/run/fabric/local.sock; requires --local)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if !local {
			if cmd.Flags().Changed("local-dir") || cmd.Flags().Changed("local-socket") {
				return errors.New("--local-dir and --local-socket require --local")
			}
			return projectInit(cmd, args)
		}
		for _, name := range []string{"ai", "network", "runtime", "role"} {
			if cmd.Flags().Changed(name) {
				return fmt.Errorf("--%s configures project initialization; omit it with --local", name)
			}
		}
		authority, socket, e := localFabricPaths(directory, socket)
		if e != nil {
			return e
		}
		if e = fabrichost.ValidateSocketPath(socket); e != nil {
			return e
		}
		settings := localinstallation.DefaultSettings(socket)
		if e = localinstallation.PrepareBootstrapParents(authority, settings); e != nil {
			return e
		}
		installed, e := localinstallation.Bootstrap(cmd.Context(), authority, localinstallation.Options{Settings: settings})
		status, domain := "initialized", ""
		if e != nil {
			var existing *localinstallation.AlreadyInstalledError
			if !errors.As(e, &existing) {
				return e
			}
			status, domain = "already_installed", existing.Domain
			retained, err := localinstallation.Load(cmd.Context(), authority, registry.Options{})
			if err != nil {
				return err
			}
			if err = fabrichost.ValidateSocketPath(retained.Configuration().Settings.SocketPath); err != nil {
				return errors.Join(err, retained.Close())
			}
			if err = fabricnode.InitializeDefaultServices(cmd.Context(), retained); err != nil {
				return errors.Join(err, retained.Close())
			}
			socket = retained.Configuration().Settings.SocketPath
			if err = retained.Close(); err != nil {
				return err
			}
		} else {
			if e = fabricnode.InitializeDefaultServices(cmd.Context(), installed); e != nil {
				return errors.Join(e, installed.Close())
			}
			domain = installed.Configuration().Domain
			if e = installed.Close(); e != nil {
				return e
			}
		}
		if jsonOut {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				Status    string `json:"status"`
				Domain    string `json:"domain"`
				Directory string `json:"directory"`
				Socket    string `json:"socket"`
			}{status, domain, authority, socket})
		}
		if silent {
			return nil
		}
		if status == "already_installed" {
			fmt.Fprintln(cmd.OutOrStdout(), "Local Pagnet is already initialized; its identity and keys are unchanged.")
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Local Pagnet initialized.")
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Authority: %s\nSocket: %s\n", authority, socket)
		return nil
	}
}
