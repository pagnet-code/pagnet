package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	"github.com/spf13/cobra"
	"path/filepath"
)

func runLocalFabricDaemon(cmd *cobra.Command, directory string) (err error) {
	dir, _, err := localFabricPaths(directory, "")
	if err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	n, err := fabricnode.OpenInstalled(ctx, fabricnode.InstalledConfig{Directory: dir, Binary: binary, Federation: &fabricnode.InstalledFederationConfig{}, Actions: &fabricnode.InstalledActionsConfig{}})
	if err != nil {
		var retained *fabricnode.InstalledOpenError
		if errors.As(err, &retained) {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err = errors.Join(err, retained.CloseContext(cleanup))
		}
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = errors.Join(err, n.CloseContext(cleanup))
	}()
	if !silent {
		if _, err = fmt.Fprintf(cmd.OutOrStdout(), "Local Pagnet node ready.\nMCP: pagnet mcp fabric --socket %q\n", n.Installation.Configuration().Settings.SocketPath); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}

// Local detachment validates the actual installed root before spawning. It
// never enters cloud account loading/enrollment and forwards the exact selected
// installation rather than silently launching another daemon mode.
func runLocalFabricDetached(cmd *cobra.Command, directory string) error {
	for _, name := range []string{"state-dir", "debug", "server", "account", "token"} {
		if cmd.Flags().Changed(name) {
			return fmt.Errorf("--%s does not apply to local Fabric serve", name)
		}
	}
	dir, _, err := localFabricPaths(directory, "")
	if err != nil {
		return err
	}
	installed, err := localinstallation.Load(cmd.Context(), dir, registry.DefaultOptions())
	if err != nil {
		return err
	}
	socket := installed.Configuration().Settings.SocketPath
	if err = localinstallation.VerifySocketDirectory(socket); err != nil {
		installed.Close()
		return err
	}
	if err = installed.Close(); err != nil {
		return err
	}
	return daemonizeSelf(filepath.Dir(socket), []string{"serve", "--local", "--local-dir", dir})
}
