package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/config"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	otel "github.com/pagnet-code/pagnet/internal/telemetry"
	"github.com/spf13/cobra"
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
	// A missing installation never creates state (not even the telemetry
	// store dir): refuse before any file is touched.
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no local Fabric installation at %s (run 'pagnet fabric install' first)", dir)
		}
		return err
	}
	// Observability stack (E4.4): the daemon telemetry config (env + the
	// local installation dir's state file, if any) + the bounded durable
	// metadata-only trace store inside the local installation. The empty
	// endpoint keeps the no-op export default.
	localCfg, err := config.LoadDaemon(dir)
	if err != nil {
		return fmt.Errorf("load local telemetry config: %w", err)
	}
	tel, err := otel.Compose(ctx, telemetryStackConfig(localCfg, filepath.Join(dir, "telemetry")))
	if err != nil {
		return fmt.Errorf("compose observability: %w", err)
	}
	n, err := fabricnode.OpenInstalled(ctx, fabricnode.InstalledConfig{Directory: dir, Binary: binary, Federation: &fabricnode.InstalledFederationConfig{}, Actions: &fabricnode.InstalledActionsConfig{}, Tracing: tel.Provider})
	if err != nil {
		var retained *fabricnode.InstalledOpenError
		if errors.As(err, &retained) {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err = errors.Join(err, retained.CloseContext(cleanup))
		}
		shutdown, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		if shutdownErr := tel.Shutdown(shutdown); shutdownErr != nil {
			err = errors.Join(err, shutdownErr)
		}
		return err
	}
	// Defer order (LIFO): the stack shutdown registers FIRST, so the node
	// close runs BEFORE it — the node's final spans end into the store and
	// the exporter queue, then the stack flushes and closes.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := tel.Shutdown(cleanup); err != nil {
			err = errors.Join(err, fmt.Errorf("observability shutdown: %w", err))
		}
	}()
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
