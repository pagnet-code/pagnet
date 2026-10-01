package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/externalprofile"
	"github.com/pagnet-code/pagnet/internal/runtimeconnect"
	"github.com/spf13/cobra"
)

func mcpRuntimeConnectCmd() *cobra.Command {
	var state, profile, origin, workspace, session, clientID, tokenFile, runtime string
	cmd := &cobra.Command{Use: "runtime-connect", Args: cobra.NoArgs, Short: "Add a private external MCP profile to an authenticated existing Qwen serve workspace", RunE: func(cmd *cobra.Command, _ []string) error {
		if domain.CanonicalRuntime(runtime) != domain.RuntimeQwenCode {
			return errors.New("automatic live connection currently supports Qwen serve only; use documented native MCP configuration for other runtimes")
		}
		dir, err := filepath.Abs(machineStateDir(state))
		if err != nil {
			return err
		}
		p, cfg, err := externalProfileConfig(dir, profile)
		if err != nil {
			return err
		}
		if err := verifyExternalProfile(cmd.Context(), p, cfg); err != nil {
			return err
		}
		workspace, err = filepath.EvalSymlinks(workspace)
		if err != nil {
			return errors.New("workspace must be an existing absolute local directory")
		}
		workspace, err = filepath.Abs(workspace)
		if err != nil {
			return err
		}
		info, err := os.Stat(workspace)
		if err != nil || !info.IsDir() {
			return errors.New("workspace must be a local directory")
		}
		tokenFile, err = filepath.Abs(tokenFile)
		if err != nil {
			return err
		}
		token, err := externalprofile.ReadSecret(tokenFile)
		if err != nil {
			return err
		}
		name := "pagnet_external_" + strings.ReplaceAll(domain.NewID().String(), "-", "")
		binding := runtimeconnect.Binding{URL: origin, Workspace: workspace, Session: session, Client: clientID, Name: name, TokenFile: tokenFile}
		qwen, err := runtimeconnect.NewQwen(binding, token)
		if err != nil {
			return err
		}
		if err := qwen.Preflight(cmd.Context()); err != nil {
			return err
		}
		executable, err := os.Executable()
		if err != nil {
			return errors.New("cannot locate Pagnet executable")
		}
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "runtime-connections", name+".json")
		// Persist before mutation: even an ambiguous timeout leaves a named cleanup
		// handle, rather than leaking an unrecorded live connection.
		if err := externalprofile.SaveBinding(path, binding); err != nil {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Connection record: %s (use runtime-disconnect with this name if setup fails).\n", name)
		if err := qwen.Connect(cmd.Context(), executable, profile, dir); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Connected Pagnet MCP tools in Qwen workspace. Connection: %s. Existing session and terminal remain owned by Qwen.\n", name)
		return nil
	}}
	cmd.Flags().StringVar(&runtime, "runtime", "qwen-code", "native runtime (Qwen serve currently supported)")
	cmd.Flags().StringVar(&state, "state-dir", "", "private profile state directory")
	cmd.Flags().StringVar(&profile, "profile", "", "private external profile name")
	cmd.Flags().StringVar(&origin, "url", "", "explicit authenticated Qwen serve loopback origin")
	cmd.Flags().StringVar(&workspace, "workspace", "", "exact local workspace path")
	cmd.Flags().StringVar(&session, "session", "", "existing live native session ID")
	cmd.Flags().StringVar(&clientID, "client-id", "", "existing registered Qwen client ID for that workspace")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "private file containing the Qwen operator token")
	for _, flag := range []string{"profile", "url", "workspace", "session", "client-id", "token-file"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}
func mcpRuntimeDisconnectCmd() *cobra.Command {
	var state, tokenFile, clientID string
	cmd := &cobra.Command{Use: "runtime-disconnect CONNECTION", Args: cobra.ExactArgs(1), Short: "Remove only the recorded Pagnet MCP entry; keep the external runtime running", RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if !strings.HasPrefix(name, "pagnet_external_") || strings.ContainsAny(name, "/\\") || len(name) != 48 {
			return errors.New("invalid Pagnet runtime connection name")
		}
		path := filepath.Join(machineStateDir(state), "runtime-connections", name+".json")
		var binding runtimeconnect.Binding
		if err := externalprofile.LoadBinding(path, &binding); err != nil {
			return err
		}
		if binding.Name != name {
			return errors.New("connection record identity mismatch")
		}
		if tokenFile != "" {
			binding.TokenFile = tokenFile
		}
		if clientID != "" {
			binding.Client = clientID
		}
		token, err := externalprofile.ReadSecret(binding.TokenFile)
		if err != nil {
			return err
		}
		qwen, err := runtimeconnect.NewQwen(binding, token)
		if err != nil {
			return err
		}
		if err := qwen.Disconnect(cmd.Context()); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return errors.New("MCP entry removed, but local record cleanup failed")
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Disconnected the recorded Pagnet MCP entry. External session and terminal were not stopped.")
		return nil
	}}
	cmd.Flags().StringVar(&state, "state-dir", "", "private profile state directory")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "optional current private Qwen token file after token rotation")
	cmd.Flags().StringVar(&clientID, "client-id", "", "optional current registered client ID after reconnection")
	return cmd
}
