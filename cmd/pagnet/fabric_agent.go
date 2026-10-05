package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	"github.com/spf13/cobra"
)

func localAgentCreateCmd() *cobra.Command {
	var description, socket, requestID, runtime, profile, role, workspace, model string
	command := &cobra.Command{Use: "create NAME", Short: "Create an agent identity in your local network", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(description) == "" {
			if !interactiveMode() {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --description with what this agent does for the network")
			}
			answer, err := askLineFn("What does this agent do for the network? ")
			if err != nil {
				return err
			}
			description = answer
		}
		if strings.TrimSpace(description) == "" {
			return fabric.NewError(fabric.CodeInvalidInput, "A network description is required")
		}
		_, path, err := localFabricPaths("", socket)
		if err != nil {
			return err
		}
		if requestID == "" {
			value := make([]byte, 16)
			if _, err = rand.Read(value); err != nil {
				return err
			}
			requestID = "create-" + hex.EncodeToString(value)
		}
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		client, err := fabricadmin.Dial(ctx, path)
		if err != nil {
			return err
		}
		defer client.Close()
		if workspace == "" {
			workspace, err = os.Getwd()
			if err != nil {
				return err
			}
		}
		workspace, err = filepath.Abs(workspace)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(fabricnode.AgentCreateInput{Name: args[0], Description: description, Runtime: runtime, Profile: profile, Role: role, Workspace: workspace, Model: model})
		if err != nil {
			return err
		}
		result, err := client.Call(ctx, fabricadmin.Request{Version: fabricadmin.Version, ID: requestID, Operation: "agent.create", Input: raw})
		if err != nil {
			return fmt.Errorf("%w; to check or repeat this exact setup, use --request-id %s", err, requestID)
		}
		if result.Error != nil {
			return result.Error
		}
		if jsonOut {
			return printLocalResult(cmd.OutOrStdout(), result.Result)
		}
		if silent {
			return nil
		}
		var setup fabricnode.AgentSetupResult
		if err = fabric.DecodeJSON(result.Result, &setup); err != nil {
			return err
		}
		if setup.State == "configured" {
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s is configured with %s. It starts on an explicit invocation.\n", args[0], setup.Runtime)
		} else {
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s created as a searchable identity. Select --runtime or --profile on creation to configure execution.\n", args[0])
		}
		return err
	}}
	command.Flags().StringVar(&description, "description", "", "what others in the network should know this agent does")
	command.Flags().StringVar(&runtime, "runtime", "", "installed runtime: qwen-code, claude-code, codex, opencode, grok-code")
	command.Flags().StringVar(&profile, "profile", "", "explicit host-local runtime profile")
	command.Flags().StringVar(&role, "role", "", "private standing role/instructions; not the network description")
	command.Flags().StringVar(&workspace, "workspace", "", "existing working folder (default current folder)")
	command.Flags().StringVar(&model, "model", "", "explicit runtime model (default runtime's own selection)")
	command.Flags().StringVar(&socket, "socket", "", "private local node socket (default ~/.pagnet/run/fabric/local.sock)")
	command.Flags().StringVar(&requestID, "request-id", "", "repeat the same setup request after an interrupted connection")
	return command
}
