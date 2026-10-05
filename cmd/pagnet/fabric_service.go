package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	"github.com/spf13/cobra"
)

func localServiceAddCmd() *cobra.Command {
	var v fabricnode.ServiceAddInput
	var socket, requestID, a2aCard string
	var cancellation bool
	cmd := &cobra.Command{Use: "add URL", Short: "Connect an MCP service or A2A agent to your local network", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		v.URL = args[0]
		if strings.TrimSpace(v.Description) == "" {
			if !interactiveMode() {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --description with what this service does for the network")
			}
			answer, e := askLineFn("What does this service do for the network? ")
			if e != nil {
				return e
			}
			v.Description = answer
		}
		if strings.TrimSpace(v.Description) == "" {
			return fabric.NewError(fabric.CodeInvalidInput, "A network description is required")
		}
		operation := "service.add"
		var setupInput any = v
		if a2aCard != "" {
			if cmd.Flags().Changed("protocol-version") {
				return fabric.NewError(fabric.CodeInvalidInput, "A2A protocol version comes from the explicitly selected Agent Card interface")
			}
			card, e := readLocalA2ACard(a2aCard)
			if e != nil {
				return e
			}
			operation = "service.a2a.add"
			setupInput = fabricnode.A2AServiceAddInput{URL: v.URL, Name: v.Name, Description: v.Description, Card: card, CredentialSelector: v.CredentialSelector, AllowHTTP: v.AllowHTTP, Cancellation: cancellation}
		} else if cmd.Flags().Changed("cancellation") {
			return fabric.NewError(fabric.CodeInvalidInput, "--cancellation applies to an explicitly supplied A2A Agent Card")
		}
		_, path, e := localFabricPaths("", socket)
		if e != nil {
			return e
		}
		if requestID == "" {
			value := make([]byte, 16)
			if _, e = rand.Read(value); e != nil {
				return e
			}
			requestID = "service-" + hex.EncodeToString(value)
		}
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		client, e := fabricadmin.Dial(ctx, path)
		if e != nil {
			return e
		}
		defer client.Close()
		raw, e := json.Marshal(setupInput)
		if e != nil {
			return e
		}
		response, e := client.Call(ctx, fabricadmin.Request{Version: fabricadmin.Version, ID: requestID, Operation: operation, Input: raw})
		if e != nil {
			return fmt.Errorf("%w; repeat this exact setup with --request-id %s", e, requestID)
		}
		if response.Error != nil {
			return response.Error
		}
		if jsonOut {
			return printLocalResult(cmd.OutOrStdout(), response.Result)
		}
		if silent {
			return nil
		}
		var result fabricnode.ServiceAddResult
		if e = json.Unmarshal(response.Result, &result); e != nil {
			return e
		}
		switch result.State {
		case "configured":
			_, e = fmt.Fprintf(cmd.OutOrStdout(), "%s configured. Discover it in your local network; setup did not call the remote agent.\n", result.Name)
		case "connected":
			_, e = fmt.Fprintf(cmd.OutOrStdout(), "%s connected. Its tools are discoverable in your local network.\n", result.Name)
		case "connecting":
			_, e = fmt.Fprintf(cmd.OutOrStdout(), "%s configured; its selected endpoint is connecting.\n", result.Name)
		case "offline":
			_, e = fmt.Fprintf(cmd.OutOrStdout(), "%s configured; the endpoint is offline. Retry this exact setup with --request-id %s.\n", result.Name, requestID)
		default:
			_, e = fmt.Fprintf(cmd.OutOrStdout(), "The endpoint could not complete setup. Check it, then retry with --request-id %s.\n", requestID)
		}
		return e
	}}
	cmd.Flags().StringVar(&v.Name, "name", "", "service display name (default URL hostname)")
	cmd.Flags().StringVar(&v.Description, "description", "", "what the service does for the network")
	cmd.Flags().StringVar(&v.ProtocolVersion, "protocol-version", "", "explicit MCP version for offline setup (default official SDK negotiation)")
	cmd.Flags().StringVar(&a2aCard, "a2a-card", "", "explicit trusted local Agent Card file; URL selects its exact A2A JSON-RPC interface")
	cmd.Flags().BoolVar(&cancellation, "cancellation", false, "explicitly enable A2A cancellation for this selected agent")
	cmd.Flags().StringVar(&v.CredentialSelector, "credential-selector", "none", "selector in the installation's explicitly configured private provider")
	cmd.Flags().BoolVar(&v.AllowHTTP, "allow-http", false, "explicitly permit unencrypted HTTP beyond loopback")
	cmd.Flags().StringVar(&socket, "socket", "", "private local node socket (default ~/.pagnet/run/fabric/local.sock)")
	cmd.Flags().StringVar(&requestID, "request-id", "", "repeat the same setup after an interrupted connection")
	return cmd
}

func readLocalA2ACard(path string) (json.RawMessage, error) {
	f, e := openLocalA2ACard(path)
	if e != nil {
		var failure *fabric.Error
		if errors.As(e, &failure) {
			return nil, e
		}
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Cannot read the selected local A2A Agent Card")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 24<<10 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Select a regular Agent Card file of at most 24 KiB")
	}
	raw, e := io.ReadAll(io.LimitReader(f, (24<<10)+1))
	if e != nil || len(raw) > 24<<10 || fabric.DecodeJSONWithLimits(raw, new(any), fabric.WireLimits{MaxBytes: 24 << 10, MaxDepth: 32, MaxMembers: 2048}) != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Agent Card must contain one bounded JSON document")
	}
	return raw, nil
}
