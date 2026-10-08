package main

// The `pagnet federation` surface wraps the installed node's private
// federation exposure administration operations (see
// internal/fabricnode/installed_federation.go). This is a pure client: it
// dials the local node socket, sends one admin request per command, and
// prints the server-side receipt. It defines no parallel runtime types; the
// exposure configuration is validated against the real SDK type before it is
// sent.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	"github.com/spf13/cobra"
)

// The wire input shape mirrors the node's private administration input struct
// (federationExposurePutInput). Field order and tags must match the server
// byte-for-byte; the server decodes with DisallowUnknownFields. The CAS base
// is a JSON number in the input (the request-level expectedRevision string is
// rejected server-side).
type federationExposurePutRequest struct {
	ExpectedRevision uint64                          `json:"expectedRevision"`
	Exposures        []fabricnode.FederationExposure `json:"exposures"`
}

// localFederationReadConfig reads a JSON file and validates it against the
// real FederationExposureConfiguration type before it is sent (the server
// rejects unknown fields and a non-canonical endpoint-ref string).
func localFederationReadConfig(path string) (fabricnode.FederationExposureConfiguration, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fabricnode.FederationExposureConfiguration{}, err
	}
	var config fabricnode.FederationExposureConfiguration
	if err := json.Unmarshal(raw, &config); err != nil {
		return fabricnode.FederationExposureConfiguration{}, fmt.Errorf("read --config %s: %w", path, err)
	}
	return config, nil
}

// localFederationCmd is the `pagnet federation` group.
func localFederationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "federation",
		Short: "Manage your local node's signed federation exposure configuration",
	}
	cmd.AddCommand(localFederationExposureCmd())
	return cmd
}

// localFederationExposureCmd is the `pagnet federation exposure` group (2 leaves).
func localFederationExposureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exposure",
		Short: "Declare and read the node's signed federation exposure configuration",
	}
	cmd.AddCommand(
		localFederationExposurePutCmd(),
		localFederationExposureGetCmd(),
	)
	return cmd
}

func localFederationExposurePutCmd() *cobra.Command {
	var configPath, socket, requestID string
	var expectedRevision uint64
	cmd := &cobra.Command{
		Use:   "put",
		Short: "Declare the node's federation exposure configuration (signed FULL CAS)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if configPath == "" {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --config with a JSON file containing the federation exposure configuration")
			}
			config, err := localFederationReadConfig(configPath)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(federationExposurePutRequest{ExpectedRevision: expectedRevision, Exposures: config.Exposures})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("federation-exposure-put-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "federation.exposure.put", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var receipt struct {
					Revision uint64 `json:"revision"`
				}
				if err := json.Unmarshal(raw, &receipt); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "exposures: %d (revision %d)\n", len(config.Exposures), receipt.Revision)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "JSON file with the federation exposure configuration (exposures: [...])")
	cmd.Flags().Uint64Var(&expectedRevision, "expected-revision", 0, "current revision to replace (0 = first declaration)")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	return cmd
}

func localFederationExposureGetCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Read the node's declared federation exposure configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := json.Marshal(struct{}{})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("federation-exposure-get-", "")
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "federation.exposure.get", raw, false)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var view struct {
					Revision  uint64 `json:"revision"`
					Exposures []struct {
						RemoteDomain string `json:"remoteDomain"`
						Target       string `json:"target"`
					} `json:"exposures"`
				}
				if err := json.Unmarshal(raw, &view); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "exposures: %d (revision %d)\n", len(view.Exposures), view.Revision)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	return cmd
}
