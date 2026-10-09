package main

// The `pagnet federation` surface wraps the installed node's private
// federation exposure administration operations (see
// internal/fabricnode/installed_federation.go). This is a pure client: it
// dials the local node socket, sends one admin request per command, and
// prints the server-side receipt. It defines no parallel runtime types; the
// exposure configuration is validated against the real SDK type before it is
// sent.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	"github.com/spf13/cobra"
)

// localFederationFixedBytes decodes a 64-character hex string into the 32-byte
// routing value the federation link carries (channel id / receiver routes).
func localFederationFixedBytes(hexValue string) ([]byte, error) {
	raw, err := hex.DecodeString(hexValue)
	if err != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Federation routing value must be hex: "+err.Error())
	}
	if len(raw) != 32 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Federation routing value must be 32 bytes (64 hex characters)")
	}
	return raw, nil
}

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
	cmd.AddCommand(localFederationExposureCmd(), localFederationPeerCmd(), localFederationLinkCmd())
	return cmd
}

// localFederationPeerCmd is the `pagnet federation peer` group: the local
// exchange keypair + peer certificate and the explicitly pinned remote peers.
func localFederationPeerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "peer",
		Short: "Manage the local exchange keypair, peer certificate, and pinned remote peers",
	}
	cmd.AddCommand(
		localFederationPeerGetCmd(),
		localFederationPeerCertifyCmd(),
		localFederationPeerPinCmd(),
		localFederationPeerUnpinCmd(),
	)
	return cmd
}

// localFederationLinkCmd is the `pagnet federation link` group: the per-channel
// link registry (peer identity + opaque channel binding + role).
func localFederationLinkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "link",
		Short: "Manage the per-channel federation link registry",
	}
	cmd.AddCommand(
		localFederationLinkPutCmd(),
		localFederationLinkGetCmd(),
		localFederationLinkRemoveCmd(),
	)
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

func localFederationPeerGetCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Read the local exchange keypair and whether the local peer identity is certified",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := json.Marshal(struct{}{})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("federation-peer-get-", "")
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "federation.peer.local-get", raw, false)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var view struct {
					PublicKey   [32]byte `json:"publicKey"`
					KeyRevision string   `json:"keyRevision"`
					Certified   bool     `json:"certified"`
				}
				if err := json.Unmarshal(raw, &view); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "exchange key: %s (revision %s), certified: %v\n", hex.EncodeToString(view.PublicKey[:]), view.KeyRevision, view.Certified)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	return cmd
}

func localFederationPeerCertifyCmd() *cobra.Command {
	var socket, requestID string
	var expectedRevision, expirySeconds uint64
	cmd := &cobra.Command{
		Use:   "certify",
		Short: "Generate-or-rotate the sealed local exchange key and certify it with the retained root",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := json.Marshal(struct {
				ExpectedRevision uint64 `json:"expectedRevision"`
				ExpirySeconds    uint64 `json:"expirySeconds"`
			}{expectedRevision, expirySeconds})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("federation-peer-certify-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "federation.peer.local-certify", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var view struct {
					PublicKey   [32]byte `json:"publicKey"`
					KeyRevision string   `json:"keyRevision"`
					Digest      [32]byte `json:"digest"`
				}
				if err := json.Unmarshal(raw, &view); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "certified exchange key %s (revision %s), digest %s\n", hex.EncodeToString(view.PublicKey[:]), view.KeyRevision, hex.EncodeToString(view.Digest[:]))
				return err
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	cmd.Flags().Uint64Var(&expectedRevision, "expected-revision", 0, "current certificate revision to replace (0 = first)")
	cmd.Flags().Uint64Var(&expirySeconds, "expiry-seconds", 0, "certificate validity in seconds (0 = 90 days)")
	return cmd
}

func localFederationPeerPinCmd() *cobra.Command {
	var socket, requestID, certificatePath, ownerRef, ownerKind, ownerIssuer string
	var expectedRevision uint64
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Explicitly pin a remote peer's certificate (pasted out-of-band; never automatic trust)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if certificatePath == "" || ownerRef == "" || ownerKind == "" || ownerIssuer == "" {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --certificate (JSON file), --owner-ref, --owner-kind, and --owner-issuer")
			}
			certRaw, err := os.ReadFile(certificatePath)
			if err != nil {
				return err
			}
			var certificate fabric.SignedPeerCertificate
			if err := json.Unmarshal(certRaw, &certificate); err != nil {
				return fmt.Errorf("read --certificate %s: %w", certificatePath, err)
			}
			raw, err := json.Marshal(struct {
				ExpectedRevision uint64                       `json:"expectedRevision"`
				Owner            fabric.Principal             `json:"owner"`
				Certificate      fabric.SignedPeerCertificate `json:"certificate"`
			}{expectedRevision, fabric.Principal{Ref: ownerRef, Kind: ownerKind, Issuer: ownerIssuer}, certificate})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("federation-peer-pin-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "federation.peer.pin", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var view struct {
					Authority struct {
						Namespace string `json:"namespace"`
						StoreID   string `json:"storeId"`
					} `json:"authority"`
					Revision string `json:"revision"`
				}
				if err := json.Unmarshal(raw, &view); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "pinned peer %s/%s (revision %s)\n", view.Authority.Namespace, view.Authority.StoreID, view.Revision)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	cmd.Flags().Uint64Var(&expectedRevision, "expected-revision", 0, "current pin revision to replace (0 = first)")
	cmd.Flags().StringVar(&certificatePath, "certificate", "", "JSON file with the remote peer's signed certificate")
	cmd.Flags().StringVar(&ownerRef, "owner-ref", "", "remote owner principal ref")
	cmd.Flags().StringVar(&ownerKind, "owner-kind", "", "remote owner principal kind")
	cmd.Flags().StringVar(&ownerIssuer, "owner-issuer", "", "remote owner principal issuer")
	return cmd
}

func localFederationPeerUnpinCmd() *cobra.Command {
	var socket, requestID, namespace, storeID string
	var expectedRevision uint64
	cmd := &cobra.Command{
		Use:   "unpin",
		Short: "Remove a pinned remote peer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if namespace == "" || storeID == "" {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --namespace and --store-id")
			}
			raw, err := json.Marshal(struct {
				ExpectedRevision uint64 `json:"expectedRevision"`
				Namespace        string `json:"namespace"`
				StoreID          string `json:"storeId"`
			}{expectedRevision, namespace, storeID})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("federation-peer-unpin-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "federation.peer.unpin", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, _ []byte) error {
				_, err := fmt.Fprintln(out, "unpinned peer "+namespace+"/"+storeID)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	cmd.Flags().Uint64Var(&expectedRevision, "expected-revision", 0, "current pin revision to replace")
	cmd.Flags().StringVar(&namespace, "namespace", "", "remote peer namespace (54 hex)")
	cmd.Flags().StringVar(&storeID, "store-id", "", "remote peer store id (64 hex)")
	return cmd
}

func localFederationLinkPutCmd() *cobra.Command {
	var socket, requestID, remoteNamespace, remoteStoreID, channelID, sourceRoute, destinationRoute string
	var expectedRevision uint64
	var sourceRole bool
	cmd := &cobra.Command{
		Use:   "put",
		Short: "Declare the per-channel federation link (pinned peer identity + opaque channel + role)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			channel, err := localFederationFixedBytes(channelID)
			if err != nil {
				return err
			}
			source, err := localFederationFixedBytes(sourceRoute)
			if err != nil {
				return err
			}
			destination, err := localFederationFixedBytes(destinationRoute)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(struct {
				ExpectedRevision uint64 `json:"expectedRevision"`
				RemoteNamespace  string `json:"remoteNamespace"`
				RemoteStoreID    string `json:"remoteStoreId"`
				ChannelID        []byte `json:"channelId"`
				SourceRoute      []byte `json:"sourceRoute"`
				DestinationRoute []byte `json:"destinationRoute"`
				SourceRole       bool   `json:"sourceRole"`
			}{expectedRevision, remoteNamespace, remoteStoreID, channel, source, destination, sourceRole})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("federation-link-put-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "federation.link.put", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var view struct {
					Revision string `json:"revision"`
				}
				if err := json.Unmarshal(raw, &view); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "link %s -> %s/%s (revision %s)\n", hex.EncodeToString(channel), remoteNamespace, remoteStoreID, view.Revision)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	cmd.Flags().Uint64Var(&expectedRevision, "expected-revision", 0, "current link revision to replace (0 = first)")
	cmd.Flags().StringVar(&remoteNamespace, "remote-namespace", "", "pinned remote namespace (54 hex)")
	cmd.Flags().StringVar(&remoteStoreID, "remote-store-id", "", "pinned remote store id (64 hex)")
	cmd.Flags().StringVar(&channelID, "channel-id", "", "opaque channel binding id (64 hex)")
	cmd.Flags().StringVar(&sourceRoute, "source-route", "", "opaque receiver route on the source (64 hex)")
	cmd.Flags().StringVar(&destinationRoute, "destination-route", "", "opaque receiver route on the destination (64 hex)")
	cmd.Flags().BoolVar(&sourceRole, "source-role", false, "this node is the sending (source) end of the channel")
	return cmd
}

func localFederationLinkGetCmd() *cobra.Command {
	var socket, channelID string
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Read the per-channel federation link",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			channel, err := localFederationFixedBytes(channelID)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(struct {
				ChannelID []byte `json:"channelId"`
			}{channel})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("federation-link-get-", "")
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "federation.link.get", raw, false)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var view struct {
					Revision string `json:"revision"`
					Link     struct {
						RemoteNamespace string `json:"remoteNamespace"`
						RemoteStoreID   string `json:"remoteStoreId"`
						SourceRole      bool   `json:"sourceRole"`
					} `json:"link"`
				}
				if err := json.Unmarshal(raw, &view); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "link %s -> %s/%s, sourceRole=%v (revision %s)\n", hex.EncodeToString(channel), view.Link.RemoteNamespace, view.Link.RemoteStoreID, view.Link.SourceRole, view.Revision)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&channelID, "channel-id", "", "opaque channel binding id (64 hex)")
	return cmd
}

func localFederationLinkRemoveCmd() *cobra.Command {
	var socket, requestID, channelID string
	var expectedRevision uint64
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Revoke the per-channel federation link",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			channel, err := localFederationFixedBytes(channelID)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(struct {
				ExpectedRevision uint64 `json:"expectedRevision"`
				ChannelID        []byte `json:"channelId"`
			}{expectedRevision, channel})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("federation-link-remove-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "federation.link.remove", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, _ []byte) error {
				_, err := fmt.Fprintf(out, "removed link %s\n", hex.EncodeToString(channel))
				return err
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	cmd.Flags().Uint64Var(&expectedRevision, "expected-revision", 0, "current link revision to replace")
	cmd.Flags().StringVar(&channelID, "channel-id", "", "opaque channel binding id (64 hex)")
	return cmd
}
