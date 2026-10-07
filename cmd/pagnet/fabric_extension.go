package main

// The `pagnet extension` / `pagnet continuation` surface wraps the 13
// extension/continuation administration operations the installed node already
// serves on its private admin socket (see
// internal/fabricnode/installed_extension_admin.go). This is a pure client: it
// dials the local node socket, sends one admin request per command, and prints
// the server-side receipt. It defines no parallel runtime types; installation
// and profile payloads are validated against the real SDK types before they are
// sent.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/pagnet-code/pagnet/fabric"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	"github.com/spf13/cobra"
)

// The wire input shapes mirror the node's private administration input structs
// (extensionMutationInput / extensionReferenceInput / extensionListInput /
// extensionResumeInput / extensionPageInput). Field order and tags must match
// the server byte-for-byte; the server decodes with DisallowUnknownFields.
type extensionMutationRequest struct {
	Generation   uint64                   `json:"generation,string"`
	Revision     uint64                   `json:"revision,string,omitempty"`
	Installation extregistry.Installation `json:"installation"`
}
type extensionReferenceRequest struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation,string,omitempty"`
	Revision   uint64 `json:"revision,string,omitempty"`
}
type extensionListRequest struct {
	After string `json:"after,omitempty"`
	Limit int    `json:"limit"`
}
type extensionResumeRequest struct {
	ID      string `json:"id"`
	ClaimID string `json:"claimId"`
}
type extensionPageRequest struct {
	Handle     string `json:"handle"`
	ACK        string `json:"ack,omitempty"`
	WaitMillis int    `json:"waitMillis,omitempty"`
}

const localExtensionSocketFlagHelp = "private local node socket (default ~/.pagnet/run/fabric/local.sock)"
const localExtensionRequestIDFlagHelp = "repeat the same setup request after an interrupted connection"

// newLocalExtensionRequestID returns the provided id, or a fresh random one
// prefixed for the operation. Every admin request needs a valid id; mutating
// operations let the operator pin one for an exact retry.
func newLocalExtensionRequestID(prefix, provided string) (string, error) {
	if provided != "" {
		return provided, nil
	}
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}

// localExtensionCall dials the private node socket, sends exactly one admin
// request, and resolves transport/server failures. It returns the raw result
// bytes. For a mutating operation a transport failure carries the
// --request-id retry suffix (fabric_agent.go pattern); a server-side error is
// returned verbatim.
func localExtensionCall(cmd *cobra.Command, socket, requestID, operation string, input []byte, mutating bool) ([]byte, error) {
	_, path, err := localFabricPaths("", socket)
	if err != nil {
		return nil, err
	}
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	client, err := fabricadmin.Dial(ctx, path)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	result, err := client.Call(ctx, fabricadmin.Request{Version: fabricadmin.Version, ID: requestID, Operation: operation, Input: input})
	if err != nil {
		if mutating {
			return nil, fmt.Errorf("%w; to check or repeat this exact setup, use --request-id %s", err, requestID)
		}
		return nil, err
	}
	if result.Error != nil {
		return nil, result.Error
	}
	return result.Result, nil
}

// localExtensionPrint applies the --json / --silent output policy and, in human
// mode, renders the one-line summary via human.
func localExtensionPrint(cmd *cobra.Command, result []byte, human func(out io.Writer, result []byte) error) error {
	if jsonOut {
		return printLocalResult(cmd.OutOrStdout(), result)
	}
	if silent {
		return nil
	}
	return human(cmd.OutOrStdout(), result)
}

// localExtensionReadProfile reads a JSON file and validates it against the real
// ExtensionProfile type before it is sent (the server rejects unknown fields).
func localExtensionReadProfile(path string) (fabricnode.ExtensionProfile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fabricnode.ExtensionProfile{}, err
	}
	var profile fabricnode.ExtensionProfile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return fabricnode.ExtensionProfile{}, fmt.Errorf("read --profile %s: %w", path, err)
	}
	return profile, nil
}

// localExtensionReadInstallation reads a JSON file and validates it against the
// real extregistry.Installation type before it is embedded (no parallel struct).
func localExtensionReadInstallation(path string) (extregistry.Installation, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return extregistry.Installation{}, err
	}
	var installation extregistry.Installation
	if err := json.Unmarshal(raw, &installation); err != nil {
		return extregistry.Installation{}, fmt.Errorf("read --installation %s: %w", path, err)
	}
	return installation, nil
}

// localExtensionCmd is the `pagnet extension` group (6 leaves).
func localExtensionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extension",
		Short: "Manage installed private interceptor extensions on your local node",
	}
	cmd.AddCommand(
		localExtensionProfileCmd(),
		localExtensionInstallCmd(),
		localExtensionUpdateCmd(),
		localExtensionInspectCmd(),
		localExtensionListCmd(),
		localExtensionRemoveCmd(),
	)
	return cmd
}

func localExtensionProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage retained private interceptor profiles",
	}
	cmd.AddCommand(localExtensionProfilePutCmd())
	return cmd
}

func localExtensionProfilePutCmd() *cobra.Command {
	var profilePath, socket, requestID string
	cmd := &cobra.Command{
		Use:   "put",
		Short: "Store one private interceptor profile (content-addressed, immutable)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if profilePath == "" {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --profile with a JSON file containing the interceptor profile")
			}
			profile, err := localExtensionReadProfile(profilePath)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(profile)
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("extension-profile-put-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "extension.profile.put", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var receipt struct {
					Digest string `json:"digest"`
				}
				if err := json.Unmarshal(raw, &receipt); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "profile %s\n", receipt.Digest)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&profilePath, "profile", "", "JSON file with the interceptor profile (protocol, url, credentialSelector, maxConcurrency, allowHttp)")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	return cmd
}

func localExtensionInstallCmd() *cobra.Command {
	var generation uint64
	var installationPath, socket, requestID string
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install one private extension from a manifest file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if installationPath == "" {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --installation with a JSON file containing the extension installation")
			}
			installation, err := localExtensionReadInstallation(installationPath)
			if err != nil {
				return err
			}
			// Install has no --revision: the server denies a nonzero revision on
			// install, so the CLI never sends one (Revision stays 0 and is omitted).
			raw, err := json.Marshal(extensionMutationRequest{Generation: generation, Installation: installation})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("extension-install-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "extension.install", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var ref extregistry.Reference
				if err := json.Unmarshal(raw, &ref); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "installed %s@%d\n", ref.ID, ref.Revision)
				return err
			})
		},
	}
	cmd.Flags().Uint64Var(&generation, "generation", 0, "configuration generation to install under")
	cmd.Flags().StringVar(&installationPath, "installation", "", "JSON file with the extension installation (manifest + bindings)")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	return cmd
}

func localExtensionUpdateCmd() *cobra.Command {
	var generation, revision uint64
	var installationPath, socket, requestID string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update one installed private extension revision",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if installationPath == "" {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --installation with a JSON file containing the extension installation")
			}
			installation, err := localExtensionReadInstallation(installationPath)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(extensionMutationRequest{Generation: generation, Revision: revision, Installation: installation})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("extension-update-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "extension.update", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var ref extregistry.Reference
				if err := json.Unmarshal(raw, &ref); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "updated %s@%d\n", ref.ID, ref.Revision)
				return err
			})
		},
	}
	cmd.Flags().Uint64Var(&generation, "generation", 0, "configuration generation to update")
	cmd.Flags().Uint64Var(&revision, "revision", 0, "current revision to replace")
	cmd.Flags().StringVar(&installationPath, "installation", "", "JSON file with the replacement extension installation")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	return cmd
}

func localExtensionInspectCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "inspect <id>",
		Short: "Read one installed extension's signed reference and installation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Inspect sends only the id: the server denies generation/revision.
			raw, err := json.Marshal(extensionReferenceRequest{ID: args[0]})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("extension-inspect-", "")
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "extension.inspect", raw, false)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var inspected struct {
					Reference extregistry.Reference `json:"reference"`
				}
				if err := json.Unmarshal(raw, &inspected); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "inspected %s@%d\n", inspected.Reference.ID, inspected.Reference.Revision)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	return cmd
}

func localExtensionListCmd() *cobra.Command {
	var after string
	var limit int
	var socket string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List installed private extensions (bounded page)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit <= 0 {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide a positive --limit")
			}
			raw, err := json.Marshal(extensionListRequest{After: after, Limit: limit})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("extension-list-", "")
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "extension.list", raw, false)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var page extregistry.Page
				if err := json.Unmarshal(raw, &page); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "%d extension(s)\n", len(page.Entries))
				return err
			})
		},
	}
	cmd.Flags().StringVar(&after, "after", "", "continue after this page cursor")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum entries (required, >0)")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	return cmd
}

func localExtensionRemoveCmd() *cobra.Command {
	var generation, revision uint64
	var socket, requestID string
	cmd := &cobra.Command{
		Use:   "remove <id>",
		Short: "Remove one installed private extension",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := json.Marshal(extensionReferenceRequest{ID: args[0], Generation: generation, Revision: revision})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("extension-remove-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "extension.remove", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, _ []byte) error {
				_, err := fmt.Fprintln(out, "removed")
				return err
			})
		},
	}
	cmd.Flags().Uint64Var(&generation, "generation", 0, "configuration generation")
	cmd.Flags().Uint64Var(&revision, "revision", 0, "revision to remove")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	return cmd
}

// localContinuationCmd is the `pagnet continuation` group (7 leaves).
func localContinuationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "continuation",
		Short: "Inspect and drive retained private continuations on your local node",
	}
	cmd.AddCommand(
		localContinuationInspectCmd(),
		localContinuationStopCmd(),
		localContinuationResumeCmd(),
		localContinuationRecoverCmd(),
		localContinuationRotateCmd(),
		localContinuationStreamCmd(),
	)
	return cmd
}

func localContinuationInspectCmd() *cobra.Command {
	var claim, socket string
	cmd := &cobra.Command{
		Use:   "inspect <id>",
		Short: "Read one retained continuation claim's receipt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if claim == "" {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --claim with the claim id")
			}
			raw, err := json.Marshal(extensionResumeRequest{ID: args[0], ClaimID: claim})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("continuation-inspect-", "")
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "continuation.inspect", raw, false)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var receipt struct {
					ID    string `json:"id"`
					State string `json:"state"`
				}
				if err := json.Unmarshal(raw, &receipt); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "inspected id=%s state=%s\n", receipt.ID, receipt.State)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&claim, "claim", "", "claim id (hex)")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	return cmd
}

func localContinuationStopCmd() *cobra.Command {
	var claim, socket, requestID string
	cmd := &cobra.Command{
		Use:   "stop <id>",
		Short: "Stop one retained continuation's original source",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if claim == "" {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --claim with the claim id")
			}
			raw, err := json.Marshal(extensionResumeRequest{ID: args[0], ClaimID: claim})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("continuation-stop-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "continuation.stop", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, _ []byte) error {
				_, err := fmt.Fprintln(out, "stopped")
				return err
			})
		},
	}
	cmd.Flags().StringVar(&claim, "claim", "", "claim id (hex)")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	return cmd
}

func localContinuationResumeCmd() *cobra.Command {
	var claim, socket, requestID string
	cmd := &cobra.Command{
		Use:   "resume <id>",
		Short: "Resume one retained continuation (joins the original source)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if claim == "" {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --claim with the claim id")
			}
			raw, err := json.Marshal(extensionResumeRequest{ID: args[0], ClaimID: claim})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("continuation-resume-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "continuation.resume", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var receipt struct {
					ID    string `json:"id"`
					State string `json:"state"`
				}
				if err := json.Unmarshal(raw, &receipt); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "resumed id=%s state=%s\n", receipt.ID, receipt.State)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&claim, "claim", "", "claim id (hex)")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	return cmd
}

func localContinuationRecoverCmd() *cobra.Command {
	var socket, requestID string
	cmd := &cobra.Command{
		Use:   "recover <id>",
		Short: "Recover and republish one retained continuation's notification",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Recover sends only the id: the server denies generation and revision.
			raw, err := json.Marshal(extensionReferenceRequest{ID: args[0]})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("continuation-recover-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "continuation.recover", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, _ []byte) error {
				_, err := fmt.Fprintln(out, "published")
				return err
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	return cmd
}

func localContinuationRotateCmd() *cobra.Command {
	var revision uint64
	var socket, requestID string
	cmd := &cobra.Command{
		Use:   "rotate <id>",
		Short: "Rotate one pending continuation's capability",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := json.Marshal(extensionReferenceRequest{ID: args[0], Revision: revision})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("continuation-rotate-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "continuation.rotate", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var rotated struct {
					ID       string `json:"id"`
					Revision uint64 `json:"capabilityRevision,string"`
				}
				if err := json.Unmarshal(raw, &rotated); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "rotated id=%s capabilityRevision=%d\n", rotated.ID, rotated.Revision)
				return err
			})
		},
	}
	cmd.Flags().Uint64Var(&revision, "revision", 0, "pending capability revision to rotate")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	return cmd
}

func localContinuationStreamCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stream",
		Short: "Page a retained continuation's original output stream",
	}
	cmd.AddCommand(
		localContinuationStreamPageCmd(),
		localContinuationStreamCloseCmd(),
	)
	return cmd
}

func localContinuationStreamPageCmd() *cobra.Command {
	var handle, ack, socket string
	var waitMillis int
	cmd := &cobra.Command{
		Use:   "page",
		Short: "Read the next page from a retained continuation stream",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if handle == "" {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --handle with the stream handle")
			}
			raw, err := json.Marshal(extensionPageRequest{Handle: handle, ACK: ack, WaitMillis: waitMillis})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("continuation-stream-page-", "")
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "continuation.stream.page", raw, false)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, raw []byte) error {
				var page struct {
					Handle   string `json:"handle"`
					Cursor   uint64 `json:"cursor,string"`
					Frames   []any  `json:"frames"`
					Pending  bool   `json:"pending"`
					Terminal bool   `json:"terminal"`
				}
				if err := json.Unmarshal(raw, &page); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "page handle=%s cursor=%d frames=%d pending=%t terminal=%t\n", page.Handle, page.Cursor, len(page.Frames), page.Pending, page.Terminal)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&handle, "handle", "", "stream handle (hex)")
	cmd.Flags().StringVar(&ack, "ack", "", "acknowledge this page digest to advance")
	cmd.Flags().IntVar(&waitMillis, "wait-ms", 0, "maximum wait for the next frame (0-25000)")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	return cmd
}

func localContinuationStreamCloseCmd() *cobra.Command {
	var handle, ack, socket, requestID string
	cmd := &cobra.Command{
		Use:   "close",
		Short: "Close a retained continuation stream",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if handle == "" {
				return fabric.NewError(fabric.CodeInvalidInput, "Provide --handle with the stream handle")
			}
			// The server denies a non-empty ack on close; the flag exists for input
			// parity with page and is rejected server-side when set.
			raw, err := json.Marshal(extensionPageRequest{Handle: handle, ACK: ack})
			if err != nil {
				return err
			}
			id, err := newLocalExtensionRequestID("continuation-stream-close-", requestID)
			if err != nil {
				return err
			}
			result, err := localExtensionCall(cmd, socket, id, "continuation.stream.close", raw, true)
			if err != nil {
				return err
			}
			return localExtensionPrint(cmd, result, func(out io.Writer, _ []byte) error {
				_, err := fmt.Fprintln(out, "stopped")
				return err
			})
		},
	}
	cmd.Flags().StringVar(&handle, "handle", "", "stream handle (hex)")
	cmd.Flags().StringVar(&ack, "ack", "", "acknowledge (the server rejects a non-empty ack on close)")
	cmd.Flags().StringVar(&socket, "socket", "", localExtensionSocketFlagHelp)
	cmd.Flags().StringVar(&requestID, "request-id", "", localExtensionRequestIDFlagHelp)
	return cmd
}
