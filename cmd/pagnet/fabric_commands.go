package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/spf13/cobra"
)

func localOperationClient(ctx context.Context, socket string) (*fabricclient.Client, error) {
	_, actual, err := localFabricPaths("", socket)
	if err != nil {
		return nil, err
	}
	auth, err := fabrichost.FromEnvironment(os.Getenv)
	if err != nil {
		return nil, err
	}
	return fabricclient.Dial(ctx, actual, auth)
}
func localOperationResult(result *sdkmcp.CallToolResult) ([]byte, error) {
	if result == nil || len(result.Content) != 1 {
		return nil, fabric.NewError(fabric.CodeProtocolError, "Missing bounded local result")
	}
	text, ok := result.Content[0].(*sdkmcp.TextContent)
	if !ok || len(text.Text) > fabric.DefaultWireLimits.MaxBytes {
		return nil, fabric.NewError(fabric.CodeProtocolError, "Invalid local result")
	}
	raw := []byte(text.Text)
	var validated json.RawMessage
	if err := fabric.DecodeJSONWithLimits(raw, &validated, fabric.DefaultWireLimits); err != nil {
		return nil, err
	}
	if result.IsError {
		var failure struct {
			Error *fabric.Error `json:"error"`
		}
		if fabric.DecodeJSON(raw, &failure) != nil || failure.Error == nil {
			return nil, fabric.NewError(fabric.CodeProtocolError, "Missing structured operation error")
		}
		return nil, failure.Error
	}
	return bytes.Clone(raw), nil
}
func printLocalResult(out io.Writer, raw []byte) error {
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, raw, "", "  "); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, formatted.String())
	return err
}
func localReadOperation(cmd *cobra.Command, socket string, op fabric.Operation, args any) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	client, err := localOperationClient(ctx, socket)
	if err != nil {
		return err
	}
	defer client.Close()
	raw, err := json.Marshal(args)
	if err != nil {
		return err
	}
	result, err := client.Call(ctx, op, raw)
	if err != nil {
		return err
	}
	content, err := localOperationResult(result)
	if err != nil {
		return err
	}
	if op == fabric.OperationDescribe {
		var described fabric.DescribeResult
		if err := fabric.DecodeJSON(content, &described); err != nil {
			return err
		}
		for _, selection := range described.Descriptions {
			if selection.Error != nil {
				return selection.Error
			}
		}
	}
	return printLocalResult(cmd.OutOrStdout(), content)
}
func discoverCmd() *cobra.Command {
	var socket, cursor string
	var limit int
	var kinds, tags []string
	cmd := &cobra.Command{Use: "discover <query>", Short: "Find compact candidates on your local network; nothing is executed", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		request := fabric.DiscoverRequest{Query: args[0], Limit: limit, Cursor: cursor, Filters: fabric.SearchFilters{Kinds: kinds, Tags: tags}}
		if err := request.Validate(); err != nil {
			return err
		}
		return localReadOperation(cmd, socket, fabric.OperationDiscover, request)
	}}
	cmd.Flags().StringVar(&socket, "socket", "", "private local node socket (default ~/.pagnet/run/fabric/local.sock)")
	cmd.Flags().StringVar(&cursor, "cursor", "", "continue a bounded discovery page")
	cmd.Flags().IntVar(&limit, "limit", 10, "maximum compact results (1–100)")
	cmd.Flags().StringSliceVar(&kinds, "kind", nil, "filter by namespaced endpoint kinds")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "filter by tags")
	return cmd
}
func describeCmd() *cobra.Command {
	var socket, revision, cursor string
	var limit int
	cmd := &cobra.Command{Use: "describe <ref>", Short: "Read one selected endpoint or operation schema; nothing is executed", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ref, err := fabric.ParseEndpointRef(args[0])
		if err != nil {
			return err
		}
		request := fabric.DescribeRequest{Selections: []fabric.DescribeSelection{{Ref: ref, ExpectedRevision: fabric.Revision(revision), OffersCursor: cursor, OffersLimit: limit}}}
		if err = request.Validate(); err != nil {
			return err
		}
		return localReadOperation(cmd, socket, fabric.OperationDescribe, request)
	}}
	cmd.Flags().StringVar(&socket, "socket", "", "private local node socket")
	cmd.Flags().StringVar(&revision, "revision", "", "require this retained descriptor revision")
	cmd.Flags().StringVar(&cursor, "cursor", "", "continue this endpoint's offers page")
	cmd.Flags().IntVar(&limit, "offers-limit", 0, "bounded endpoint offers page size (0 uses default)")
	return cmd
}

func readLocalInput(cmd *cobra.Command, path string) ([]byte, error) {
	if path == "" {
		return []byte(`{}`), nil
	}
	reader := cmd.InOrStdin()
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	}
	raw, err := io.ReadAll(io.LimitReader(reader, int64(fabric.DefaultWireLimits.MaxBytes)+1))
	if err != nil {
		return nil, err
	}
	var validated json.RawMessage
	if err = fabric.DecodeJSONWithLimits(raw, &validated, fabric.DefaultWireLimits); err != nil {
		return nil, err
	}
	return raw, nil
}
func runLocalInvoke(cmd *cobra.Command, target, socket, revision, input, idempotency string, timeout time.Duration) error {
	ref, err := fabric.ParseEndpointRef(target)
	if err != nil {
		return err
	}
	if revision == "" || len(revision) > 256 || timeout <= 0 {
		return fabric.NewError(fabric.CodeInvalidInput, "Invoke requires the selected --revision and a positive --timeout")
	}
	raw, err := readLocalInput(cmd, input)
	if err != nil {
		return err
	}
	defer clear(raw)
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := localOperationClient(ctx, socket)
	if err != nil {
		return err
	}
	defer client.Close()
	deadline, _ := ctx.Deadline()
	arguments, err := json.Marshal(struct {
		Target      fabric.EndpointRef `json:"target"`
		Input       json.RawMessage    `json:"input"`
		Revision    string             `json:"revision"`
		Deadline    time.Time          `json:"deadline"`
		Idempotency string             `json:"idempotencyKey,omitempty"`
	}{ref, json.RawMessage(raw), revision, deadline, idempotency})
	if err != nil {
		return err
	}
	defer func() { clear(arguments) }()
	var handle, invocation string
	var sequence uint64
	first, terminal := true, false
	for {
		result, err := client.Call(ctx, fabric.OperationInvoke, arguments)
		if err != nil {
			return err
		}
		content, err := localOperationResult(result)
		if err != nil {
			return err
		}
		if first {
			var deferred struct {
				DeferredID        string        `json:"deferredId"`
				NotificationError *fabric.Error `json:"notificationError,omitempty"`
			}
			if err = fabric.DecodeJSON(content, &deferred); err != nil {
				return err
			}
			if deferred.DeferredID != "" {
				// This is a retained continuation, not a completed endpoint result.
				// Print the actual handle and any notification error, without polling
				// or guessing how an external approval application will resume it.
				return printLocalResult(cmd.OutOrStdout(), content)
			}
		}
		var page mcpbridge.Page
		if err = fabric.DecodeJSON(content, &page); err != nil {
			return err
		}
		if len(page.Frames) != 1 || terminal || !first && page.Handle != handle {
			return fabric.NewError(fabric.CodeProtocolError, "Invalid invocation page association")
		}
		frame := page.Frames[0]
		if first {
			if frame.Kind != fabric.FrameStart || frame.Sequence != 0 || frame.InvocationID == "" {
				return fabric.NewError(fabric.CodeProtocolError, "Invocation did not start")
			}
			handle, invocation = page.Handle, frame.InvocationID
		} else if frame.InvocationID != invocation || frame.Sequence != sequence+1 || frame.Kind == fabric.FrameStart {
			return fabric.NewError(fabric.CodeProtocolError, "Invocation stream sequence changed")
		}
		sequence = frame.Sequence
		switch frame.Kind {
		case fabric.FrameStart, fabric.FrameProgress:
		case fabric.FrameChunk:
			if !jsonOut {
				if _, err = cmd.OutOrStdout().Write(frame.Data); err != nil {
					return err
				}
			}
		case fabric.FrameComplete:
			terminal = true
		case fabric.FrameError:
			if frame.Error == nil {
				return fabric.NewError(fabric.CodeProtocolError, "Missing invocation failure")
			}
			return frame.Error
		default:
			return fabric.NewError(fabric.CodeProtocolError, "Unknown invocation frame")
		}
		if jsonOut {
			if err = json.NewEncoder(cmd.OutOrStdout()).Encode(page); err != nil {
				return err
			}
		}
		if !page.More {
			if !terminal {
				return fabric.NewError(fabric.CodeTargetUnavailable, "Invocation ended without a completion; outcome is unknown")
			}
			return nil
		}
		if terminal || handle == "" {
			return fabric.NewError(fabric.CodeProtocolError, "Invalid continued invocation")
		}
		clear(arguments)
		arguments, err = json.Marshal(struct {
			Stream mcpbridge.StreamControl `json:"stream"`
		}{mcpbridge.StreamControl{Handle: handle, AfterSequence: sequence}})
		if err != nil {
			return err
		}
		first = false
	}
}
