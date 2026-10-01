package externalbridge

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/pagnet-code/pagnet/sdk"
	"strings"
)

type messagingClient interface {
	SendBrowserAsk(context.Context, string, string, string, string) (*sdk.BrowserAskResult, error)
	GetBrowserAsk(context.Context, string, string) (*sdk.BrowserAskResult, error)
}

func (b *Bridge) addMessagingTools(s *server.MCPServer) {
	if len(b.messagingTargets) == 0 {
		return
	}
	s.AddTool(mcp.NewTool("pagnet_ask", mcp.WithDescription("Ask an explicitly allowed Pagnet agent a question. Agent descriptions are discoverable via pagnet_search; no business capability schema is required. Choose a short requestId such as travel-plan-1 for new work, and reuse the SAME requestId, agent and text for retries. The bridge creates durable identifiers; you do not need UUIDs. Results are durable; poll pagnet_ask_get, never resubmit under a new request key after timeout."+untrusted), mcp.WithReadOnlyHintAnnotation(false), mcp.WithIdempotentHintAnnotation(true), mcp.WithString("targetPrincipalId", mcp.Required()), mcp.WithString("requestId"), mcp.WithString("messageId", mcp.Description("Advanced compatibility: UUID instead of requestId")), mcp.WithString("text", mcp.Required())), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, id, err := b.messagingRequestID(ctx, r)
		if err != nil {
			return result(nil, err)
		}
		text := r.GetString("text", "")
		if !b.messagingTargets[target] {
			return result(nil, errors.New("agent is outside approved messaging targets"))
		}
		if len(text) == 0 || len(text) > 64<<10 {
			return result(nil, errors.New("text must be 1..65536 bytes"))
		}
		client, ok := b.client.(messagingClient)
		if !ok {
			return result(nil, errors.New("device SDK does not support messaging"))
		}
		out, err := client.SendBrowserAsk(ctx, b.network, target, id, text)
		if err != nil && out != nil {
			return result(map[string]any{"requestId": r.GetString("requestId", ""), "targetPrincipalId": target, "messageId": out.MessageID, "threadId": out.ThreadID, "notice": "Submission outcome is uncertain; retry only the same requestId, agent and text or poll its result."}, nil)
		}
		if out != nil {
			out.RequestID = r.GetString("requestId", "")
		}
		return result(out, err)
	})
	s.AddTool(mcp.NewTool("pagnet_ask_get", mcp.WithDescription("Poll only this connector's own ASK and addressed replies. Decryption happens on its device; no other network history is available."+untrusted), mcp.WithReadOnlyHintAnnotation(true), mcp.WithString("targetPrincipalId", mcp.Required()), mcp.WithString("requestId"), mcp.WithString("messageId", mcp.Description("Advanced compatibility: UUID instead of requestId"))), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, id, resolveErr := b.messagingRequestID(ctx, r)
		if resolveErr != nil {
			return result(nil, resolveErr)
		}
		if _, err := uuid.Parse(id); err != nil {
			return result(nil, errors.New("messageId must be UUID"))
		}
		client, ok := b.client.(messagingClient)
		if !ok {
			return result(nil, errors.New("device SDK does not support messaging"))
		}
		out, err := client.GetBrowserAsk(ctx, b.network, id)
		if err != nil {
			return result(nil, err)
		}
		if out == nil || out.MessageID != id || out.TargetPrincipalID != target || !b.messagingTargets[out.TargetPrincipalID] {
			return result(nil, errors.New("ASK target is outside approved messaging policy"))
		}
		out.RequestID = r.GetString("requestId", "")
		return result(out, nil)
	})
}

// Short request keys are scoped to the immutable principal/network/target,
// avoiding both user UUID handling and identity collisions across connectors.
func (b *Bridge) messagingRequestID(ctx context.Context, r mcp.CallToolRequest) (string, string, error) {
	target := r.GetString("targetPrincipalId", "")
	if !b.messagingTargets[target] {
		return "", "", errors.New("agent is outside approved messaging targets")
	}
	key, id := r.GetString("requestId", ""), r.GetString("messageId", "")
	if key == "" {
		if _, err := uuid.Parse(id); err != nil {
			return "", "", errors.New("provide a short requestId for new work or the same key for a retry")
		}
		return target, id, nil
	}
	if id != "" || len(key) > 80 || strings.Trim(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-") != "" {
		return "", "", errors.New("requestId must be 1..80 letters, digits, dots, underscores or hyphens; do not also supply messageId")
	}
	identity, err := b.client.WhoAmI(ctx)
	if err != nil {
		return "", "", err
	}
	if identity == nil {
		return "", "", errors.New("connector identity unavailable")
	}
	if _, err := uuid.Parse(identity.PrincipalID); err != nil {
		return "", "", errors.New("connector identity unavailable")
	}
	name := fmt.Sprintf("pagnet:browser-ask:v1\x00%s\x00%s\x00%s\x00%s", b.network, identity.PrincipalID, target, key)
	return target, uuid.NewSHA1(uuid.NameSpaceURL, []byte(name)).String(), nil
}
