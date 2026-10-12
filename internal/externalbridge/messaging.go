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

// AskUncertainNotice explains an ambiguous ASK submission: the outcome is
// unknown, so only the same request key, agent and text (or a poll) is a
// safe follow-up.
const AskUncertainNotice = "Submission outcome is uncertain; retry only the same requestId, agent and text or poll its result."

func (b *Bridge) addMessagingTools(s *server.MCPServer) {
	if len(b.messagingTargets) == 0 {
		return
	}
	s.AddTool(mcp.NewTool("pagnet_ask", mcp.WithDescription("Ask an explicitly allowed Pagnet agent a question. Agent descriptions are discoverable via pagnet_search; no business capability schema is required. Choose a short requestId such as travel-plan-1 for new work, and reuse the SAME requestId, agent and text for retries. The bridge creates durable identifiers; you do not need UUIDs. Results are durable; poll pagnet_ask_get, never resubmit under a new request key after timeout."+untrusted), mcp.WithReadOnlyHintAnnotation(false), mcp.WithIdempotentHintAnnotation(true), mcp.WithString("targetPrincipalId", mcp.Required()), mcp.WithString("requestId"), mcp.WithString("messageId", mcp.Description("Advanced compatibility: UUID instead of requestId")), mcp.WithString("text", mcp.Required())), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := b.Ask(ctx, r.GetString("targetPrincipalId", ""), r.GetString("requestId", ""), r.GetString("messageId", ""), r.GetString("text", ""))
		if err != nil && out != nil {
			return result(map[string]any{"requestId": r.GetString("requestId", ""), "targetPrincipalId": out.TargetPrincipalID, "messageId": out.MessageID, "threadId": out.ThreadID, "notice": AskUncertainNotice, "reason": err.Error()}, nil)
		}
		return result(out, err)
	})
	s.AddTool(mcp.NewTool("pagnet_ask_get", mcp.WithDescription("Poll only this connector's own ASK and addressed replies. Decryption happens on its device; no other network history is available."+untrusted), mcp.WithReadOnlyHintAnnotation(true), mcp.WithString("targetPrincipalId", mcp.Required()), mcp.WithString("requestId"), mcp.WithString("messageId", mcp.Description("Advanced compatibility: UUID instead of requestId"))), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return result(b.AskGet(ctx, r.GetString("targetPrincipalId", ""), r.GetString("requestId", ""), r.GetString("messageId", "")))
	})
}

// Ask sends (or durably retries) one encrypted ASK to an approved agent.
// key is a short request key (new work, or a retry of the same work);
// messageID is the advanced UUID form. Only one of the two is accepted.
func (b *Bridge) Ask(ctx context.Context, target, key, messageID, text string) (*sdk.BrowserAskResult, error) {
	t, id, err := b.messagingMessageID(ctx, target, key, messageID)
	if err != nil {
		return nil, err
	}
	if len(text) == 0 || len(text) > 64<<10 {
		return nil, errors.New("text must be 1..65536 bytes")
	}
	client, ok := b.client.(messagingClient)
	if !ok {
		return nil, errors.New("device SDK does not support messaging")
	}
	out, err := client.SendBrowserAsk(ctx, b.network, t, id, text)
	if out != nil {
		out.RequestID = key
	}
	return out, err
}

// AskGet polls one of the bridge's own ASKs and addressed replies under its
// messaging policy.
func (b *Bridge) AskGet(ctx context.Context, target, key, messageID string) (*sdk.BrowserAskResult, error) {
	t, id, err := b.messagingMessageID(ctx, target, key, messageID)
	if err != nil {
		return nil, err
	}
	client, ok := b.client.(messagingClient)
	if !ok {
		return nil, errors.New("device SDK does not support messaging")
	}
	out, err := client.GetBrowserAsk(ctx, b.network, id)
	if err != nil {
		return nil, err
	}
	if out == nil || out.MessageID != id || out.TargetPrincipalID != t || !b.messagingTargets[t] {
		return nil, errors.New("ASK target is outside approved messaging policy")
	}
	out.RequestID = key
	return out, nil
}

// Short request keys are scoped to the immutable principal/network/target,
// avoiding both user UUID handling and identity collisions across connectors.
func (b *Bridge) messagingMessageID(ctx context.Context, target, key, messageID string) (string, string, error) {
	if !b.messagingTargets[target] {
		return "", "", errors.New("agent is outside approved messaging targets")
	}
	if key == "" {
		if _, err := uuid.Parse(messageID); err != nil {
			return "", "", errors.New("provide a short requestId for new work or the same key for a retry")
		}
		return target, messageID, nil
	}
	if messageID != "" || len(key) > 80 || strings.Trim(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-") != "" {
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
