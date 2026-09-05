package main

// `pagnet chat [rep]` — talk to your Representative from the CLI
// (addendum §55). The CLI is just another frontend to the same logical
// human delegate as Telegram and the Web UI: messages go through the same
// channel gateway (the fake channel for the CLI) into the same
// Representative conversation model.

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func chatCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chat [rep]",
		Short: "Chat with your Representative (same delegate as Telegram/Web)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			repName := ""
			if len(args) == 1 {
				repName = args[0]
			}

			var reps []struct {
				ID   string `json:"ID"`
				Name string `json:"Name"`
			}
			if err := c.get("/api/v1/representatives", &reps); err != nil {
				return err
			}
			// No argument: the first rep in list order (the same rep the
			// server falls back to — deterministic on both sides).
			rep, repLabel := "", ""
			for _, r := range reps {
				if repName == "" || r.Name == repName {
					rep, repLabel = r.ID, r.Name
					break
				}
			}
			if rep == "" {
				if repName != "" {
					return fmt.Errorf("representative %q not found (create one in the Web UI)", repName)
				}
				return fmt.Errorf("no representatives exist yet (create one in the Web UI first)")
			}

			// Ensure the CLI's fake-channel binding (pairing once, like
			// the other channels — the binding is the access gate).
			bindingID, convID, err := c.ensureFakeBinding()
			if err != nil {
				return err
			}

			fmt.Printf("chatting with representative %s (the same delegate Telegram and the Web reach)\n", repLabel)
			fmt.Println("type a message; 'exit' to leave")
			for {
				fmt.Print("you> ")
				scanner := bufio.NewScanner(os.Stdin)
				if !scanner.Scan() {
					break
				}
				text := strings.TrimSpace(scanner.Text())
				if text == "" {
					continue
				}
				if text == "exit" || text == "quit" {
					break
				}
				var out struct {
					ConversationID string `json:"conversationId"`
					Delivered      bool   `json:"delivered"`
					InstanceStatus string `json:"instanceStatus"`
				}
				if err := c.post("/api/v1/channels/fake/messages", map[string]any{
					"bindingId":        bindingID,
					"representativeId": rep,
					"text":             text,
				}, &out); err != nil {
					fmt.Fprintln(os.Stderr, "send failed:", err)
					continue
				}
				convID = out.ConversationID
				if !out.Delivered {
					fmt.Printf("(delivered later — the representative is %s; your message is kept durable)\n", out.InstanceStatus)
				}
				if reply, err := c.waitRepReply(convID); err != nil {
					fmt.Fprintln(os.Stderr, "no reply:", err)
				} else {
					fmt.Printf("rep>  %s\n", reply)
				}
			}
			return nil
		},
	}
	return cmd
}

// ensureFakeBinding finds (or pairs) the CLI's fake-channel binding and
// returns it with the id of the CLI's conversation.
func (c *cliCtx) ensureFakeBinding() (bindingID, convID string, err error) {
	var bindings []struct {
		ID        string `json:"ID"`
		Channel   string `json:"Channel"`
		RevokedAt any    `json:"RevokedAt"`
	}
	if err := c.get("/api/v1/channels/bindings", &bindings); err != nil {
		return "", "", err
	}
	for _, b := range bindings {
		if b.Channel == "fake" && b.RevokedAt == nil {
			bindingID = b.ID
		}
	}
	if bindingID == "" {
		var pc struct {
			Code string `json:"code"`
		}
		if err := c.post("/api/v1/channels/pairing-codes", map[string]any{"channel": "fake"}, &pc); err != nil {
			return "", "", fmt.Errorf("pairing code: %w", err)
		}
		who, _ := user.Current()
		externalUser := "cli"
		if who != nil && who.Username != "" {
			externalUser = "cli-" + who.Username
		}
		var b struct {
			ID string `json:"ID"`
		}
		if err := c.post("/api/v1/channels/pair", map[string]any{
			"channel":        "fake",
			"code":           pc.Code,
			"externalUserId": externalUser,
			"externalChatId": "cli",
		}, &b); err != nil {
			return "", "", fmt.Errorf("pair: %w", err)
		}
		bindingID = b.ID
	}
	// The CLI's own conversation for this binding (first match on chat id).
	var convs []struct {
		ID                   string `json:"ID"`
		ExternalConversation string `json:"ExternalConversationID"`
	}
	if err := c.get("/api/v1/channels/bindings/"+bindingID+"/conversations", &convs); err != nil {
		return "", "", err
	}
	for _, cv := range convs {
		if cv.ExternalConversation == "cli" || cv.ExternalConversation == "default" {
			convID = cv.ID
		}
	}
	return bindingID, convID, nil
}

// waitRepReply polls the conversation for the next outbound message after
// the one just sent.
func (c *cliCtx) waitRepReply(convID string) (string, error) {
	deadline := time.Now().Add(180 * time.Second)
	lastSentAt := time.Now()
	for time.Now().Before(deadline) {
		var out struct {
			Messages []struct {
				ID        string `json:"ID"`
				Direction string `json:"Direction"`
				Body      string `json:"Body"`
				CreatedAt string `json:"CreatedAt"`
			} `json:"messages"`
		}
		if err := c.get("/api/v1/channels/conversations/"+convID+"/messages?limit=100", &out); err != nil {
			return "", err
		}
		for _, m := range out.Messages {
			if m.Direction != "out" {
				continue
			}
			if t, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err == nil && t.Before(lastSentAt) {
				continue
			}
			return m.Body, nil
		}
		time.Sleep(1 * time.Second)
	}
	return "", fmt.Errorf("the representative did not reply in time (is it running? check its instance)")
}
