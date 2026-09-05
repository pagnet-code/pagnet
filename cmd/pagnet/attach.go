package main

// `pagnet attach <agent>` — interactive attach to a managed agent on
// (possibly another) host, through the control-plane terminal proxy
// (spec §54). The same session model as the browser terminal: input lines
// become turns; output streams back; closing the REPL detaches.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

func attachCmd() *cobra.Command {
	var network, instanceID string
	cmd := &cobra.Command{
		Use:   "attach <agent>",
		Short: "Attach interactively to a running agent (terminal proxy)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			defID, inst, err := c.findInstance(netID, args[0], instanceID)
			if err != nil {
				return err
			}

			var att struct {
				AttachSessionID string `json:"attachSessionId"`
				WSTicket        string `json:"wsTicket"`
			}
			if err := c.post("/api/v1/networks/"+netID+"/agents/"+defID+"/instances/"+inst.ID+"/attach",
				map[string]any{}, &att); err != nil {
				return fmt.Errorf("attach: %w", err)
			}
			session := att.AttachSessionID
			fmt.Printf("attached to %s (instance %s, session %s)\n", args[0], inst.ID, session)
			fmt.Println("type to send input; 'exit' or Ctrl-D to detach")

			u, err := url.Parse(c.base)
			if err != nil {
				return err
			}
			// wss only for an https control plane — never downgrade TLS
			// (the scheme must be read BEFORE it is rewritten).
			switch u.Scheme {
			case "https":
				u.Scheme = "wss"
			default:
				u.Scheme = "ws"
			}
			u.Path = "/api/v1/attach/" + session + "/ws"
			// The WS handshake carries the one-shot ticket issued with the
			// attach — never the long-lived token (SEC-004).
			u.RawQuery = "ticket=" + url.QueryEscape(att.WSTicket)
			ws, resp, err := websocket.DefaultDialer.Dial(u.String(), nil)
			if err != nil {
				return fmt.Errorf("attach WS: %v (status %v)", err, resp)
			}
			defer func() { _ = ws.Close() }()

			// Output pump: print runtime output; surface errors.
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					_, raw, err := ws.ReadMessage()
					if err != nil {
						return
					}
					var f struct {
						Type  string `json:"type"`
						Data  string `json:"data"`
						Error string `json:"error"`
					}
					if json.Unmarshal(raw, &f) != nil {
						continue
					}
					switch f.Type {
					case "output":
						fmt.Println(f.Data)
					case "error":
						fmt.Fprintln(os.Stderr, "attach:", f.Error)
					}
				}
			}()

			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "exit" || line == "quit" {
					break
				}
				if line == "" {
					continue
				}
				if err := ws.WriteJSON(map[string]any{"type": "input", "data": line}); err != nil {
					return fmt.Errorf("send input: %w", err)
				}
			}
			if err := scanner.Err(); err != nil && err.Error() != "EOF" {
				return err
			}

			// Give the last output frames a moment, then detach.
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				select {
				case <-done:
				default:
					time.Sleep(100 * time.Millisecond)
				}
			}
			fmt.Println("detached")
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network of the agent (default: the saved/only network)")
	cmd.Flags().StringVar(&instanceID, "instance", "", "instance id (when the agent has several)")
	return cmd
}

// findInstance resolves an agent by name and picks its instance (the only
// one, or --instance).
func (c *cliCtx) findInstance(netID, agentName, instanceID string) (defID string, inst *struct {
	ID     string `json:"ID"`
	Status string `json:"Status"`
}, err error) {
	var agents []struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
	}
	if err := c.get("/api/v1/networks/"+netID+"/agents", &agents); err != nil {
		return "", nil, err
	}
	def := ""
	for _, a := range agents {
		if a.Name == agentName {
			def = a.ID
		}
	}
	if def == "" {
		return "", nil, fmt.Errorf("agent %q not found in this network", agentName)
	}
	var insts []struct {
		ID     string `json:"ID"`
		Status string `json:"Status"`
	}
	if err := c.get("/api/v1/networks/"+netID+"/agents/"+def+"/instances", &insts); err != nil {
		return "", nil, err
	}
	switch len(insts) {
	case 0:
		return "", nil, fmt.Errorf("agent %s has no instance (launch one first)", agentName)
	case 1:
		return def, &insts[0], nil
	}
	if instanceID == "" {
		fmt.Println("instances:")
		for _, i := range insts {
			fmt.Printf("  %s  %s\n", i.ID, i.Status)
		}
		return "", nil, fmt.Errorf("pick one with --instance")
	}
	for i := range insts {
		if insts[i].ID == instanceID {
			return def, &insts[i], nil
		}
	}
	return "", nil, fmt.Errorf("instance %s not found for %s", instanceID, agentName)
}
