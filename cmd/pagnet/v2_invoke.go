package main

// The V2 invocation + event commands (plan D10 / D2): `pagnet invoke`
// (client-side E2EE, sync or async) and `pagnet event publish|watch`.
// The protected content (invocation input, event payload) is encrypted on
// THIS host before it crosses the boundary (D6 always-encrypted); a
// network that is not yet active fails with the clear not-ready error —
// there is no plaintext fallback.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/sdk"
)

// --- pagnet invoke --------------------------------------------------------------

type invocationRecord struct {
	ID             string                   `json:"id,omitempty"`
	IDLegacy       string                   `json:"ID,omitempty"`
	State          string                   `json:"state,omitempty"`
	StateLegacy    string                   `json:"status,omitempty"`
	OutputEnvelope *e2ee.EncryptedPayloadV1 `json:"outputEnvelope,omitempty"`
	ResultEnvelope *e2ee.EncryptedPayloadV1 `json:"resultEnvelope,omitempty"`
	OutputAAD      *e2ee.AAD                `json:"outputAAD,omitempty"`
	ResultAAD      *e2ee.AAD                `json:"resultAAD,omitempty"`
	Error          string                   `json:"error,omitempty"`
	ErrorCode      string                   `json:"publicResultCode,omitempty"`
}

func (r invocationRecord) recID() string {
	if r.ID != "" {
		return r.ID
	}
	return r.IDLegacy
}

func (r invocationRecord) recState() string {
	if r.State != "" {
		return r.State
	}
	return r.StateLegacy
}

func (r invocationRecord) envelopeAAD() (*e2ee.EncryptedPayloadV1, *e2ee.AAD) {
	if r.OutputEnvelope != nil {
		return r.OutputEnvelope, r.OutputAAD
	}
	return r.ResultEnvelope, r.ResultAAD
}

func invokeCmd() *cobra.Command {
	var (
		network        string
		inputPath      string
		idempotencyKey string
		asynchronous   bool
		waitTimeout    time.Duration
		actor          principalActorOptions
	)
	cmd := &cobra.Command{
		Use:   "invoke <agent-or-service> <capability> [--input file|-]",
		Short: "Invoke a network capability (the input is encrypted end-to-end on this host)",
		Long: `Call a capability an agent or a service offers. The input is encrypted on
this host and only the target decrypts it.

An invocation is made BY an agent or a service — the control plane refuses a
signed-in user, because the record's caller must be a network participant. This
host makes the call as one when it holds that participant's credential:

  pagnet invoke docs-svc documents.extract --input in.json
  pagnet invoke docs-svc documents.extract --credential ` + tokenPrefixEndpoint + `... --async

Without --credential the credential comes from $` + sdk.EnvCredential + `, then from the endpoint
credential already stored on this host. pagnet service credential create
<service> (or pagnet agent credential create <agent>) prints one once.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := invokeCLI(actor)
			if err != nil {
				return err
			}
			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			target, err := c.resolveParticipant(netID, args[0])
			if err != nil {
				return err
			}
			input, err := readJSONContent(inputPath)
			if err != nil {
				return err
			}
			// Client-side encryption (D6): the input never crosses the
			// boundary in plaintext. Fails clear when the network's crypto
			// is not active (provisioning) or the keyring is not installed.
			st, kr, err := c.clientCrypto(netID)
			if err != nil {
				return err
			}
			objectID := newClientObjectID()
			env, aad, err := c.encryptClientContent(st, kr,
				e2ee.ObjectTypeInvocationInput, objectID, target.pID(), string(input))
			if err != nil {
				return err
			}
			body := map[string]any{
				"targetPrincipalId": target.pID(),
				"capabilityId":      args[1],
				// The client-generated object id that the AAD binds, under the
				// name the control plane decodes ("invocationId" — same contract
				// as sdk/rest.go's restInvocationRequest). The control plane
				// rejects unknown body fields, so the previous "inputObjectID"
				// key made the WHOLE body fail to decode and the handler answered
				// the misleading "targetPrincipalId and capabilityId required".
				"invocationId": objectID,
				"envelope":     env,
				"aad":          aad,
			}
			if idempotencyKey != "" {
				body["idempotencyKey"] = idempotencyKey
			}
			var rec invocationRecord
			// userCallerFailure renders the control plane's refusal of a human
			// caller as product text; every other failure (and everything a
			// principal actor gets) keeps the server's own reason.
			if err := userCallerFailure(c.post("/api/v1/networks/"+netID+"/invocations", body, &rec)); err != nil {
				return err
			}
			if jsonOut {
				return printJSON(rec)
			}
			if asynchronous {
				fmt.Printf("invocation: %s  state: %s  (target %s, capability %s)\n",
					rec.recID(), orDash(rec.recState()), target.pName(), args[1])
				return nil
			}

			// Synchronous: poll until the invocation settles, then decrypt
			// and print the result.
			ctx, cancel := context.WithTimeout(cmd.Context(), waitTimeout)
			defer cancel()
			settled, err := pollInvocation(ctx, c, netID, rec.recID(), time.Second)
			if err != nil {
				return err
			}
			switch settled.recState() {
			case "completed":
				env, aad := settled.envelopeAAD()
				if env == nil || aad == nil {
					return fmt.Errorf("invocation %s completed without a result envelope", settled.recID())
				}
				plain, err := c.decryptClientContent(kr, *env, *aad)
				if err != nil {
					return err
				}
				// Pretty-print JSON results; pass through anything else.
				var pretty any
				if json.Unmarshal([]byte(plain), &pretty) == nil {
					if b, err := json.MarshalIndent(pretty, "", "  "); err == nil {
						fmt.Println(string(b))
						return nil
					}
				}
				fmt.Println(plain)
				return nil
			case "failed", "cancelled", "canceled":
				if settled.Error != "" {
					return fmt.Errorf("invocation %s %s: %s", settled.recID(), settled.recState(), settled.Error)
				}
				if settled.ErrorCode != "" {
					return fmt.Errorf("invocation %s %s (code %s)", settled.recID(), settled.recState(), settled.ErrorCode)
				}
				return fmt.Errorf("invocation %s %s", settled.recID(), settled.recState())
			default:
				return fmt.Errorf("invocation %s in state %q after waiting", settled.recID(), settled.recState())
			}
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	cmd.Flags().StringVar(&inputPath, "input", "", "invocation input as a JSON file (or '-' for stdin; default: an empty object)")
	cmd.Flags().StringVar(&idempotencyKey, "idempotency-key", "", "idempotency key (a retried call with the same key is not re-executed)")
	cmd.Flags().BoolVar(&asynchronous, "async", false, "return after the invocation is queued (do not wait for the result)")
	cmd.Flags().DurationVar(&waitTimeout, "timeout", 120*time.Second, "how long to wait for the result (sync mode)")
	actor.register(cmd)
	return cmd
}

// invokeCLI resolves the bearer `pagnet invoke` acts with.
//
// An invocation is made BY a principal (api_invocations.go refuses a user
// actor with 400), so the CLI prefers an actor that can actually succeed: an
// explicit --credential / $PAGNET_CREDENTIAL, or the endpoint credential this
// host already stores for a principal. With nothing stored, the signed-in
// user's bearer is the only bearer available — the call still goes out (the
// server is the authority on who may invoke) and its refusal is translated by
// userCallerFailure into the text that names the credential that works.
func invokeCLI(opts principalActorOptions) (*cliCtx, error) {
	if opts.credential != "" || opts.as != "" || os.Getenv(sdk.EnvCredential) != "" {
		// The operator named a principal actor: that IS the intent, so a
		// problem with it is reported, never traded for a human bearer.
		return newPrincipalCLI("", opts)
	}
	c, err := newPrincipalCLI("", opts)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, errNoPrincipalCredential) {
		return nil, err // malformed credential / ambiguous store / unknown --as
	}
	return newCLI("")
}

// pollInvocation waits for the invocation to leave the pending/dispatched
// states and returns the settled record (or the last seen state on timeout).
func pollInvocation(ctx context.Context, c *cliCtx, netID, invID string, interval time.Duration) (invocationRecord, error) {
	var last invocationRecord
	for {
		var rec invocationRecord
		if err := c.get("/api/v1/networks/"+netID+"/invocations/"+invID, &rec); err != nil {
			return invocationRecord{}, err
		}
		last = rec
		switch last.recState() {
		case "completed", "failed", "cancelled", "canceled":
			return last, nil
		}
		select {
		case <-ctx.Done():
			return last, fmt.Errorf("timed out waiting for invocation %s (last state: %s)", invID, orDash(last.recState()))
		case <-time.After(interval):
		}
	}
}

// --- pagnet event publish|watch ---------------------------------------------------

func eventCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "event",
		Short: "Publish and watch network events (the payload is encrypted end-to-end)",
	}
	cmd.AddCommand(eventPublishCmd(), eventWatchCmd())
	return cmd
}

func eventPublishCmd() *cobra.Command {
	var (
		network string
		payload string
		target  string
	)
	cmd := &cobra.Command{
		Use:   "publish <type> [--payload file|-]",
		Short: "Publish a typed network event (the payload is encrypted end-to-end)",
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
			eventType := args[0]
			if !strings.Contains(eventType, ".") {
				return fmt.Errorf("event types are dot-separated (e.g. build.completed); got %q", eventType)
			}
			payloadBytes, err := readJSONContent(payload)
			if err != nil {
				return err
			}
			targetID := ""
			if target != "" {
				p, err := c.resolveParticipant(netID, target)
				if err != nil {
					return err
				}
				targetID = p.pID()
			}
			st, kr, err := c.clientCrypto(netID)
			if err != nil {
				return err
			}
			objectID := newClientObjectID()
			env, aad, err := c.encryptClientContent(st, kr,
				e2ee.ObjectTypeEventPayload, objectID, targetID, string(payloadBytes))
			if err != nil {
				return err
			}
			body := map[string]any{
				"type":          eventType,
				"schemaVersion": 1,
				"eventId":       objectID,
				"envelope":      env,
				"aad":           aad,
			}
			if targetID != "" {
				body["targetPrincipalId"] = targetID
			}
			var created struct {
				ID       string `json:"id"`
				IDLegacy string `json:"ID"`
			}
			if err := c.post("/api/v1/networks/"+netID+"/events", body, &created); err != nil {
				return err
			}
			id := created.ID
			if id == "" {
				id = created.IDLegacy
			}
			if id == "" {
				id = objectID // the client-minted id the server adopts
			}
			if jsonOut {
				return printJSON(map[string]any{"eventId": id, "type": eventType, "network": netID, "target": targetID})
			}
			fmt.Printf("event: %s  type: %s", id, eventType)
			if target != "" {
				fmt.Printf("  target: %s", target)
			}
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	cmd.Flags().StringVar(&payload, "payload", "", "event payload as a JSON file (or '-' for stdin; default: an empty object)")
	cmd.Flags().StringVar(&target, "target", "", "deliver a wake to this participant (name or id; default: network-wide)")
	return cmd
}

// streamEvent is one line of the control plane's SSE event stream. The V2
// domain events carry capitalized JSON fields (domain.Event); the heartbeat
// is lowercase. Dual tags accept both.
type streamEvent struct {
	ID          string          `json:"ID"`
	IDlc        string          `json:"id"`
	EventType   string          `json:"EventType"`
	EventTypeLC string          `json:"eventType"`
	NetworkID   *string         `json:"NetworkID"`
	NetworkIDLC *string         `json:"networkId"`
	Timestamp   string          `json:"Timestamp"`
	TimestampLC string          `json:"timestamp"`
	Payload     json.RawMessage `json:"payload"`
}

func (e streamEvent) eventType() string {
	if e.EventType != "" {
		return e.EventType
	}
	return e.EventTypeLC
}

func (e streamEvent) networkID() string {
	if e.NetworkID != nil {
		return *e.NetworkID
	}
	if e.NetworkIDLC != nil {
		return *e.NetworkIDLC
	}
	return ""
}

func (e streamEvent) ts() string {
	if e.Timestamp != "" {
		return e.Timestamp
	}
	return e.TimestampLC
}

func eventWatchCmd() *cobra.Command {
	var (
		network   string
		eventType string
	)
	cmd := &cobra.Command{
		Use:   "watch [--type pattern]",
		Short: "Live-tail the network's events (SSE stream, filtered)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID := ""
			if network != "" {
				netID, _, err = c.resolveNetwork(network)
				if err != nil {
					return err
				}
			}
			// The existing control-plane SSE stream (ticket-authenticated):
			// POST a one-shot ticket, then open the stream.
			var ticket struct {
				Ticket string `json:"ticket"`
			}
			if err := c.post("/api/v1/events/stream/ticket", map[string]any{}, &ticket); err != nil {
				return err
			}
			if ticket.Ticket == "" {
				return fmt.Errorf("no stream ticket returned")
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
				c.base+"/api/v1/events/stream?ticket="+ticket.Ticket, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Accept", "text/event-stream")
			if c.token != "" {
				req.Header.Set("Authorization", "Bearer "+c.token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("http %d opening the event stream", resp.StatusCode)
			}
			if !silent {
				fmt.Fprintln(os.Stderr, "watching events (Ctrl+C to stop)")
			}

			r := bufio.NewReader(resp.Body)
			var dataLine, idLine string
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					if ctx.Err() != nil {
						return nil // stopped by the user
					}
					return fmt.Errorf("event stream closed: %v", err)
				}
				line = strings.TrimRight(line, "\r\n")
				switch {
				case strings.HasPrefix(line, "data:"):
					dataLine = strings.TrimPrefix(line, "data:")
					dataLine = strings.TrimPrefix(dataLine, " ")
				case strings.HasPrefix(line, "id:"):
					idLine = strings.TrimPrefix(line, "id:")
					idLine = strings.TrimPrefix(idLine, " ")
				case line == "":
					if dataLine == "" {
						continue
					}
					if !handleStreamLine(cmd, json.RawMessage(dataLine), idLine, netID, eventType) {
						return nil
					}
					dataLine, idLine = "", ""
				default:
					// Comment (": connected") / unknown — skip.
				}
			}
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "only events of this network (default: all)")
	cmd.Flags().StringVar(&eventType, "type", "", "only events matching this type pattern (* wildcards)")
	return cmd
}

// handleStreamLine renders one SSE event after the filters. It returns
// false when the watcher should stop (only on a decode-level fatal;
// normally it always returns true).
func handleStreamLine(cmd *cobra.Command, raw json.RawMessage, idLine, netID, typePattern string) bool {
	if !json.Valid(raw) {
		return true
	}
	var ev streamEvent
	if json.Unmarshal(raw, &ev) != nil {
		return true
	}
	et := ev.eventType()
	if et == "" || et == "stream.heartbeat" {
		return true // liveness, not an event
	}
	if typePattern != "" {
		match, err := matchPattern(typePattern, et)
		if err != nil || !match {
			return true
		}
	}
	if netID != "" && ev.networkID() != "" && ev.networkID() != netID {
		return true
	}
	if jsonOut {
		fmt.Println(string(raw))
		return true
	}
	net := ev.networkID()
	if net == "" {
		net = "(tenant)"
	}
	id := ev.ID
	if id == "" {
		id = ev.IDlc
	}
	if id == "" {
		id = idLine
	}
	fmt.Printf("%s  %s  [%s]  %s\n", ev.ts(), ev.eventType(), net, orDash(id))
	return true
}

// matchPattern matches an event type against a dot-separated pattern with
// * wildcards (dots are literals, * matches any run — build.* matches
// build.completed and build.test.failed). path.Match has exactly these
// semantics for slash-free strings.
func matchPattern(pattern, s string) (bool, error) {
	ok, err := path.Match(pattern, s)
	if err != nil {
		return false, fmt.Errorf("invalid --type pattern %q: %v", pattern, err)
	}
	return ok, nil
}
