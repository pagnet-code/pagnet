package main

// The V2 network surface (plan D10 / D2): agents (with live endpoints),
// services (+ service create/connect), search, subscriptions, and network
// members (add/invite/revoke). Request/response commands are REST (not WS).
//
// Terminology (D10): the user-facing surface says agent / service /
// participant — NEVER "principal" (that is the internal model), and NEVER
// "worker" (the legacy managed-agent word; `pagnet worker` itself stays
// internal and unchanged).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/sdk"
)

// --- V2 wire shapes (D2) ------------------------------------------------------
//
// Dual tags: the V2 control plane returns camelCase documents
// (id/name/endpoints/permissions); the pre-cutover server returns the legacy
// capitalized shape. A row renders whichever the server sent.

type v2Capability struct {
	ID          string   `json:"id"`
	Version     int      `json:"version"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type v2Endpoint struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
	Online bool   `json:"online,omitempty"`
}

// v2Participant is a network agent or service as the V2 API returns it
// (agent principal / service principal + live endpoints + membership).
// Dual tags: the V2 control plane returns camelCase documents; the
// pre-cutover server returns the legacy capitalized shape. omitempty keeps
// --json output clean (only the server's actual shape is emitted).
type v2Participant struct {
	ID           string         `json:"id,omitempty"`
	IDLegacy     string         `json:"ID,omitempty"`
	Name         string         `json:"name,omitempty"`
	NameLegacy   string         `json:"Name,omitempty"`
	Kind         string         `json:"kind,omitempty"`
	KindLegacy   string         `json:"Kind,omitempty"`
	Runtime      string         `json:"runtime,omitempty"`
	Status       string         `json:"status,omitempty"`
	Description  string         `json:"description,omitempty"`
	Capabilities []v2Capability `json:"capabilities,omitempty"`
	Endpoints    []v2Endpoint   `json:"endpoints,omitempty"`
	Permissions  []string       `json:"permissions,omitempty"`
	State        string         `json:"state,omitempty"`
}

func (p v2Participant) pID() string {
	if p.ID != "" {
		return p.ID
	}
	return p.IDLegacy
}

func (p v2Participant) pName() string {
	if p.Name != "" {
		return p.Name
	}
	return p.NameLegacy
}

func (p v2Participant) pKind() string {
	switch {
	case p.Kind != "":
		return p.Kind
	case p.KindLegacy != "":
		return p.KindLegacy
	default:
		return ""
	}
}

func (p v2Participant) endpointStatus() string {
	if p.Status != "" {
		return p.Status
	}
	if len(p.Endpoints) == 0 {
		return ""
	}
	online, offline := 0, 0
	for _, e := range p.Endpoints {
		if e.Online || e.Status == "online" || e.Status == "working" || e.Status == "idle" {
			online++
		} else {
			offline++
		}
	}
	if online > 0 {
		return fmt.Sprintf("%d online", online)
	}
	return fmt.Sprintf("%d offline", offline)
}

// fetchParticipants loads a network's agents + services (the V2
// membership view: members are agents and services).
func (c *cliCtx) fetchParticipants(netID string) ([]v2Participant, error) {
	var agents []v2Participant
	if err := c.get("/api/v1/networks/"+netID+"/agents", &agents); err != nil {
		return nil, err
	}
	var services []v2Participant
	if err := c.get("/api/v1/networks/"+netID+"/services", &services); err != nil {
		return nil, err
	}
	return append(agents, services...), nil
}

// resolveParticipant resolves a name-or-id to a network participant.
func (c *cliCtx) resolveParticipant(netID, nameOrID string) (v2Participant, error) {
	all, err := c.fetchParticipants(netID)
	if err != nil {
		return v2Participant{}, err
	}
	for _, p := range all {
		if p.pID() == nameOrID || p.pName() == nameOrID {
			return p, nil
		}
	}
	// Not a member: a bare id may still name a known participant — ask for
	// its detail (D2 GET /principals/{id}).
	var det v2Participant
	if err := c.get("/api/v1/principals/"+nameOrID, &det); err == nil && det.pName() != "" {
		return det, nil
	}
	return v2Participant{}, fmt.Errorf("%q is not an agent or service in this network", nameOrID)
}

// participantRow is one table row for a network participant.
func participantRow(p v2Participant) []string {
	kind := p.pKind()
	if kind == "" {
		kind = "participant"
	}
	perms := ""
	if len(p.Permissions) > 0 {
		perms = strings.Join(p.Permissions, ", ")
	}
	state := p.State
	if state == "" {
		state = "active"
	}
	caps := ""
	if len(p.Capabilities) > 0 {
		ids := make([]string, 0, len(p.Capabilities))
		for _, cap := range p.Capabilities {
			ids = append(ids, cap.ID)
		}
		caps = strings.Join(ids, ", ")
	}
	return []string{p.pName(), kind, p.endpointStatus(), perms, state, caps, p.pID()}
}

var participantHeaders = []string{"NAME", "KIND", "ENDPOINTS", "PERMISSIONS", "STATE", "CAPABILITIES", "ID"}

// validPermission validates a --permission value against the V2 permission
// vocabulary (domain.NetworkPermission).
func validPermission(p string) error {
	if !domain.NetworkPermission(p).Valid() {
		return fmt.Errorf("unknown permission %q (discover|communicate|invoke|event_publish|event_subscribe|task_read|task_write|operate)", p)
	}
	return nil
}

// --- pagnet agents (V2: agents + live endpoints) -----------------------------

func agentsCmd() *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:   "agents",
		Short: "List the network's agents with their live endpoints and capabilities",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			all, err := c.fetchParticipants(netID)
			if err != nil {
				return err
			}
			var agents []v2Participant
			for _, p := range all {
				if p.pKind() == "service" {
					continue
				}
				agents = append(agents, p)
			}
			if jsonOut {
				return printJSON(agents)
			}
			if len(agents) == 0 {
				fmt.Println("no agents in this network yet")
				return nil
			}
			rows := make([][]string, 0, len(agents))
			for _, a := range agents {
				rows = append(rows, participantRow(a))
			}
			printTable(participantHeaders, rows)
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	return cmd
}

// --- pagnet services / service create|connect ---------------------------------

func servicesCmd() *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:   "services",
		Short: "List the network's services and their capabilities",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			all, err := c.fetchParticipants(netID)
			if err != nil {
				return err
			}
			var services []v2Participant
			for _, p := range all {
				if p.pKind() == "service" {
					services = append(services, p)
				}
			}
			if jsonOut {
				return printJSON(services)
			}
			if len(services) == 0 {
				fmt.Println("no services in this network yet (add one with `pagnet service create` or `pagnet network members add`)")
				return nil
			}
			rows := make([][]string, 0, len(services))
			for _, s := range services {
				rows = append(rows, participantRow(s))
			}
			printTable(participantHeaders, rows)
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	return cmd
}

// serviceCmd groups `service create`, `service connect`, and the credential
// surface (the service onboarding path: create → one-time activation
// credential → connect; plan §9 adds manual restricted credentials).
func serviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Create and connect services (onboarding) and manage their credentials",
	}
	cmd.AddCommand(serviceCreateCmd(), serviceConnectCmd(), credentialParentCmd(principalService))
	return cmd
}

// serviceCreateCmd implements `pagnet service create <name>` (D10): creates
// the service and prints the ONE-TIME activation credential exactly once.
func serviceCreateCmd() *cobra.Command {
	var (
		description string
		capIDs      []string
		capDescs    []string
		tags        []string
		public      bool
		network     string
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a service (prints a one-time activation credential)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			body := map[string]any{"name": args[0]}
			if description != "" {
				body["description"] = description
			}
			if public {
				body["visibility"] = "public"
			}
			caps := make([]map[string]any, 0, len(capIDs))
			for i, id := range capIDs {
				cp := map[string]any{"id": id, "version": 1}
				if i < len(capDescs) && capDescs[i] != "" {
					cp["description"] = capDescs[i]
				}
				if len(tags) > 0 {
					cp["tags"] = tags
				}
				caps = append(caps, cp)
			}
			if len(caps) > 0 {
				body["capabilities"] = caps
			}
			// The server answers {principal: {ID, Name, …}, activationCredential:
			// {credential, expiresAt}}. The credential is an OBJECT (it carries
			// its expiry) and the principal's fields are nested under "principal"
			// — domain.Principal marshals its exported field names, so the id is
			// "ID", not "id". Decoding this as a flat {id, name} plus a string
			// credential failed the POST outright:
			// "cannot unmarshal object into Go struct field .activationCredential
			// of type string".
			var created struct {
				Principal struct {
					ID   string `json:"ID"`
					Name string `json:"Name"`
				} `json:"principal"`
				// The one-time activation credential (returned ONCE, D3).
				ActivationCredential struct {
					Credential string `json:"credential"`
					ExpiresAt  string `json:"expiresAt"`
				} `json:"activationCredential"`
			}
			if err := c.post("/api/v1/services", body, &created); err != nil {
				return err
			}
			id := created.Principal.ID
			if jsonOut {
				return printJSON(map[string]any{"id": id, "name": created.Principal.Name,
					"activationCredential": created.ActivationCredential.Credential})
			}
			if !silent {
				fmt.Printf("service:  %s (%s)\n", orDash(created.Principal.Name), id)
			}
			// Join the resolved network when one is given (the service is
			// created tenant-wide; membership is a separate step).
			if network != "" {
				netID, _, err := c.resolveNetwork(network)
				if err != nil {
					return err
				}
				if err := c.post("/api/v1/networks/"+netID+"/services", map[string]any{"principalId": id}, nil); err != nil {
					return err
				}
				if !silent {
					fmt.Printf("joined:   network %s\n", netID)
				}
			}
			if created.ActivationCredential.Credential == "" {
				if !silent {
					fmt.Println("activation credential: not returned by the server (re-create to obtain one)")
				}
				return nil
			}
			// The one-time rule: printed ONCE here, never stored.
			fmt.Printf("\nactivation credential (one-time — save it now, it is shown only once):\n  %s\n\n", created.ActivationCredential.Credential)
			if !silent {
				fmt.Println("connect the service with: pagnet service connect " + orDash(created.Principal.Name))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&description, "description", "", "service description")
	cmd.Flags().StringSliceVar(&capIDs, "capability", nil, "capability id to offer (repeatable; --capability-desc pairs a description)")
	cmd.Flags().StringSliceVar(&capDescs, "capability-desc", nil, "description per --capability (same order)")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "tags for the offered capabilities")
	cmd.Flags().BoolVar(&public, "public", false, "discoverable by anyone (default: private)")
	cmd.Flags().StringVarP(&network, "network", "n", "", "also join this network after creating")
	return cmd
}

// serviceConnectCmd implements `pagnet service connect <name>` (D10): the
// Go SDK quickstart for wiring the service to the network.
func serviceConnectCmd() *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:   "connect <name>",
		Short: "Show the Go SDK quickstart to connect a service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			name := args[0]
			if network != "" {
				netID, _, err := c.resolveNetwork(network)
				if err != nil {
					return err
				}
				p, err := c.resolveParticipant(netID, args[0])
				if err != nil {
					return err
				}
				name = p.pName()
			}
			if jsonOut {
				return printJSON(map[string]any{"service": name, "quickstart": serviceQuickstart(name, c.base)})
			}
			fmt.Println(serviceQuickstart(name, c.base))
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "verify the service is in this network")
	return cmd
}

// serviceQuickstart renders the minimal Go SDK connect snippet (D9/D10).
func serviceQuickstart(name, serverURL string) string {
	return `Connect your Go service to pagnet (plan §D9 SDK):

  // 1. Install the SDK
  go get github.com/pagnet-code/pagnet/sdk

  // 2. Set the environment: the control plane + the SERVICE's credential.
  //    PAGNET_CREDENTIAL is the endpoint credential for this service —
  //    the one-time activation credential printed by
  //    'pagnet service create' (or a durable credential minted from the
  //    console). The CLI never stores it.
  export PAGNET_SERVER=` + orDash(serverURL) + `
  export PAGNET_CREDENTIAL=pgn_epd_v1_...

  // 3. main.go — serve the service's capabilities on the endpoint:
  import (
      "context"
      pagnet "github.com/pagnet-code/pagnet/sdk"
  )

  func main() {
      ctx := context.Background()
      client, err := pagnet.Connect(ctx, pagnet.ConfigFromEnv())
      check(err)
      svc := client.Service("` + name + `")
      svc.Handle("` + name + `.echo", func(ctx context.Context, in echoIn) (echoOut, error) {
          return echoOut{Text: in.Text}, nil
      })
      svc.Serve(ctx) // reconnects, heartbeats, acks; runs until cancelled
  }

  type echoIn struct{ Text string }
  type echoOut struct{ Text string }

Then call it from the network. An invocation is made BY an agent or a service,
so the caller presents that participant's own endpoint credential (the control
plane refuses a signed-in user):

  pagnet invoke ` + name + ` ` + name + `.echo --input input.json --credential ` + tokenPrefixEndpoint + `...

With no --credential the caller uses $` + sdk.EnvCredential + `, or the endpoint credential it
already stores on this host.`
}

// --- pagnet search (D10) -------------------------------------------------------

type searchResult struct {
	ID           string   `json:"id,omitempty"`
	IDLegacy     string   `json:"ID,omitempty"`
	Kind         string   `json:"kind,omitempty"`
	Name         string   `json:"name,omitempty"`
	Capability   string   `json:"capability,omitempty"`
	Description  string   `json:"description,omitempty"`
	MatchReasons []string `json:"matchReasons,omitempty"`
	State        string   `json:"state,omitempty"`
}

// searchPage is the control plane's search envelope. BOTH search endpoints
// (GET /networks/{id}/search and GET /services/search) answer
// {results, cursor} and nothing else.
//
// The CLI used to treat "decoded, but empty" as a decode failure and retry the
// request into a bare []searchResult. The server never answers with a bare
// array, so that fallback fired on exactly the case it could not handle: a
// legitimate zero-result search. It reported
// "json: cannot unmarshal object into Go value of type []main.searchResult"
// instead of "nothing found".
type searchPage struct {
	Results []searchResult `json:"results"`
	Cursor  string         `json:"cursor"`
}

func searchCmd() *cobra.Command {
	var (
		network    string
		capability string
		kind       string
		public     bool
		limit      int
		cursor     string
	)
	cmd := &cobra.Command{
		Use:   "search [query]",
		Short: "Discover agents, services, and capabilities (--public: the public service directory)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			query := ""
			if len(args) > 0 {
				query = args[0]
			}
			if kind != "" && kind != "agent" && kind != "service" && kind != "capability" {
				return fmt.Errorf("--kind must be agent|service|capability (got %q)", kind)
			}
			var (
				results []searchResult
				next    string
			)
			if public {
				// Public service discovery (no network required).
				path := fmt.Sprintf("/api/v1/services/search?query=%s&limit=%d", urlQueryEscape(query), limit)
				if cursor != "" {
					path += "&cursor=" + urlQueryEscape(cursor)
				}
				var page searchPage
				if err := c.get(path, &page); err != nil {
					return err
				}
				results, next = page.Results, page.Cursor
			} else {
				netID, _, err := c.resolveNetwork(network)
				if err != nil {
					return err
				}
				path := fmt.Sprintf("/api/v1/networks/%s/search?query=%s&limit=%d", netID, urlQueryEscape(query), limit)
				if kind != "" {
					path += "&kind=" + kind
				}
				if capability != "" {
					path += "&capability=" + urlQueryEscape(capability)
				}
				if cursor != "" {
					path += "&cursor=" + urlQueryEscape(cursor)
				}
				var page searchPage
				if err := c.get(path, &page); err != nil {
					return err
				}
				results, next = page.Results, page.Cursor
			}
			if jsonOut {
				return printJSON(map[string]any{"results": results, "cursor": next})
			}
			if len(results) == 0 {
				fmt.Println("no results")
				return nil
			}
			rows := make([][]string, 0, len(results))
			for _, r := range results {
				id := r.ID
				if id == "" {
					id = r.IDLegacy
				}
				name := r.Name
				if name == "" {
					name = r.Capability
				}
				rows = append(rows, []string{
					orDash(r.Kind), orDash(name), orDash(r.Capability),
					orDash(r.Description), orDash(strings.Join(r.MatchReasons, "; ")), orDash(r.State), orDash(id),
				})
			}
			printTable([]string{"KIND", "NAME", "CAPABILITY", "DESCRIPTION", "MATCH", "STATE", "ID"}, rows)
			if next != "" {
				fmt.Printf("\nmore results: --cursor %s\n", next)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network to search (default: the saved/only network)")
	cmd.Flags().StringVar(&capability, "capability", "", "search for a specific capability id")
	cmd.Flags().StringVar(&kind, "kind", "", "restrict to agent|service|capability")
	cmd.Flags().BoolVar(&public, "public", false, "search the public service directory (no network)")
	cmd.Flags().IntVar(&limit, "limit", 20, "max results")
	cmd.Flags().StringVar(&cursor, "cursor", "", "pagination cursor from a prior search")
	return cmd
}

// --- pagnet subscribe / subscriptions / unsubscribe ----------------------------

type v2Subscription struct {
	ID       string `json:"id,omitempty"`
	IDLegacy string `json:"ID,omitempty"`
	Pattern  string `json:"eventPattern,omitempty"`
	Mode     string `json:"mode,omitempty"`
}

func (s v2Subscription) sID() string {
	if s.ID != "" {
		return s.ID
	}
	return s.IDLegacy
}

func subscribeCmd() *cobra.Command {
	var network string
	var actor principalActorOptions
	cmd := &cobra.Command{
		Use:   "subscribe <pattern>",
		Short: "Subscribe to a network event pattern (dot-separated, * wildcards; needs the agent's or service's endpoint credential)",
		Long: `Subscribe the calling agent or service to a network event pattern.

Subscriptions are the subscriber's own surface: the control plane answers a
signed-in user 404 (anti-enumeration — the SDK is the subscription manager), so
this command is acted on by the agent or service itself and needs its endpoint
credential:

  pagnet subscribe build.* --credential ` + tokenPrefixEndpoint + `...
  pagnet subscribe build.* --as <agent-or-service-id>

With no flag the credential comes from $` + sdk.EnvCredential + `, then from the endpoint credential
already stored on this host. pagnet service credential create <service> (or
pagnet agent credential create <agent>) prints one once.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// There is no user-bearer path here to fall back on: a human actor
			// is answered 404 by design, so the CLI says so locally (naming the
			// credential that works) instead of spending a round trip on a 404
			// that explains nothing. The credential is still proven before any
			// request, and a principal actor's genuine 404 — a network it is
			// not a member of — is surfaced as the server's own answer.
			c, err := newPrincipalCLI("", actor)
			if err != nil {
				return err
			}
			netID, label, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			var sub v2Subscription
			if err := c.post("/api/v1/networks/"+netID+"/subscriptions",
				map[string]any{"eventPattern": args[0]}, &sub); err != nil {
				return err
			}
			if jsonOut {
				return printJSON(sub)
			}
			fmt.Printf("subscription: %s  pattern %q  network %s\n", sub.sID(), args[0], label)
			fmt.Println("match the pattern to receive wake triggers: pagnet event watch --type " + args[0])
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	actor.register(cmd)
	return cmd
}

func subscriptionsCmd() *cobra.Command {
	var network string
	var actor principalActorOptions
	cmd := &cobra.Command{
		Use:   "subscriptions",
		Short: "List the event subscriptions your agent or service holds in this network (needs its endpoint credential)",
		Long: `List the event subscriptions the calling agent or service owns in this network.

Subscriptions are the subscriber's own surface: the control plane answers a
signed-in user 404 (anti-enumeration — the SDK is the subscription manager), so
this command is acted on by the agent or service itself and needs its endpoint
credential:

  pagnet subscriptions --credential ` + tokenPrefixEndpoint + `...
  pagnet subscriptions --as <agent-or-service-id>

With no flag the credential comes from $` + sdk.EnvCredential + `, then from the endpoint credential
already stored on this host. pagnet service credential create <service> (or
pagnet agent credential create <agent>) prints one once.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// There is no user-bearer path here to fall back on: a human actor
			// is answered 404 by design, so the CLI says so locally (naming the
			// credential that works) instead of spending a round trip on a 404
			// that explains nothing. The credential is still proven before any
			// request, and a principal actor's genuine 404 — a network it is
			// not a member of — is surfaced as the server's own answer.
			c, err := newPrincipalCLI("", actor)
			if err != nil {
				return err
			}
			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			var subs []v2Subscription
			if err := c.get("/api/v1/networks/"+netID+"/subscriptions", &subs); err != nil {
				return err
			}
			if jsonOut {
				return printJSON(subs)
			}
			if len(subs) == 0 {
				fmt.Println("no subscriptions for this agent or service in this network")
				return nil
			}
			rows := make([][]string, 0, len(subs))
			for _, s := range subs {
				rows = append(rows, []string{s.sID(), s.Pattern, orDash(s.Mode)})
			}
			printTable([]string{"ID", "PATTERN", "MODE"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	actor.register(cmd)
	return cmd
}

func unsubscribeCmd() *cobra.Command {
	var network string
	var actor principalActorOptions
	cmd := &cobra.Command{
		Use:   "unsubscribe <subscription-id>",
		Short: "Cancel an event subscription (needs the agent's or service's endpoint credential)",
		Long: `Cancel one of the calling agent or service's event subscriptions.

Subscriptions are the subscriber's own surface: the control plane answers a
signed-in user 404 (anti-enumeration — the SDK is the subscription manager), so
this command is acted on by the agent or service itself and needs its endpoint
credential:

  pagnet unsubscribe <subscription-id> --credential ` + tokenPrefixEndpoint + `...
  pagnet unsubscribe <subscription-id> --as <agent-or-service-id>

With no flag the credential comes from $` + sdk.EnvCredential + `, then from the endpoint credential
already stored on this host. pagnet service credential create <service> (or
pagnet agent credential create <agent>) prints one once.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// There is no user-bearer path here to fall back on: a human actor
			// is answered 404 by design, so the CLI says so locally (naming the
			// credential that works) instead of spending a round trip on a 404
			// that explains nothing. The credential is still proven before any
			// request, and a principal actor's genuine 404 — a network it is
			// not a member of — is surfaced as the server's own answer.
			c, err := newPrincipalCLI("", actor)
			if err != nil {
				return err
			}
			netID, label, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			if err := c.del("/api/v1/networks/" + netID + "/subscriptions/" + args[0]); err != nil {
				return err
			}
			if !jsonOut {
				fmt.Printf("subscription %s cancelled (network %s)\n", args[0], label)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	actor.register(cmd)
	return cmd
}

// --- pagnet network members (add/invite/revoke) --------------------------------

// networkMembersCmd implements `pagnet network members` (+ add/invite/revoke):
// the network's participant membership (agents + services) and the D2
// membership operations.
func networkMembersCmd() *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:   "members",
		Short: "List and manage the network's members (agents + services)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMembersList(network)
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	cmd.AddCommand(membersAddCmd(), membersInviteCmd(), membersRevokeCmd())
	return cmd
}

func runMembersList(network string) error {
	c, err := newCLI("")
	if err != nil {
		return err
	}
	netID, label, err := c.resolveNetwork(network)
	if err != nil {
		return err
	}
	all, err := c.fetchParticipants(netID)
	if err != nil {
		return err
	}
	if jsonOut {
		return printJSON(all)
	}
	if len(all) == 0 {
		fmt.Printf("no members in network %s yet\n", label)
		return nil
	}
	rows := make([][]string, 0, len(all))
	for _, p := range all {
		rows = append(rows, participantRow(p))
	}
	printTable(participantHeaders, rows)
	return nil
}

func newMembersParentCmd(short, use string, run func(cmd *cobra.Command, args []string, perms []string) error) *cobra.Command {
	var (
		network string
		perms   []string
	)
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, p := range perms {
				if err := validPermission(p); err != nil {
					return err
				}
			}
			return run(cmd, args, perms)
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network (default: the saved/only network)")
	cmd.Flags().StringSliceVar(&perms, "permission", nil, "permission to grant (repeatable: discover|communicate|invoke|event_publish|event_subscribe|task_read|task_write|operate)")
	return cmd
}

func membersAddCmd() *cobra.Command {
	return newMembersParentCmd("Add a participant to the network (admin, immediate)",
		"add <agent-or-service>", func(cmd *cobra.Command, args []string, perms []string) error {
			network, _ := cmd.Flags().GetString("network")
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, label, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			p, err := c.resolveParticipant(netID, args[0])
			if err != nil {
				return err
			}
			// Set the membership to active with the given permissions
			// (idempotent upsert: adds the participant when not a member yet,
			// updates the permissions when already one). The server returns
			// the resulting membership (PascalCase domain fields).
			body := map[string]any{"permissions": perms}
			var m struct {
				State       string   `json:"State"`
				Permissions []string `json:"Permissions"`
			}
			if err := c.do(http.MethodPut, "/api/v1/networks/"+netID+"/members/"+p.pID(), body, &m); err != nil {
				return err
			}
			if jsonOut {
				return printJSON(map[string]any{"added": p.pName(), "network": netID, "state": m.State, "permissions": m.Permissions})
			}
			fmt.Printf("%s added to network %s", p.pName(), label)
			if len(perms) > 0 {
				fmt.Printf("  permissions: %s", strings.Join(perms, ", "))
			}
			fmt.Println()
			return nil
		})
}

func membersInviteCmd() *cobra.Command {
	return newMembersParentCmd("Invite a participant (accepted from their side)",
		"invite <agent-or-service>", func(cmd *cobra.Command, args []string, perms []string) error {
			network, _ := cmd.Flags().GetString("network")
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, label, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			p, err := c.resolveParticipant(netID, args[0])
			if err != nil {
				return err
			}
			body := map[string]any{"principalId": p.pID()}
			if len(perms) > 0 {
				body["permissions"] = perms
			}
			var inv struct {
				ID       string `json:"id"`
				IDLegacy string `json:"ID"`
			}
			if err := c.post("/api/v1/networks/"+netID+"/invitations", body, &inv); err != nil {
				return err
			}
			id := inv.ID
			if id == "" {
				id = inv.IDLegacy
			}
			if jsonOut {
				return printJSON(map[string]any{"invitation": id, "participant": p.pName(), "network": netID, "permissions": perms})
			}
			fmt.Printf("invitation %s sent to %s for network %s (pending their acceptance)\n", id, p.pName(), label)
			return nil
		})
}

func membersRevokeCmd() *cobra.Command {
	return newMembersParentCmd("Revoke a participant's membership (immediate)",
		"revoke <agent-or-service>", func(cmd *cobra.Command, args []string, _ []string) error {
			network, _ := cmd.Flags().GetString("network")
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, label, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			p, err := c.resolveParticipant(netID, args[0])
			if err != nil {
				return err
			}
			if err := c.post("/api/v1/networks/"+netID+"/members/"+p.pID()+"/revoke", map[string]any{}, nil); err != nil {
				return err
			}
			if jsonOut {
				return printJSON(map[string]any{"revoked": p.pName(), "network": netID})
			}
			fmt.Printf("%s revoked from network %s\n", p.pName(), label)
			return nil
		})
}

// --- shared output helpers ------------------------------------------------------

// printJSON emits machine-readable JSON (the --json flag contract).
func printJSON(v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// urlQueryEscape escapes a query component for a hand-built query string.
func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}
