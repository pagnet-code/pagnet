package main

// Principal credentials (plan §9 / spec §28-29): `pagnet agent credential
// create|list|revoke <agent>` and the same trio under `pagnet service`.
//
// A principal credential is the durable endpoint credential (pgn_epd_) that
// the Go SDK presents on connect — a manually created credential is the SAME
// class as the one the activation exchange produces, only restricted.
// Restrictions only ever REDUCE what the principal may do: the network
// membership stays the ceiling (spec §16/§19), and an empty restriction list
// means "whatever the membership already allows", not "nothing".
//
// Terminology (plan D10 / spec §14): the product says agent / service — never
// "principal" — and managing a credential is secondary to "connect".
//
// Path ids follow each product surface's own addressing (server 1052f65):
// {agentID} is the agent DEFINITION id, {serviceID} is the service's
// PRINCIPAL id. The network membership view already returns exactly those ids
// (/networks/{id}/agents yields agent DEFINITIONS, /networks/{id}/services
// yields principals), so resolving a name through it lands in the right id
// space for each surface automatically.

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/pagnet-code/pagnet/domain"
)

// principalKind is the CLI-facing principal class. The REST resource path is
// the same word (spec §14: there is no /principals product route).
type principalKind string

const (
	principalAgent   principalKind = "agent"
	principalService principalKind = "service"
)

// restResource is the plural REST resource a class is addressed by
// (/api/v1/agents/{id}/credentials, /api/v1/services/{id}/credentials).
func (k principalKind) restResource() string { return string(k) + "s" }

// credentialCollection is the credential endpoint for one principal id. The
// id space is whatever that surface addresses (definition id for agents,
// principal id for services).
func credentialCollection(kind principalKind, id string) string {
	return "/api/v1/" + kind.restResource() + "/" + id + "/credentials"
}

// maxCredentialNameLen mirrors the server's create validation (a longer name
// is a 400 there; failing locally names the field before any round-trip).
const maxCredentialNameLen = 64

// v2Credential is one principal credential exactly as the control plane's
// management view renders it (principalCredentialView, server 1052f65):
// camelCase, with empty restriction lists serialized as [].
//
// Credential is the plaintext, which the server sets on the CREATE response
// only — a list can never carry it, because only the keyed verifier is
// stored. It lives in this one shape rather than a separate type so a list
// can never accidentally render a secret column the server did not send.
type v2Credential struct {
	ID           string   `json:"id,omitempty"`
	Name         string   `json:"name,omitempty"`
	Kind         string   `json:"kind,omitempty"`
	CreatedAt    string   `json:"createdAt,omitempty"`
	LastUsedAt   string   `json:"lastUsedAt,omitempty"`
	ExpiresAt    string   `json:"expiresAt,omitempty"`
	RevokedAt    string   `json:"revokedAt,omitempty"`
	NetworkIDs   []string `json:"networkIds"`
	Permissions  []string `json:"permissions"`
	Capabilities []string `json:"capabilities"`

	Credential string `json:"credential,omitempty"`
}

// state renders the credential's lifecycle state from its own metadata. An
// unparseable expiry is reported as NOT expired: the server is the authority
// on its own rows and the CLI never invents a state it cannot read.
func (v v2Credential) state() string {
	if v.RevokedAt != "" {
		return "revoked"
	}
	if v.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, v.ExpiresAt); err == nil && !time.Now().Before(t) {
			return "expired"
		}
	}
	return "active"
}

// restriction renders a restriction list the way the human surface says it: an
// empty allowlist is "everything the membership already allows".
func restriction(list []string) string {
	if len(list) == 0 {
		return "all"
	}
	return strings.Join(list, ", ")
}

func credentialRow(v v2Credential) []string {
	return []string{
		orDash(v.Name),
		restriction(v.NetworkIDs),
		restriction(v.Permissions),
		restriction(v.Capabilities),
		orDash(v.LastUsedAt),
		orDash(v.ExpiresAt),
		v.state(),
		v.ID,
	}
}

var credentialHeaders = []string{"NAME", "NETWORKS", "ACCESS", "CAPABILITIES", "LAST USED", "EXPIRES", "STATE", "ID"}

// --- principal resolution ---------------------------------------------------

// principalRef is a resolved agent or service, carrying the id its own product
// surface is addressed by.
type principalRef struct {
	Kind principalKind
	// ID is the definition id for an agent and the principal id for a service
	// — exactly what /agents/{id}/credentials and /services/{id}/credentials
	// expect.
	ID   string
	Name string
}

func (p principalRef) credentials() string { return credentialCollection(p.Kind, p.ID) }

// The credential surface speaks the same REST as everything else, with one
// extra contract: it is USER-only, so an agent/service credential presented
// here answers 403 user_identity_required (server 1052f65). That is an
// authorization failure on a perfectly valid credential, and its JSON body
// would read like a broken CLI — so every call on this surface goes through
// the credential failure translation (plan §7). Unrelated failures (404
// not_found for a wrong-kind or foreign id, 400 validation) keep the
// server's own message.
func (c *cliCtx) credGet(path string, out any) error { return c.authError(c.get(path, out)) }

func (c *cliCtx) credPost(path string, body, out any) error {
	return c.authError(c.post(path, body, out))
}

func (c *cliCtx) credDel(path string) error { return c.authError(c.del(path)) }

// resolvePrincipalRef resolves an <agent|service-id-or-name> argument to a
// principal of the expected kind, in that surface's id space.
//
// Names are looked up across the networks the caller can see, because the
// control plane has no tenant-wide principal list (spec §14). An unknown or
// ambiguous name fails with the concrete ids to choose from — never a silent
// guess. A bare id is verified through /principals/{id} where that endpoint
// can answer for the surface: services ARE principals, while an agent id is a
// DEFINITION id that /principals does not know, so it is passed through and
// the control plane decides (it is the authority on its own rows, and a
// wrong-kind or foreign id is a 404 there).
func (c *cliCtx) resolvePrincipalRef(kind principalKind, arg string) (principalRef, error) {
	var (
		matches   []principalRef
		readFails int
	)
	var nets []struct {
		ID string `json:"ID"`
	}
	if err := c.get("/api/v1/networks", &nets); err != nil {
		return principalRef{}, err
	}
	for _, n := range nets {
		all, err := c.fetchParticipants(n.ID)
		if err != nil {
			// A network whose membership cannot be read is skipped (the same
			// tolerance resourceKeys applies) but counted, so a "not found"
			// answer can say it may be incomplete.
			readFails++
			continue
		}
		for _, p := range all {
			if !kindIs(kind, p.pKind()) || (p.pID() != arg && p.pName() != arg) {
				continue
			}
			dup := false
			for _, m := range matches {
				if m.ID == p.pID() {
					dup = true
					break
				}
			}
			if !dup {
				matches = append(matches, principalRef{Kind: kind, ID: p.pID(), Name: p.pName()})
			}
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
	default:
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, m.ID)
		}
		return principalRef{}, fmt.Errorf("%d %ss are named %q — pass the id instead: %s",
			len(matches), kind, arg, strings.Join(ids, ", "))
	}

	// Nothing in the visible memberships. An id may still name a principal
	// that has not joined a network yet (`pagnet service create` creates
	// tenant-wide and joins one only with --network).
	if _, err := domain.ParseID(arg); err == nil {
		if kind == principalService {
			// GET /principals/{id} answers {"principal": {...}} with the
			// domain struct's exported field names.
			var det struct {
				Principal struct {
					ID   string `json:"ID"`
					Kind string `json:"Kind"`
					Name string `json:"Name"`
				} `json:"principal"`
			}
			// The error is returned unwrapped: when it is a translated
			// credential failure, prefixing it with a path would mangle the
			// product sentence.
			if err := c.credGet("/api/v1/principals/"+arg, &det); err != nil {
				return principalRef{}, err
			}
			if det.Principal.ID == "" {
				return principalRef{}, fmt.Errorf("service %q not found", arg)
			}
			if det.Principal.Kind != string(principalService) {
				return principalRef{}, fmt.Errorf("%q is a %s, but `pagnet service credential` manages services",
					arg, orDash(det.Principal.Kind))
			}
			return principalRef{Kind: kind, ID: det.Principal.ID, Name: det.Principal.Name}, nil
		}
		// An agent definition id: no tenant-wide lookup exists, so the
		// control plane decides (a wrong-kind or foreign id is a 404 there).
		return principalRef{Kind: kind, ID: arg}, nil
	}

	// The answer names the alternative, not just the dead end: every caller
	// arrived here with a string that is neither a visible name nor a usable
	// id, so "pass the id" is always the next move.
	if readFails > 0 {
		return principalRef{}, fmt.Errorf("no %s named %q is visible to you (%d network(s) could not be read) — pass the %s id instead",
			kind, arg, readFails, kind)
	}
	return principalRef{}, fmt.Errorf("no %s named %q is visible to you — pass the %s id instead", kind, arg, kind)
}

// kindIs reports whether a wire kind is the CLI class. The V2 surface labels
// services "service"; everything else in the participant view is an agent
// (the same classification `pagnet agents` applies).
func kindIs(want principalKind, got string) bool {
	if want == principalService {
		return got == string(principalService)
	}
	return got != string(principalService)
}

// --- command tree -----------------------------------------------------------

// agentCmd groups the per-agent subcommands. The plural `pagnet agents` is the
// network listing; this is the single-agent surface (plan §9).
func agentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage one agent (its credentials)",
	}
	cmd.AddCommand(credentialParentCmd(principalAgent))
	return cmd
}

// credentialParentCmd is the `credential` group under `agent` / `service`.
func credentialParentCmd(kind principalKind) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "credential",
		Aliases: []string{"credentials"},
		Short:   fmt.Sprintf("Create, list, and revoke %s credentials", kind),
	}
	cmd.AddCommand(
		credentialCreateCmd(kind),
		credentialListCmd(kind),
		credentialRevokeCmd(kind),
	)
	return cmd
}

// --- credential create --------------------------------------------------------

// credentialCreateCmd implements `credential create <agent|service>`.
//
// Interactive: it asks only what the flags did not supply, with defaults that
// work (an unrestricted credential that never expires). Automation: every
// answer is a flag and nothing prompts.
func credentialCreateCmd(kind principalKind) *cobra.Command {
	var (
		name     string
		networks []string
		allow    []string
		caps     []string
		expires  string
	)
	cmd := &cobra.Command{
		Use:   "create <" + string(kind) + "-id-or-name>",
		Short: fmt.Sprintf("Create a credential for a %s (prints the secret once)", kind),
		Long: `Create a credential the ` + string(kind) + ` can authenticate with.

The credential is the durable endpoint credential the Go SDK presents
(pgn_epd_...). Restrictions only ever NARROW what the ` + string(kind) + ` may
do — the network membership stays the ceiling, and leaving a restriction empty
means "whatever the membership already allows".

Automation:
  pagnet ` + string(kind) + ` credential create ` + string(kind) + `name \
    --network prod --allow discover,invoke --capability docs.extract \
    --expires 30d --non-interactive --json

The secret is shown exactly once. The CLI never stores it, and ` + "`list`" + `
can never return it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			p, err := c.resolvePrincipalRef(kind, args[0])
			if err != nil {
				return err
			}

			// Ask only for what the flags did not answer.
			if name == "" {
				def := credentialNameDefault(p.Name)
				name, err = promptCredentialField(fmt.Sprintf("credential name [%s]: ", def), def, interactiveMode())
				if err != nil {
					return err
				}
			}
			if len(name) > maxCredentialNameLen {
				return fmt.Errorf("credential name is %d characters, the maximum is %d", len(name), maxCredentialNameLen)
			}
			if len(networks) == 0 {
				networks, err = promptCredentialList(
					fmt.Sprintf("allowed networks (comma-separated; blank = every network this %s belongs to): ", kind),
					interactiveMode())
				if err != nil {
					return err
				}
			}
			if len(allow) == 0 {
				allow, err = promptCredentialList(
					"access (comma-separated: "+permissionVocabulary+"; blank = the membership's own permissions): ",
					interactiveMode())
				if err != nil {
					return err
				}
			}
			// The vocabulary is checked whatever produced the list: a flag
			// value is as capable of a typo as a typed one, and the
			// automation path must not reach the server with a permission the
			// gate does not know.
			for _, perm := range allow {
				if err := validPermission(perm); err != nil {
					return err
				}
			}
			if len(caps) == 0 {
				caps, err = promptCredentialList(
					"capability allowlist for outbound calls (comma-separated; blank = no capability restriction): ",
					interactiveMode())
				if err != nil {
					return err
				}
			}
			if expires == "" {
				expires, err = promptCredentialField("expires (never | 30d | 2026-10-01T00:00:00Z) [never]: ",
					"never", interactiveMode())
				if err != nil {
					return err
				}
			}

			// Names → ids, so the automation path can say "prod".
			netIDs := make([]string, 0, len(networks))
			for _, n := range networks {
				id, _, err := c.resolveNetwork(n)
				if err != nil {
					return err
				}
				netIDs = append(netIDs, id)
			}
			expiresAt, err := parseExpiry(expires)
			if err != nil {
				return err
			}

			body := map[string]any{"name": name}
			if len(netIDs) > 0 {
				body["networkIds"] = netIDs
			}
			if len(allow) > 0 {
				body["permissions"] = allow
			}
			if len(caps) > 0 {
				body["capabilities"] = caps
			}
			if expiresAt != "" {
				body["expiresAt"] = expiresAt
			}

			// The create response is ONE flat object: the metadata view with
			// the plaintext in its "credential" field — the only response that
			// ever carries it.
			var created v2Credential
			if err := c.credPost(p.credentials(), body, &created); err != nil {
				return err
			}
			if created.Credential == "" {
				// The server created a row whose secret it did not return: the
				// operator holds an unusable credential. Say so — do not print
				// an empty line as if it were a secret.
				return errors.New("the server created the credential but returned no secret (create it again to obtain one)")
			}
			if jsonOut {
				// The raw secret appears ONLY on a successful create.
				return printJSON(created)
			}
			if !silent {
				fmt.Printf("credential:   %s (%s)\n", orDash(created.Name), created.ID)
				fmt.Printf("%s:       %s\n", kind, orDash(p.Name))
				fmt.Printf("networks:     %s\n", restriction(created.NetworkIDs))
				fmt.Printf("access:       %s\n", restriction(created.Permissions))
				fmt.Printf("capabilities: %s\n", restriction(created.Capabilities))
				fmt.Printf("expires:      %s\n", orDash(created.ExpiresAt))
			}
			// --silent still prints the secret: it is the only copy, and a
			// machine-output mode must not discard it (spec §29).
			fmt.Printf("\n%s\n\n", created.Credential)
			fmt.Println("Shown once. Keep it private.")
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "credential name (default: prompted, or <"+string(kind)+">-credential)")
	cmd.Flags().StringSliceVarP(&networks, "network", "n", nil, "restrict to these networks (comma-separated; default: every network the "+string(kind)+" belongs to)")
	cmd.Flags().StringSliceVar(&allow, "allow", nil, "permissions to grant (comma-separated: "+permissionVocabulary+"; default: the membership's own)")
	cmd.Flags().StringSliceVar(&caps, "capability", nil, "outbound capability allowlist (comma-separated; default: unrestricted)")
	cmd.Flags().StringVar(&expires, "expires", "", "expiry (never | 30d | 12h | RFC3339 timestamp; default: never)")
	return cmd
}

// credentialNameDefault derives a name when neither a flag nor a human did.
func credentialNameDefault(principalName string) string {
	if principalName == "" {
		return "credential"
	}
	return principalName + "-credential"
}

// permissionVocabulary is the CLI's one rendering of the permission set (the
// values domain.NetworkPermission accepts and validPermission checks).
const permissionVocabulary = "discover,communicate,invoke,event_publish,event_subscribe,task_read,task_write,operate"

// promptCredentialField asks one question with a default. Non-interactive runs
// return the default (the automation contract: never prompt, never hang).
func promptCredentialField(prompt, def string, interactive bool) (string, error) {
	if !interactive {
		return def, nil
	}
	line, err := askLineFn(prompt)
	if err != nil {
		return "", err
	}
	if line == "" {
		return def, nil
	}
	return line, nil
}

// promptCredentialList asks one comma-separated list question (the repo's list
// flag convention, mirrored in the prompt). Blank = no restriction.
func promptCredentialList(prompt string, interactive bool) ([]string, error) {
	if !interactive {
		return nil, nil
	}
	line, err := askLineFn(prompt)
	if err != nil {
		return nil, err
	}
	return splitList(line), nil
}

// splitList splits a comma-separated answer into trimmed, non-empty items.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// relativeExpiryPattern is a "--expires 30d" style value: a count and a unit.
var relativeExpiryPattern = regexp.MustCompile(`^([0-9]+)([smhdw])$`)

// parseExpiry turns the --expires value into an RFC3339 UTC timestamp. "" and
// "never" mean no expiry; "30d"/"12h" are relative to now; anything else must
// be an RFC3339 timestamp the server can read.
func parseExpiry(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "never") {
		return "", nil
	}
	if m := relativeExpiryPattern.FindStringSubmatch(v); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return "", fmt.Errorf("invalid --expires %q: %v", v, err)
		}
		var unit time.Duration
		switch m[2] {
		case "s":
			unit = time.Second
		case "m":
			unit = time.Minute
		case "h":
			unit = time.Hour
		case "d":
			unit = 24 * time.Hour
		case "w":
			unit = 7 * 24 * time.Hour
		}
		return time.Now().UTC().Add(time.Duration(n) * unit).Format(time.RFC3339), nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("invalid --expires %q (want never, a relative duration like 30d/12h, or an RFC3339 timestamp)", v)
}

// --- credential list ----------------------------------------------------------

func credentialListCmd(kind principalKind) *cobra.Command {
	return &cobra.Command{
		Use:   "list <" + string(kind) + "-id-or-name>",
		Short: fmt.Sprintf("List a %s's credentials (metadata only — never the secret)", kind),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			p, err := c.resolvePrincipalRef(kind, args[0])
			if err != nil {
				return err
			}
			var creds []v2Credential
			if err := c.credGet(p.credentials(), &creds); err != nil {
				return err
			}
			if jsonOut {
				return printJSON(creds)
			}
			if len(creds) == 0 {
				fmt.Printf("no credentials for %s %s\n", kind, orDash(p.Name))
				return nil
			}
			rows := make([][]string, 0, len(creds))
			for _, cr := range creds {
				rows = append(rows, credentialRow(cr))
			}
			printTable(credentialHeaders, rows)
			return nil
		},
	}
}

// --- credential revoke --------------------------------------------------------

func credentialRevokeCmd(kind principalKind) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <" + string(kind) + "-id-or-name> <credential-id-or-name>",
		Short: fmt.Sprintf("Revoke one %s credential (immediate)", kind),
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			p, err := c.resolvePrincipalRef(kind, args[0])
			if err != nil {
				return err
			}
			id, name, err := c.resolveCredential(p, args[1])
			if err != nil {
				return err
			}
			if err := c.credDel(p.credentials() + "/" + id); err != nil {
				return err
			}
			if jsonOut {
				return printJSON(map[string]any{"revoked": id, "name": name, "kind": kind, "principal": p.ID})
			}
			fmt.Printf("credential %s (%s) revoked — it stops working immediately\n", name, id)
			return nil
		},
	}
}

// resolveCredential resolves a credential id or name within one principal. A
// name must match exactly one credential; ambiguity fails with the ids.
func (c *cliCtx) resolveCredential(p principalRef, idOrName string) (id, name string, err error) {
	var creds []v2Credential
	if err := c.credGet(p.credentials(), &creds); err != nil {
		return "", "", err
	}
	var matches []v2Credential
	for _, cr := range creds {
		if cr.ID == idOrName || cr.Name == idOrName {
			matches = append(matches, cr)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].ID, matches[0].Name, nil
	case 0:
		return "", "", fmt.Errorf("credential %q not found on %s %s", idOrName, p.Kind, orDash(p.Name))
	default:
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, m.ID)
		}
		return "", "", fmt.Errorf("%d credentials are named %q — pass the id instead: %s",
			len(matches), idOrName, strings.Join(ids, ", "))
	}
}
