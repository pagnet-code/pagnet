package main

// `pagnet recipe apply <path-or-url>` (plan D10 / D12 / D13): import a
// declarative recipe manifest (pagnet.dev/v1 YAML) — a service, an agent
// template, or a recipe — as normal API calls. Interactive runs show a
// summary and confirm; --non-interactive applies deterministically and
// fails fast when any input is missing (never prompts, never waits).

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/pagnet-code/pagnet/internal/netpolicy"
)

// recipeManifest is the pagnet.dev/v1 manifest (D13 — small on purpose).
type recipeManifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"` // Recipe | Service | AgentTemplate
	Metadata   struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	} `yaml:"metadata"`
	// Capabilities are the offered verbs (the capability set is DATA —
	// discovered via search, called via invoke; there is no per-capability
	// code path).
	Capabilities []struct {
		ID           string   `yaml:"id"`
		Version      int      `yaml:"version"`
		Description  string   `yaml:"description"`
		InputSchema  any      `yaml:"inputSchema,omitempty"`
		OutputSchema any      `yaml:"outputSchema,omitempty"`
		Tags         []string `yaml:"tags,omitempty"`
	} `yaml:"capabilities"`
	Subscriptions []struct {
		Event string `yaml:"event"`
		Mode  string `yaml:"mode"`
	} `yaml:"subscriptions"`
	Permissions struct {
		Requested []string `yaml:"requested"`
	} `yaml:"permissions"`
}

// recipeCmd implements `pagnet recipe apply` (the apply subcommand is the
// only verb; the group keeps room for future recipe commands).
func recipeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recipe",
		Short: "Apply declarative network recipes (pagnet.dev/v1 manifests)",
	}
	var network string
	apply := &cobra.Command{
		Use:   "apply <path-or-url>",
		Short: "Apply a recipe manifest (create the participant + subscriptions)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := readRecipeSource(args[0])
			if err != nil {
				return err
			}
			m, err := parseRecipe(raw)
			if err != nil {
				return err
			}
			c, err := newCLI("")
			if err != nil {
				return err
			}
			// The network is required: fail fast (and BEFORE the
			// confirmation prompt) when it cannot be resolved.
			netID, label, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}

			summary := recipeSummary(m, label)
			if interactiveMode() {
				ok, err := confirmApplyFn(summary)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("apply cancelled (nothing was created)")
				}
			} else if !silent {
				fmt.Println(summary)
			}

			created, err := applyRecipe(c, netID, m)
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(created)
			}
			fmt.Printf("applied %s %q to network %s\n", m.Kind, m.Metadata.Name, label)
			if len(m.Capabilities) > 0 {
				fmt.Printf("capabilities: %s\n", capabilityIDList(m))
			}
			for _, s := range m.Subscriptions {
				fmt.Printf("subscription: %s (mode %s)\n", s.Event, orDash(s.Mode))
			}
			if created.ActivationCredential != "" {
				// The one-time rule: printed ONCE here, never stored.
				fmt.Printf("\nactivation credential (one-time — save it now, it is shown only once):\n  %s\n", created.ActivationCredential)
			}
			return nil
		},
	}
	apply.Flags().StringVarP(&network, "network", "n", "", "network to apply the recipe to (default: the saved/only network)")
	cmd.AddCommand(apply)
	return cmd
}

// confirmApplyFn asks for confirmation (interactive only); overridable in
// tests.
var confirmApplyFn = func(summary string) (bool, error) {
	fmt.Println(summary)
	line, err := askLineFn("Apply this recipe? [y/N] ")
	if err != nil {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}

func recipeSummary(m *recipeManifest, network string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "recipe %s %q\n", m.Kind, m.Metadata.Name)
	if m.Metadata.Description != "" {
		fmt.Fprintf(&b, "  %s\n", m.Metadata.Description)
	}
	fmt.Fprintf(&b, "network: %s\n", network)
	if len(m.Capabilities) > 0 {
		ids := make([]string, 0, len(m.Capabilities))
		for _, cp := range m.Capabilities {
			ids = append(ids, cp.ID)
		}
		fmt.Fprintf(&b, "capabilities: %s\n", strings.Join(ids, ", "))
	}
	if len(m.Subscriptions) > 0 {
		pats := make([]string, 0, len(m.Subscriptions))
		for _, s := range m.Subscriptions {
			pats = append(pats, s.Event)
		}
		fmt.Fprintf(&b, "subscriptions: %s\n", strings.Join(pats, ", "))
	}
	if len(m.Permissions.Requested) > 0 {
		fmt.Fprintf(&b, "requested permissions: %s\n", strings.Join(m.Permissions.Requested, ", "))
	}
	return b.String()
}

func capabilityIDList(m *recipeManifest) string {
	ids := make([]string, 0, len(m.Capabilities))
	for _, cp := range m.Capabilities {
		ids = append(ids, cp.ID)
	}
	return strings.Join(ids, ", ")
}

// readRecipeSource reads the manifest from a file path or an http(s) URL.
func readRecipeSource(src string) ([]byte, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		if err := netpolicy.Check(src, insecureRemoteHTTP); err != nil {
			return nil, err
		}
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(src)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch recipe: http %d for %s", resp.StatusCode, src)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	}
	return os.ReadFile(src)
}

// parseRecipe validates the manifest (fail fast on any structural problem —
// an invalid manifest never half-applies).
func parseRecipe(raw []byte) (*recipeManifest, error) {
	var m recipeManifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("recipe is not valid YAML: %v", err)
	}
	if m.APIVersion != "pagnet.dev/v1" {
		return nil, fmt.Errorf("unsupported apiVersion %q (want pagnet.dev/v1)", m.APIVersion)
	}
	switch m.Kind {
	case "Recipe", "Service", "AgentTemplate":
	default:
		return nil, fmt.Errorf("unsupported kind %q (want Recipe | Service | AgentTemplate)", m.Kind)
	}
	if m.Metadata.Name == "" {
		return nil, fmt.Errorf("recipe metadata.name is required")
	}
	for i, cp := range m.Capabilities {
		if cp.ID == "" {
			return nil, fmt.Errorf("capabilities[%d].id is required", i)
		}
		if !strings.Contains(cp.ID, ".") {
			return nil, fmt.Errorf("capability ids are dot-separated (e.g. documents.extract); got %q", cp.ID)
		}
		if v := cp.Version; v == 0 {
			m.Capabilities[i].Version = 1
		}
	}
	for i, s := range m.Subscriptions {
		if s.Event == "" {
			return nil, fmt.Errorf("subscriptions[%d].event is required", i)
		}
	}
	for _, p := range m.Permissions.Requested {
		if err := validPermission(p); err != nil {
			return nil, err
		}
	}
	return &m, nil
}

// recipeApplied is what applyRecipe created (the --json output).
type recipeApplied struct {
	Kind                 string   `json:"kind"`
	Name                 string   `json:"name"`
	ID                   string   `json:"id,omitempty"`
	Network              string   `json:"network"`
	Subscriptions        []string `json:"subscriptions,omitempty"`
	ActivationCredential string   `json:"activationCredential,omitempty"`
}

// applyRecipe turns the manifest into normal API calls (D12: declarative →
// normal API calls).
func applyRecipe(c *cliCtx, netID string, m *recipeManifest) (*recipeApplied, error) {
	out := &recipeApplied{Kind: m.Kind, Name: m.Metadata.Name, Network: netID}

	caps := make([]map[string]any, 0, len(m.Capabilities))
	for _, cp := range m.Capabilities {
		entry := map[string]any{"id": cp.ID, "version": cp.Version}
		if cp.Description != "" {
			entry["description"] = cp.Description
		}
		if cp.InputSchema != nil {
			entry["inputSchema"] = cp.InputSchema
		}
		if cp.OutputSchema != nil {
			entry["outputSchema"] = cp.OutputSchema
		}
		if len(cp.Tags) > 0 {
			entry["tags"] = cp.Tags
		}
		caps = append(caps, entry)
	}

	switch m.Kind {
	case "AgentTemplate":
		body := map[string]any{"name": m.Metadata.Name}
		if m.Metadata.Description != "" {
			body["description"] = m.Metadata.Description
		}
		if len(caps) > 0 {
			body["capabilities"] = caps
		}
		var created struct {
			ID       string `json:"id"`
			IDLegacy string `json:"ID"`
		}
		if err := c.post("/api/v1/networks/"+netID+"/agents", body, &created); err != nil {
			return nil, fmt.Errorf("create agent: %w", err)
		}
		if created.ID != "" {
			out.ID = created.ID
		} else {
			out.ID = created.IDLegacy
		}
	default: // Recipe | Service: a service participant.
		body := map[string]any{"name": m.Metadata.Name}
		if m.Metadata.Description != "" {
			body["description"] = m.Metadata.Description
		}
		if len(caps) > 0 {
			body["capabilities"] = caps
		}
		var created struct {
			ID                   string `json:"id"`
			IDLegacy             string `json:"ID"`
			ActivationCredential string `json:"activationCredential"`
		}
		if err := c.post("/api/v1/services", body, &created); err != nil {
			return nil, fmt.Errorf("create service: %w", err)
		}
		id := created.ID
		if id == "" {
			id = created.IDLegacy
		}
		out.ID = id
		out.ActivationCredential = created.ActivationCredential
		if err := c.post("/api/v1/networks/"+netID+"/services", map[string]any{"principalId": id}, nil); err != nil {
			return nil, fmt.Errorf("add service to network: %w", err)
		}
	}

	// Subscriptions (the participant's event patterns).
	for _, s := range m.Subscriptions {
		body := map[string]any{"eventPattern": s.Event}
		if s.Mode != "" {
			body["mode"] = s.Mode
		}
		if err := c.post("/api/v1/networks/"+netID+"/subscriptions", body, nil); err != nil {
			return nil, fmt.Errorf("subscribe %s: %w", s.Event, err)
		}
		out.Subscriptions = append(out.Subscriptions, s.Event)
	}
	return out, nil
}
