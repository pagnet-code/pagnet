package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/pagnet-code/pagnet/fabric"
	adapter "github.com/pagnet-code/pagnet/fabric/adapters/a2a"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

// A2AServiceAddInput selects an exact interface from an operator-supplied card.
// Cards/addresses remain private profiles; only Name/Description are published.
// Setup neither fetches another card nor invokes the advertised agent.
type A2AServiceAddInput struct {
	URL                string          `json:"url"`
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	Card               json.RawMessage `json:"card"`
	CredentialSelector string          `json:"credentialSelector,omitempty"`
	AllowHTTP          bool            `json:"allowHttp,omitempty"`
	Cancellation       bool            `json:"cancellation,omitempty"`
}

func validateA2AServiceAdd(v *A2AServiceAddInput) (*sdk.AgentCard, sdk.AgentInterface, error) {
	var selected sdk.AgentInterface
	// Reuse address/name bounds, but version negotiation remains MCP-specific.
	common := ServiceAddInput{URL: v.URL, Name: v.Name, Description: v.Description, CredentialSelector: v.CredentialSelector, AllowHTTP: v.AllowHTTP}
	if e := validateServiceAdd(&common); e != nil {
		return nil, selected, e
	}
	v.Name, v.CredentialSelector, v.AllowHTTP = common.Name, common.CredentialSelector, common.AllowHTTP
	var card sdk.AgentCard
	if fabric.DecodeJSONWithLimits(v.Card, &card, fabric.WireLimits{MaxBytes: 24 << 10, MaxDepth: 32, MaxMembers: 2048}) != nil || strings.TrimSpace(card.Name) == "" || len(card.SupportedInterfaces) < 1 || len(card.SupportedInterfaces) > 32 {
		return nil, selected, fabric.NewError(fabric.CodeInvalidInput, "Provide a bounded A2A Agent Card with the exact selected interface")
	}
	found := false
	for _, candidate := range card.SupportedInterfaces {
		if candidate != nil && candidate.URL == v.URL && candidate.ProtocolBinding == sdk.TransportProtocolJSONRPC && candidate.ProtocolVersion == sdk.Version {
			if found {
				return nil, selected, fabric.NewError(fabric.CodeInvalidInput, "Agent Card repeats the selected interface")
			}
			selected, found = *candidate, true
		}
	}
	if !found {
		return nil, selected, fabric.NewError(fabric.CodeUnsupported, "Agent Card must advertise exactly the selected A2A JSON-RPC interface and supported version")
	}
	return &card, selected, nil
}

func (n *InstalledNode) a2aServiceAdd(ctx context.Context, access *fabricauth.OwnerAdministration, r fabricadmin.Request) (json.RawMessage, error) {
	if n == nil || n.Installation == nil || access == nil || r.Operation != "service.a2a.add" || r.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	if n.Runtime == nil || n.Services == nil || n.Publisher == nil {
		return nil, fabric.NewError(fabric.CodeUnsupported, "Initialize service support with pagnet init, then restart the local node")
	}
	var input A2AServiceAddInput
	if fabric.DecodeJSON(r.Input, &input) != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid A2A service setup")
	}
	decoder := json.NewDecoder(bytes.NewReader(r.Input))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Unsupported A2A service setup fields")
	}
	card, endpoint, e := validateA2AServiceAdd(&input)
	if e != nil {
		return nil, e
	}
	settings, e := LoadInstalledServiceSettings(ctx, n.Installation)
	if e != nil || settings == nil {
		return nil, localDenied()
	}
	if settings.ProviderSelector == "credentials.none" && input.CredentialSelector != "none" {
		return nil, fabric.NewError(fabric.CodeUnsupported, "This installation explicitly selects credential-free services only")
	}
	owner, e := n.Installation.Operator(ctx)
	if e != nil || access.PrincipalView() != owner.PrincipalView() {
		return nil, localDenied()
	}
	var out json.RawMessage
	e = n.Installation.WithCurrentOperator(ctx, owner, func(current context.Context) error {
		credentials, e := n.Services.config.Credentials.Resolve(current, input.CredentialSelector)
		if e != nil || credentials.BindingDigest == [32]byte{} {
			return fabric.NewError(fabric.CodeUnauthenticated, "The selected private service credential provider is unavailable")
		}
		profile := fabricservices.Profile{Protocol: "a2a.jsonrpc", Version: string(sdk.Version), CredentialSelector: input.CredentialSelector, BindingDigest: credentials.BindingDigest, A2A: &fabricservices.A2AProfile{Card: card, Interface: endpoint, AllowHTTP: input.AllowHTTP, Cancellation: input.Cancellation, Limits: adapter.Limits{MaxEventBytes: 1 << 20, MaxRequestBytes: 1 << 20, MaxStreamBytes: 64 << 20, Lifetime: 5 * time.Minute}}}
		if e = fabricservices.ValidateProfile(profile); e != nil {
			return fabric.NewError(fabric.CodeInvalidInput, "Selected A2A Agent Card/profile exceeds supported configuration bounds")
		}
		canonical, e := json.Marshal(struct {
			Protocol string
			Input    A2AServiceAddInput
			Account  [32]byte
			Provider string
		}{"a2a.jsonrpc", input, credentials.BindingDigest, settings.ProviderSelector})
		if e != nil {
			return e
		}
		defer clear(canonical)
		// Both bindings are the same explicit service-add operation. Reusing its
		// purpose also makes a request ID conflict across adapter selections.
		ref, e := n.ReserveSetupEndpoint(current, access, "service.add", r.ID, canonical)
		if e != nil {
			return e
		}
		if e = access.VerifyCurrent(current); e != nil {
			return e
		}
		revision, e := n.Installation.Store.Register(current, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: input.Name, Description: input.Description, Metadata: a2aInputMetadata(card.Capabilities.Streaming, input.Cancellation), Bindings: []fabric.BindingSummary{{ID: "a2a", Protocol: "a2a.jsonrpc", Version: string(sdk.Version), Streaming: card.Capabilities.Streaming, Cancellation: input.Cancellation, Idempotency: true}}}})
		if e != nil {
			return e
		}
		scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "a2a"}
		_, e = n.Services.Profiles.Install(current, scope, profile)
		if e != nil {
			return e
		}
		if e = access.VerifyCurrent(current); e != nil {
			return e
		}
		n.Publisher.Notify()
		result := ServiceAddResult{Ref: ref, Revision: revision, Name: input.Name, ProtocolVersion: string(sdk.Version), State: "configured"}
		// A2A setup is local adapter construction, not a remote health check.
		// Never report the endpoint online solely because its card was accepted.
		if e = n.Services.Connect(current, scope, false); e != nil {
			result.State, result.ErrorCode = "unavailable", fabric.CodeTargetUnavailable
		}
		out, e = json.Marshal(result)
		return e
	})
	return out, e
}

// Progressive disclosure describes the adapter grammar, not the private card
// or a new mandatory capability taxonomy. It contains no transport/credential.
func a2aInputMetadata(streaming, cancellation bool) map[string]json.RawMessage {
	operations := []string{"send", "get"}
	modes := []string{"unary"}
	if streaming {
		operations = append(operations, "subscribe")
		modes = append(modes, "stream")
	}
	if cancellation {
		operations = append(operations, "cancel")
	}
	schema := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "object", "required": []string{"operation"},
		"properties": map[string]any{
			"operation":             map[string]any{"type": "string", "enum": operations},
			"mode":                  map[string]any{"type": "string"},
			"associationInvocation": map[string]any{"type": "string", "maxLength": 256},
			"parts": map[string]any{"type": "array", "maxItems": 64, "items": map[string]any{
				"type": "object", "oneOf": []any{
					map[string]any{"required": []string{"text"}, "properties": map[string]any{"text": map[string]any{"type": "string"}, "data": false}},
					map[string]any{"required": []string{"data"}, "properties": map[string]any{"text": false}},
				},
			}},
		},
		"if": map[string]any{"properties": map[string]any{"operation": map[string]any{"const": "send"}}},
		"then": map[string]any{"required": []string{"mode", "parts"}, "properties": map[string]any{
			"mode": map[string]any{"enum": modes}, "parts": map[string]any{"minItems": 1}, "associationInvocation": map[string]any{"maxLength": 0},
		}},
		"else": map[string]any{"required": []string{"associationInvocation"}, "properties": map[string]any{
			"associationInvocation": map[string]any{"minLength": 1}, "parts": map[string]any{"maxItems": 0}, "mode": map[string]any{"const": ""},
		}},
	}
	raw, _ := json.Marshal(schema)
	return map[string]json.RawMessage{
		"extensions.pagnet.agent.input_schema":   raw,
		"extensions.pagnet.agent.input_examples": json.RawMessage(`[{"operation":"send","mode":"unary","parts":[{"text":"Your request"}]}]`),
		"extensions.pagnet.agent.input_limits":   json.RawMessage(`{"requestUtf8Bytes":1048576,"format":"a2a.jsonrpc.input.v1"}`),
	}
}
