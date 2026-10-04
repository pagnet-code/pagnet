// Package mcp adapts registered downstream MCP tools without changing Fabric
// identity, routing or admission. Protocol negotiation belongs to the official SDK.
package mcp

import (
	"context"
	"encoding/json"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
)

type Credentials struct {
	Headers     map[string]string
	Environment []string
}
type CredentialProvider interface {
	Credentials(context.Context, string) (Credentials, error)
}

// TransportFactory runs during explicit connection setup only. It receives
// binding-private credentials, never a target's application input. Remote
// factories must retain SDK Connection state-update hooks: use the supplied
// tap's HTTP transport wrapper, not a generic Connection wrapper.
type TransportFactory interface {
	Transport(context.Context, Credentials, *ResultTap) (sdk.Transport, error)
}

type ToolDescriptor struct {
	Name, Description, Fingerprint string
	InputSchema, OutputSchema      json.RawMessage
}
type ToolBinding struct {
	Offer                 fabric.OfferDescriptor
	ToolName, Fingerprint string
}

// ToolIdentity is a schema-free synchronization summary, not an invocation target.
type ToolIdentity struct{ ToolName, Fingerprint string }

type CatalogDelta struct {
	Upsert []ToolDescriptor
	Remove []string
}

// Catalog owns durable authority-derived stable identities, encrypted schemas,
// revisions, tombstones and index updates. Name-only disappearance is removal;
// a later name is a new identity unless an explicit provider-ID contract says
// otherwise. Apply must be atomic; adapter publication follows successful Apply.
type Catalog interface {
	Current(context.Context, string) ([]ToolIdentity, error)
	Apply(context.Context, string, fabric.EndpointRef, CatalogDelta) ([]ToolBinding, error)
	Resolve(context.Context, string, fabric.EndpointRef, fabric.Revision) (ToolBinding, error)
}
type Limits struct{ MaxTools, MaxPages, MaxPending, MaxResultBytes, MaxCatalogBytes int }

var DefaultLimits = Limits{4096, 128, 32, 1 << 20, 16 << 20}

type Config struct {
	BindingID       string
	Audience        string
	Endpoint        fabric.EndpointRef
	Credentials     CredentialProvider
	Transport       TransportFactory
	Catalog         Catalog
	Limits          Limits
	ProtocolVersion string
}
