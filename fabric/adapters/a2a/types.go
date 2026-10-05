// Package a2a adapts an explicitly selected official A2A1.0 JSON-RPC binding.
package a2a

import (
	"context"
	"encoding/json"
	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/pagnet-code/pagnet/fabric"
	"net/http"
	"time"
)

type Credentials func(context.Context, fabric.ExecutionContext, sdk.AgentInterface) (http.Header, error)
type DisclosureGate func(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, fabric.InvokeRequest) error
type Limits struct {
	MaxEventBytes, MaxRequestBytes int
	MaxStreamBytes                 int64
	Lifetime                       time.Duration
}
type Config struct {
	// RootIdempotency opts into a trusted signed local alias ledger. It does
	// not assert upstream A2A retry support or emit remote idempotency headers.
	RootIdempotency     bool
	Ref                 fabric.EndpointRef
	Revision            fabric.Revision
	BindingID, Audience string
	// BindingDigest pins trusted operator-selected provider account/profile, never a token.
	BindingDigest  [32]byte
	Card           *sdk.AgentCard
	Interface      sdk.AgentInterface
	Credentials    Credentials
	DisclosureGate DisclosureGate
	Associations   AssociationStore
	HTTPClient     *http.Client
	AllowHTTP      bool
	Cancellation   bool
	Limits         Limits
}
type Input struct {
	Operation             string `json:"operation"`
	Mode                  string `json:"mode,omitempty"`
	Parts                 []Part `json:"parts,omitempty"`
	AssociationInvocation string `json:"associationInvocation,omitempty"`
}
type Part struct {
	Text *string         `json:"text,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}
type AssociationKey struct {
	Principal                       fabric.Principal
	Ref                             fabric.EndpointRef
	Revision                        fabric.Revision
	Binding, InvocationID, Audience string
}
type Association struct {
	Key                                          AssociationKey
	InputSHA, Operation, Mode, TaskID, ContextID string
}
type AssociationStore interface {
	Scope() StoreScope
	Admit(context.Context, Association) error
	Associate(context.Context, AssociationKey, string, string) error
	Lookup(context.Context, AssociationKey) (Association, error)
}

// RootIdempotencyStore is trusted composition, not a remote AgentCard claim.
// Only a real same-root admission/alias ledger may opt into this capability.
type RootIdempotencyStore interface {
	AssociationStore
	SupportsRootIdempotency() bool
}
