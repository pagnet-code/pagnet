package fabric

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"
)

type Operation string

const (
	OperationDiscover Operation = "discover"
	OperationDescribe Operation = "describe"
	OperationInvoke   Operation = "invoke"
)

type Revision string

// Principal is a public assertion/view, never an authentication credential.
type Principal struct {
	Ref    string `json:"ref"`
	Kind   string `json:"kind"`
	Issuer string `json:"issuer"`
}

// Envelope is signed/encrypted as exact bounded bytes. Its routing and system
// context are immutable to application JSON Patch. Metadata keys are namespaced.
type Envelope struct {
	ProtocolVersion  ProtocolVersion            `json:"protocolVersion"`
	ID               string                     `json:"id"`
	Operation        Operation                  `json:"operation"`
	Principal        Principal                  `json:"principal"`
	Source           string                     `json:"source"`
	Target           *EndpointRef               `json:"target,omitempty"`
	ExpectedRevision Revision                   `json:"expectedRevision,omitempty"`
	CreatedAt        time.Time                  `json:"createdAt"`
	Payload          json.RawMessage            `json:"payload"`
	Metadata         map[string]json.RawMessage `json:"metadata,omitempty"`
	Context          EnvelopeContext            `json:"context"`
	Trace            TraceContext               `json:"traceContext,omitempty"`
	RequiredFeatures []string                   `json:"requiredFeatures,omitempty"`
}

type EnvelopeContext struct {
	ParentID       string     `json:"parentId,omitempty"`
	Origin         string     `json:"origin"`
	Ancestry       []string   `json:"ancestry,omitempty"`
	Hops           uint32     `json:"hops"`
	Deadline       *time.Time `json:"deadline,omitempty"`
	IdempotencyKey string     `json:"idempotencyKey,omitempty"`
	ExtensionChain []string   `json:"extensionChain,omitempty"`
	TriggerLineage []string   `json:"triggerLineage,omitempty"`
}

type TraceContext struct {
	TraceParent string `json:"traceparent,omitempty"`
	TraceState  string `json:"tracestate,omitempty"`
	Baggage     string `json:"baggage,omitempty"`
}

func (e Envelope) Validate() error {
	if err := e.ProtocolVersion.Validate(); err != nil {
		return err
	}
	if !validText(e.ID, 256) || !validText(e.Source, 4096) || !validText(e.Context.Origin, 4096) || e.CreatedAt.IsZero() {
		return NewError(CodeInvalidInput, "Missing or invalid envelope identity")
	}
	if !validText(e.Principal.Ref, 4096) || !validText(e.Principal.Issuer, 4096) || !ValidNamespacedName(e.Principal.Kind) {
		return NewError(CodeInvalidInput, "Invalid principal assertion")
	}
	switch e.Operation {
	case OperationDiscover, OperationDescribe:
		if e.Target != nil || e.ExpectedRevision != "" {
			return NewError(CodeInvalidInput, "Read operation has invocation routing fields")
		}
	case OperationInvoke:
		if e.Target == nil {
			return NewError(CodeInvalidInput, "Invocation requires an exact target")
		}
		if _, err := ParseEndpointRef(e.Target.String()); err != nil {
			return err
		}
	default:
		return NewError(CodeUnsupported, "Unsupported operation")
	}
	if len(e.RequiredFeatures) > 0 {
		return NewError(CodeUnsupported, "Required protocol features are not supported")
	}
	if len(e.Context.Ancestry) > 64 || len(e.Context.ExtensionChain) > 64 || len(e.Context.TriggerLineage) > 64 || e.Context.Hops > 64 {
		return NewError(CodeProtocolError, "Envelope ancestry exceeds limits")
	}
	for _, values := range [][]string{e.Context.Ancestry, e.Context.ExtensionChain, e.Context.TriggerLineage} {
		for _, value := range values {
			if !validText(value, 256) {
				return NewError(CodeInvalidInput, "Invalid envelope ancestry")
			}
		}
	}
	if len(e.Metadata) > 64 {
		return NewError(CodeInvalidInput, "Too many metadata fields")
	}
	for key, value := range e.Metadata {
		if !ValidNamespacedName(key) || !strings.HasPrefix(key, "extensions.") {
			return NewError(CodeInvalidInput, "Metadata keys require an extension namespace")
		}
		var decoded any
		if err := DecodeJSON(value, &decoded); err != nil {
			return err
		}
	}
	var payload any
	return DecodeJSON(e.Payload, &payload)
}

func validText(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

// BindingSummary exposes protocol semantics, not URLs with embedded credentials
// or provider configuration. Private bindings are held by the adapter store.
type BindingSummary struct {
	ID           string `json:"id"`
	Protocol     string `json:"protocol"`
	Version      string `json:"version"`
	Streaming    bool   `json:"streaming"`
	Cancellation bool   `json:"cancellation"`
	Idempotency  bool   `json:"idempotency"`
}

type EndpointDescriptor struct {
	Ref         EndpointRef                `json:"ref"`
	Revision    Revision                   `json:"revision"`
	Kind        string                     `json:"kind"`
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	Bindings    []BindingSummary           `json:"bindings,omitempty"`
	Metadata    map[string]json.RawMessage `json:"metadata,omitempty"`
}

// Offer schemas live in individually addressable records. The parent does not
// carry all sibling schemas into a search or a paginated endpoint description.
type OfferDescriptor struct {
	Ref          EndpointRef       `json:"ref"`
	Revision     Revision          `json:"revision"`
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	InputSchema  json.RawMessage   `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage   `json:"outputSchema,omitempty"`
	Examples     []json.RawMessage `json:"examples,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	BindingID    string            `json:"bindingId"`
}

type OfferSummary struct {
	Ref         EndpointRef `json:"ref"`
	Revision    Revision    `json:"revision"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
}

type Availability struct {
	State      string    `json:"state"`
	ObservedAt time.Time `json:"observedAt"`
}

// SearchDocument is deliberately separate from full descriptors and schemas.
type SearchDocument struct {
	Ref               EndpointRef   `json:"ref"`
	Revision          Revision      `json:"revision"`
	Name              string        `json:"name"`
	ShortDescription  string        `json:"shortDescription"`
	Kind              string        `json:"kind"`
	Tags              []string      `json:"tags,omitempty"`
	Examples          []string      `json:"examples,omitempty"`
	SchemaFingerprint string        `json:"schemaFingerprint,omitempty"`
	Provider          string        `json:"provider,omitempty"`
	Availability      *Availability `json:"availability,omitempty"`
}

type DiscoverRequest struct {
	Query   string         `json:"query"`
	Scope   DiscoveryScope `json:"scope"`
	Filters SearchFilters  `json:"filters,omitempty"`
	Limit   int            `json:"limit"`
	Cursor  string         `json:"cursor,omitempty"`
}

// Remote scopes are explicit and bounded. Empty means the local trust domain.
type DiscoveryScope struct {
	Domains []string `json:"domains,omitempty"`
}

type SearchFilters struct {
	Kinds     []string `json:"kinds,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Providers []string `json:"providers,omitempty"`
}

type Candidate struct {
	Document SearchDocument `json:"document"`
	Score    float64        `json:"score"`
}

type DiscoverResult struct {
	Candidates    []Candidate `json:"candidates"`
	IndexRevision Revision    `json:"indexRevision"`
	NextCursor    string      `json:"nextCursor,omitempty"`
}

type DescribeSelection struct {
	Ref              EndpointRef `json:"ref"`
	ExpectedRevision Revision    `json:"expectedRevision,omitempty"`
	OffersCursor     string      `json:"offersCursor,omitempty"`
	OffersLimit      int         `json:"offersLimit,omitempty"`
}

type DescribeRequest struct {
	Selections []DescribeSelection `json:"selections"`
}

type Description struct {
	Ref              EndpointRef         `json:"ref"`
	Endpoint         *EndpointDescriptor `json:"endpoint,omitempty"`
	Offer            *OfferDescriptor    `json:"offer,omitempty"`
	Offers           []OfferSummary      `json:"offers,omitempty"`
	NextOffersCursor string              `json:"nextOffersCursor,omitempty"`
	Error            *Error              `json:"error,omitempty"`
}

type DescribeResult struct {
	Descriptions []Description `json:"descriptions"`
}

type InvokeRequest struct {
	// Set by the engine from the protected envelope ID, never decoded from
	// application input. It binds response streams and durable admissions.
	InvocationID     string          `json:"-"`
	Target           EndpointRef     `json:"target"`
	ExpectedRevision Revision        `json:"expectedRevision,omitempty"`
	Input            json.RawMessage `json:"input"`
	Deadline         *time.Time      `json:"deadline,omitempty"`
	IdempotencyKey   string          `json:"idempotencyKey,omitempty"`
}

func (r DiscoverRequest) Validate() error {
	if len(r.Query) > 4096 || !utf8.ValidString(r.Query) || r.Limit < 1 || r.Limit > 100 || len(r.Cursor) > 4096 || len(r.Scope.Domains) > 16 {
		return NewError(CodeInvalidInput, "Discovery bounds exceeded")
	}
	seen := make(map[string]bool, len(r.Scope.Domains))
	for _, domain := range r.Scope.Domains {
		if !validText(domain, 128) || seen[domain] {
			return NewError(CodeInvalidInput, "Invalid or duplicate discovery scope")
		}
		seen[domain] = true
	}
	if len(r.Filters.Kinds) > 32 || len(r.Filters.Tags) > 32 || len(r.Filters.Providers) > 32 {
		return NewError(CodeInvalidInput, "Too many search filters")
	}
	for _, kind := range r.Filters.Kinds {
		if !ValidNamespacedName(kind) {
			return NewError(CodeInvalidInput, "Invalid endpoint kind filter")
		}
	}
	for _, values := range [][]string{r.Filters.Tags, r.Filters.Providers} {
		for _, value := range values {
			if !validText(value, 256) {
				return NewError(CodeInvalidInput, "Invalid search filter")
			}
		}
	}
	return nil
}

func (r DescribeRequest) Validate() error {
	if len(r.Selections) < 1 || len(r.Selections) > 100 {
		return NewError(CodeInvalidInput, "Description selection bounds exceeded")
	}
	for _, selection := range r.Selections {
		if _, err := ParseEndpointRef(selection.Ref.String()); err != nil {
			return err
		}
		if selection.OffersLimit < 0 || selection.OffersLimit > 100 || len(selection.OffersCursor) > 4096 || len(selection.ExpectedRevision) > 256 {
			return NewError(CodeInvalidInput, "Invalid description page")
		}
		if selection.Ref.IsOffer() && (selection.OffersCursor != "" || selection.OffersLimit != 0) {
			return NewError(CodeInvalidInput, "An exact offer has no sibling page")
		}
	}
	return nil
}

func (r InvokeRequest) Validate() error {
	if !validText(r.InvocationID, 256) {
		return NewError(CodeInvalidInput, "Missing invocation identity")
	}
	if _, err := ParseEndpointRef(r.Target.String()); err != nil {
		return err
	}
	if len(r.ExpectedRevision) > 256 || len(r.IdempotencyKey) > 256 {
		return NewError(CodeInvalidInput, "Invocation bounds exceeded")
	}
	var input any
	return DecodeJSON(r.Input, &input)
}
