package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

// REST v2 surface (plan D2). All paths are under {server}/api/v1 and
// authenticate with the principal credential (Bearer). The control plane is
// a zero-knowledge relay: protected content crosses ONLY as
// encryptedField {envelope, aad} — the server stores and relays it
// byte-for-byte and never reads the ciphertext.

// encryptedField is one protected field on the REST wire: the E2EE
// envelope + the AAD it was bound to (the server relays both verbatim).
type encryptedField struct {
	Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD      e2ee.AAD                `json:"aad"`
}

// restClient is the SDK's REST transport (sdk-internal).
type restClient struct {
	http      *http.Client
	base      string // {server}/api/v1
	cred      func() string
	userAgent string
}

func newRestClient(base, userAgent string, cred func() string) *restClient {
	return &restClient{
		http:      &http.Client{Timeout: 30 * time.Second},
		base:      strings.TrimSuffix(base, "/") + "/api/v1",
		cred:      cred,
		userAgent: userAgent,
	}
}

// restError is a non-2xx REST response.
type restError struct {
	status int
	body   string
}

func (e *restError) Error() string {
	return fmt.Sprintf("sdk: REST %d: %s", e.status, e.body)
}

// do performs one REST call and decodes the JSON response into out (when
// non-nil).
func (r *restClient) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("sdk: encode REST body: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.cred())
	req.Header.Set("User-Agent", r.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return fmt.Errorf("sdk: REST %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := &restError{status: resp.StatusCode, body: strings.TrimSpace(string(raw))}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("%w: %s", ErrCredentialDead, err.Error())
		}
		return err
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("sdk: decode REST response: %w", err)
		}
	}
	return nil
}

// --- identity -----------------------------------------------------------------
//
// GET /auth/principal/me returns {"principal": Principal, "memberships":
// [NetworkMembership], "endpoints": [PrincipalEndpoint]} — the domain types
// marshal with their Go (PascalCase) field names (no json tags). The
// principal's tenant is OwningTenantID (the AAD routing metadata).

type restIdentity struct {
	Principal struct {
		ID             string `json:"ID"`
		OwningTenantID string `json:"OwningTenantID"`
		Kind           string `json:"Kind"`
		Name           string `json:"Name"`
		Description    string `json:"Description"`
		Visibility     string `json:"Visibility"`
		ProviderName   string `json:"ProviderName"`
		ProviderURL    string `json:"ProviderURL"`
	} `json:"principal"`
	Memberships []struct {
		NetworkID   string   `json:"NetworkID"`
		State       string   `json:"State"`
		Permissions []string `json:"Permissions"`
	} `json:"memberships"`
}

func (r *restClient) whoAmI(ctx context.Context) (*Identity, error) {
	var id restIdentity
	if err := r.do(ctx, http.MethodGet, "/auth/principal/me", nil, &id); err != nil {
		return nil, err
	}
	out := &Identity{
		PrincipalID:  id.Principal.ID,
		TenantID:     id.Principal.OwningTenantID,
		Kind:         id.Principal.Kind,
		Name:         id.Principal.Name,
		Description:  id.Principal.Description,
		Visibility:   id.Principal.Visibility,
		ProviderName: id.Principal.ProviderName,
		ProviderURL:  id.Principal.ProviderURL,
	}
	for _, m := range id.Memberships {
		out.Memberships = append(out.Memberships, Membership{
			NetworkID:   m.NetworkID,
			State:       m.State,
			Permissions: m.Permissions,
		})
	}
	return out, nil
}

// --- networks -------------------------------------------------------------------
//
// GET /networks returns a BARE ARRAY of networkResponse: the domain.Network
// fields (PascalCase) plus a camelCase "crypto" lifecycle block. A principal
// sees only the networks it is an ACTIVE member of.

type restNetwork struct {
	ID          string `json:"ID"`
	Name        string `json:"Name"`
	Slug        string `json:"Slug"`
	Description string `json:"Description"`
}

func (r *restClient) networks(ctx context.Context) ([]NetworkInfo, error) {
	var nets []restNetwork
	if err := r.do(ctx, http.MethodGet, "/networks", nil, &nets); err != nil {
		return nil, err
	}
	out := make([]NetworkInfo, 0, len(nets))
	for _, n := range nets {
		out = append(out, NetworkInfo{
			ID:          n.ID,
			Name:        n.Name,
			Slug:        n.Slug,
			Description: n.Description,
		})
	}
	return out, nil
}

// --- messages ---------------------------------------------------------------------
//
// POST /networks/{id}/messages: the protected content crosses as a top-level
// "envelope" + "aad" pair (the server relays both verbatim; it never reads
// the ciphertext). The response is the full domain.Message (PascalCase ID).

type restMessageRequest struct {
	ID                   string                  `json:"id"`
	ThreadID             string                  `json:"threadId,omitempty"`
	RecipientPrincipalID string                  `json:"recipientPrincipalId,omitempty"`
	RecipientGroup       string                  `json:"recipientGroup,omitempty"`
	Kind                 string                  `json:"kind"`
	Envelope             e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD                  e2ee.AAD                `json:"aad"`
}

func (r *restClient) sendMessage(ctx context.Context, networkID string, req restMessageRequest) (string, error) {
	var out struct {
		ID string `json:"ID"`
	}
	if err := r.do(ctx, http.MethodPost, "/networks/"+networkID+"/messages", req, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// --- events ------------------------------------------------------------------------
//
// POST /networks/{id}/events: the payload crosses as a top-level "envelope" +
// "aad" pair. The client-generated object id rides in "eventId" (the AAD
// binds it) and the server adopts it. The response is
// {"event": Event, "deliveries": n} — the event id is event.ID (PascalCase).

type restEventRequest struct {
	Type              string                  `json:"type"`
	SchemaVersion     int                     `json:"schemaVersion,omitempty"`
	TargetPrincipalID string                  `json:"targetPrincipalId,omitempty"`
	ResourceID        string                  `json:"resourceId,omitempty"`
	CapabilityID      string                  `json:"capabilityId,omitempty"`
	Envelope          e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD               e2ee.AAD                `json:"aad"`
	EventID           string                  `json:"eventId"`
	CorrelationID     string                  `json:"correlationId,omitempty"`
	CausationID       string                  `json:"causationId,omitempty"`
}

func (r *restClient) publishEvent(ctx context.Context, networkID string, req restEventRequest) (string, error) {
	var out struct {
		Event struct {
			ID string `json:"ID"`
		} `json:"event"`
	}
	if err := r.do(ctx, http.MethodPost, "/networks/"+networkID+"/events", req, &out); err != nil {
		return "", err
	}
	return out.Event.ID, nil
}

// --- subscriptions --------------------------------------------------------------------

type restSubscriptionRequest struct {
	EventPattern        string `json:"eventPattern"`
	ProducerPrincipalID string `json:"producerPrincipalId,omitempty"`
	TargetPrincipalID   string `json:"targetPrincipalId,omitempty"`
	ResourceID          string `json:"resourceId,omitempty"`
	CapabilityID        string `json:"capabilityId,omitempty"`
	DeliveryMode        string `json:"deliveryMode,omitempty"`
	Enabled             *bool  `json:"enabled,omitempty"`
}

// restSubscription is one EventSubscription (PascalCase domain fields).
type restSubscription struct {
	ID           string `json:"ID"`
	EventPattern string `json:"EventPattern"`
	Enabled      bool   `json:"Enabled"`
}

func (r *restClient) createSubscription(ctx context.Context, networkID string, req restSubscriptionRequest) (string, error) {
	var out restSubscription
	if err := r.do(ctx, http.MethodPost, "/networks/"+networkID+"/subscriptions", req, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// listSubscriptions returns the principal's subscriptions in the network
// (GET returns a BARE ARRAY of EventSubscription).
func (r *restClient) listSubscriptions(ctx context.Context, networkID string) ([]restSubscription, error) {
	var subs []restSubscription
	if err := r.do(ctx, http.MethodGet, "/networks/"+networkID+"/subscriptions", nil, &subs); err != nil {
		return nil, err
	}
	return subs, nil
}

func (r *restClient) deleteSubscription(ctx context.Context, networkID, subID string) error {
	return r.do(ctx, http.MethodDelete, "/networks/"+networkID+"/subscriptions/"+subID, nil, nil)
}

// --- invocations -----------------------------------------------------------------------
//
// POST /networks/{id}/invocations: the input crosses as a top-level
// "envelope" + "aad" pair; the client-generated object id rides in
// "invocationId" (the AAD binds it) and the server adopts it. Both POST and
// GET return the invocationView: {"invocation": CapabilityInvocation,
// "input"/"output"/"error": {envelope, aad}} — the record is PascalCase and
// the protected fields are top-level wrapper keys.

type restInvocationRequest struct {
	TargetPrincipalID string                  `json:"targetPrincipalId"`
	CapabilityID      string                  `json:"capabilityId"`
	CapabilityVersion int                     `json:"capabilityVersion"`
	Envelope          e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD               e2ee.AAD                `json:"aad"`
	InvocationID      string                  `json:"invocationId"`
	IdempotencyKey    string                  `json:"idempotencyKey,omitempty"`
	CorrelationID     string                  `json:"correlationId,omitempty"`
	CausationID       string                  `json:"causationId,omitempty"`
}

// restInvocation is the invocation record flattened from the invocationView
// (the durable server-side state + the protected fields).
type restInvocation struct {
	ID                string
	NetworkID         string
	CallerPrincipalID string
	TargetPrincipalID string
	CapabilityID      string
	CapabilityVersion int
	State             string
	IdempotencyKey    string
	ProtectedInput    *encryptedField
	ProtectedOutput   *encryptedField
	ProtectedError    *encryptedField
	PublicResultCode  string
	UsageMetadata     map[string]any
	CreatedAt         string
	CompletedAt       *time.Time
}

// restInvocationResponse is the invocationView wire shape.
type restInvocationResponse struct {
	Invocation struct {
		ID                string         `json:"ID"`
		NetworkID         string         `json:"NetworkID"`
		CallerPrincipalID string         `json:"CallerPrincipalID"`
		TargetPrincipalID string         `json:"TargetPrincipalID"`
		CapabilityID      string         `json:"CapabilityID"`
		CapabilityVersion int            `json:"CapabilityVersion"`
		State             string         `json:"State"`
		IdempotencyKey    string         `json:"IdempotencyKey"`
		PublicResultCode  string         `json:"PublicResultCode"`
		UsageMetadata     map[string]any `json:"UsageMetadata"`
		CreatedAt         string         `json:"CreatedAt"`
		CompletedAt       *time.Time     `json:"CompletedAt"`
	} `json:"invocation"`
	Input  *encryptedField `json:"input"`
	Output *encryptedField `json:"output"`
	Error  *encryptedField `json:"error"`
}

func (r *restInvocationResponse) flatten() *restInvocation {
	return &restInvocation{
		ID:                r.Invocation.ID,
		NetworkID:         r.Invocation.NetworkID,
		CallerPrincipalID: r.Invocation.CallerPrincipalID,
		TargetPrincipalID: r.Invocation.TargetPrincipalID,
		CapabilityID:      r.Invocation.CapabilityID,
		CapabilityVersion: r.Invocation.CapabilityVersion,
		State:             r.Invocation.State,
		IdempotencyKey:    r.Invocation.IdempotencyKey,
		ProtectedInput:    r.Input,
		ProtectedOutput:   r.Output,
		ProtectedError:    r.Error,
		PublicResultCode:  r.Invocation.PublicResultCode,
		UsageMetadata:     r.Invocation.UsageMetadata,
		CreatedAt:         r.Invocation.CreatedAt,
		CompletedAt:       r.Invocation.CompletedAt,
	}
}

func (r *restClient) createInvocation(ctx context.Context, networkID string, req restInvocationRequest) (*restInvocation, error) {
	var out restInvocationResponse
	if err := r.do(ctx, http.MethodPost, "/networks/"+networkID+"/invocations", req, &out); err != nil {
		return nil, err
	}
	return out.flatten(), nil
}

func (r *restClient) getInvocation(ctx context.Context, networkID, invocationID string) (*restInvocation, error) {
	var out restInvocationResponse
	if err := r.do(ctx, http.MethodGet, "/networks/"+networkID+"/invocations/"+invocationID, nil, &out); err != nil {
		return nil, err
	}
	return out.flatten(), nil
}

// --- search -------------------------------------------------------------------------------
//
// GET /networks/{id}/search returns {"results": [SearchResult], "cursor":
// string}. Each result is the embedded domain.Principal (PascalCase) plus
// MatchReasons []string, RankBucket, and HasOnlineEndpoint. (The server does
// not currently return the principal's capabilities in a search hit — the
// caller invokes by explicit capability id.)

type restSearchResult struct {
	ID                string       `json:"ID"`
	Kind              string       `json:"Kind"`
	Name              string       `json:"Name"`
	Description       string       `json:"Description"`
	Visibility        string       `json:"Visibility"`
	ProviderName      string       `json:"ProviderName"`
	ProviderURL       string       `json:"ProviderURL"`
	Capabilities      []Capability `json:"Capabilities"`
	MatchReasons      []string     `json:"MatchReasons"`
	HasOnlineEndpoint bool         `json:"HasOnlineEndpoint"`
}

func (r *restClient) search(ctx context.Context, networkID string, q Query) ([]SearchResult, string, error) {
	params := url.Values{}
	if q.Text != "" {
		params.Set("query", q.Text)
	}
	if q.Kind != "" {
		params.Set("kind", q.Kind)
	}
	if q.Capability != "" {
		params.Set("capability", q.Capability)
	}
	if q.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", q.Limit))
	}
	if q.Cursor != "" {
		params.Set("cursor", q.Cursor)
	}
	var page struct {
		Results []restSearchResult `json:"results"`
		Cursor  string             `json:"cursor"`
	}
	path := "/networks/" + networkID + "/search"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	if err := r.do(ctx, http.MethodGet, path, nil, &page); err != nil {
		return nil, "", err
	}
	out := make([]SearchResult, 0, len(page.Results))
	for _, res := range page.Results {
		state := ""
		if res.HasOnlineEndpoint {
			state = "connected"
		}
		out = append(out, SearchResult{
			PrincipalID:  res.ID,
			Kind:         res.Kind,
			Name:         res.Name,
			Description:  res.Description,
			Visibility:   res.Visibility,
			ProviderName: res.ProviderName,
			ProviderURL:  res.ProviderURL,
			Capabilities: res.Capabilities,
			MatchReasons: res.MatchReasons,
			State:        state,
		})
	}
	return out, page.Cursor, nil
}
