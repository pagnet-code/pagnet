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

type restIdentity struct {
	PrincipalID  string `json:"principalId"`
	TenantID     string `json:"tenantId"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Visibility   string `json:"visibility"`
	ProviderName string `json:"providerName"`
	ProviderURL  string `json:"providerUrl"`
	Memberships  []struct {
		NetworkID   string   `json:"networkId"`
		State       string   `json:"state"`
		Permissions []string `json:"permissions"`
	} `json:"memberships"`
}

func (r *restClient) whoAmI(ctx context.Context) (*Identity, error) {
	var id restIdentity
	if err := r.do(ctx, http.MethodGet, "/auth/principal/me", nil, &id); err != nil {
		return nil, err
	}
	out := &Identity{
		PrincipalID:  id.PrincipalID,
		TenantID:     id.TenantID,
		Kind:         id.Kind,
		Name:         id.Name,
		Description:  id.Description,
		Visibility:   id.Visibility,
		ProviderName: id.ProviderName,
		ProviderURL:  id.ProviderURL,
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

type restNetwork struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
}

func (r *restClient) networks(ctx context.Context) ([]NetworkInfo, error) {
	var page struct {
		Networks []restNetwork `json:"networks"`
	}
	if err := r.do(ctx, http.MethodGet, "/networks", nil, &page); err != nil {
		return nil, err
	}
	out := make([]NetworkInfo, 0, len(page.Networks))
	for _, n := range page.Networks {
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

type restMessageRequest struct {
	ID                   string         `json:"id"`
	ThreadID             string         `json:"threadId,omitempty"`
	RecipientPrincipalID string         `json:"recipientPrincipalId,omitempty"`
	RecipientGroupID     string         `json:"recipientGroupId,omitempty"`
	Kind                 string         `json:"kind"`
	Parts                encryptedField `json:"parts"`
	Metadata             map[string]any `json:"metadata,omitempty"`
}

func (r *restClient) sendMessage(ctx context.Context, networkID string, req restMessageRequest) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := r.do(ctx, http.MethodPost, "/networks/"+networkID+"/messages", req, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// --- events ------------------------------------------------------------------------

type restEventRequest struct {
	ID                string         `json:"id"`
	Type              string         `json:"type"`
	SchemaVersion     int            `json:"schemaVersion"`
	TargetPrincipalID string         `json:"targetPrincipalId,omitempty"`
	ResourceID        string         `json:"resourceId,omitempty"`
	CapabilityID      string         `json:"capabilityId,omitempty"`
	Payload           encryptedField `json:"payload"`
	CorrelationID     string         `json:"correlationId,omitempty"`
	CausationID       string         `json:"causationId,omitempty"`
}

func (r *restClient) publishEvent(ctx context.Context, networkID string, req restEventRequest) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := r.do(ctx, http.MethodPost, "/networks/"+networkID+"/events", req, &out); err != nil {
		return "", err
	}
	return out.ID, nil
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

type restSubscription struct {
	ID           string `json:"id"`
	EventPattern string `json:"eventPattern"`
	Enabled      bool   `json:"enabled"`
}

func (r *restClient) createSubscription(ctx context.Context, networkID string, req restSubscriptionRequest) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := r.do(ctx, http.MethodPost, "/networks/"+networkID+"/subscriptions", req, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

func (r *restClient) listSubscriptions(ctx context.Context, networkID string) ([]restSubscription, error) {
	var page struct {
		Subscriptions []restSubscription `json:"subscriptions"`
	}
	if err := r.do(ctx, http.MethodGet, "/networks/"+networkID+"/subscriptions", nil, &page); err != nil {
		return nil, err
	}
	return page.Subscriptions, nil
}

func (r *restClient) deleteSubscription(ctx context.Context, networkID, subID string) error {
	return r.do(ctx, http.MethodDelete, "/networks/"+networkID+"/subscriptions/"+subID, nil, nil)
}

// --- invocations -----------------------------------------------------------------------

type restInvocationRequest struct {
	ID                string         `json:"id"`
	TargetPrincipalID string         `json:"targetPrincipalId"`
	CapabilityID      string         `json:"capabilityId"`
	CapabilityVersion int            `json:"capabilityVersion"`
	Input             encryptedField `json:"input"`
	IdempotencyKey    string         `json:"idempotencyKey,omitempty"`
	CorrelationID     string         `json:"correlationId,omitempty"`
	CausationID       string         `json:"causationId,omitempty"`
}

// restInvocation is the invocation record (the durable server-side state).
type restInvocation struct {
	ID                string          `json:"id"`
	NetworkID         string          `json:"networkId"`
	CallerPrincipalID string          `json:"callerPrincipalId"`
	TargetPrincipalID string          `json:"targetPrincipalId"`
	CapabilityID      string          `json:"capabilityId"`
	CapabilityVersion int             `json:"capabilityVersion"`
	State             string          `json:"state"`
	IdempotencyKey    string          `json:"idempotencyKey,omitempty"`
	CorrelationID     string          `json:"correlationId,omitempty"`
	CausationID       string          `json:"causationId,omitempty"`
	ProtectedInput    *encryptedField `json:"protectedInput,omitempty"`
	ProtectedOutput   *encryptedField `json:"protectedOutput,omitempty"`
	ProtectedError    *encryptedField `json:"protectedError,omitempty"`
	PublicResultCode  string          `json:"publicResultCode,omitempty"`
	UsageMetadata     map[string]any  `json:"usageMetadata,omitempty"`
	CreatedAt         string          `json:"createdAt"`
	CompletedAt       string          `json:"completedAt,omitempty"`
}

func (r *restClient) createInvocation(ctx context.Context, networkID string, req restInvocationRequest) (*restInvocation, error) {
	var out restInvocation
	if err := r.do(ctx, http.MethodPost, "/networks/"+networkID+"/invocations", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *restClient) getInvocation(ctx context.Context, networkID, invocationID string) (*restInvocation, error) {
	var out restInvocation
	if err := r.do(ctx, http.MethodGet, "/networks/"+networkID+"/invocations/"+invocationID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- search -------------------------------------------------------------------------------

type restSearchResult struct {
	PrincipalID  string       `json:"principalId"`
	Kind         string       `json:"kind"`
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	Visibility   string       `json:"visibility"`
	ProviderName string       `json:"providerName"`
	ProviderURL  string       `json:"providerUrl"`
	Capabilities []Capability `json:"capabilities"`
	MatchReasons []string     `json:"matchReasons"`
	State        string       `json:"state"`
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
		out = append(out, SearchResult{
			PrincipalID:  res.PrincipalID,
			Kind:         res.Kind,
			Name:         res.Name,
			Description:  res.Description,
			Visibility:   res.Visibility,
			ProviderName: res.ProviderName,
			ProviderURL:  res.ProviderURL,
			Capabilities: res.Capabilities,
			MatchReasons: res.MatchReasons,
			State:        res.State,
		})
	}
	return out, page.Cursor, nil
}
