// Package directhttp implements the private direct endpoint V2 wire adapter.
// It owns no credentials and performs no retries or background coordination.
package directhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/transport"
)

const prefix = "/private/direct/v2"

type Kind string

const (
	Invalid            Kind = "invalid"
	Unauthorized       Kind = "unauthorized"
	Unavailable        Kind = "unavailable"
	Conflict           Kind = "conflict"
	TooLarge           Kind = "too_large"
	ServiceUnavailable Kind = "service_unavailable"
	Protocol           Kind = "protocol"
	Transport          Kind = "transport"
)

// Error is deliberately independent of server bodies, URLs and credentials.
// UnknownCommit means callers must reconcile before retrying a mutation.
type Error struct {
	Kind          Kind
	Status        int
	UnknownCommit bool
}

func (e *Error) Error() string { return "direct endpoint v2: " + string(e.Kind) }
func failure(k Kind) error     { return &Error{Kind: k} }

type Client struct {
	origin string
	http   *http.Client
}

// New pins an HTTPS origin for this instance. Paths, credentials, proxies and
// account sessions cannot be supplied through that origin.
func New(origin string) (*Client, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.Contains(origin, "#") || origin != u.String() || strings.ToLower(u.Host) != u.Host {
		return nil, failure(Invalid)
	}
	if u.Hostname() == "" || strings.HasSuffix(u.Hostname(), ".") || strings.HasSuffix(u.Host, ":") {
		return nil, failure(Invalid)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return nil, failure(Invalid)
		}
	}
	t := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 32 * 1024, ForceAttemptHTTP2: true}
	return &Client{origin: origin, http: &http.Client{Transport: t, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func validID(s string) bool {
	id, e := uuid.Parse(s)
	return e == nil && id.String() == s && id != uuid.Nil
}
func validBinary(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	defer clear(b)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}

// Credentials are opaque canonical credential UUID + ":" + 32-byte raw base64url
// secret. They are accepted only for the duration of an individual operation.
func credentialID(credential string) (string, bool) {
	id, secret, ok := strings.Cut(credential, ":")
	return id, ok && validID(id) && validBinary(secret)
}

type canonical interface{ CanonicalBytes() ([]byte, error) }

func decode[T canonical](raw []byte, decode func([]byte) (T, error)) (T, error) {
	v, e := decode(raw)
	if e != nil {
		var zero T
		return zero, failure(Protocol)
	}
	b, e := v.CanonicalBytes()
	if e != nil || !bytes.Equal(b, raw) {
		var zero T
		return zero, failure(Protocol)
	}
	return v, nil
}
func (c *Client) call(ctx context.Context, credential, method, path string, body []byte, limit int64, created, mutation bool) ([]byte, error) {
	if _, ok := credentialID(credential); !ok {
		return nil, failure(Invalid)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, method, c.origin+prefix+path, bytes.NewReader(body))
	if e != nil {
		return nil, failure(Invalid)
	}
	req.Header.Set("Authorization", "Pagnet-Direct-V2 "+credential)
	defer req.Header.Del("Authorization")
	req.Header.Set("Accept", "application/json")
	req.Header["User-Agent"] = []string{""}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, &Error{Kind: Transport, UnknownCommit: mutation}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && !(created && resp.StatusCode == 201) {
		k := Protocol
		switch resp.StatusCode {
		case 400:
			k = Invalid
		case 401:
			k = Unauthorized
		case 404:
			k = Unavailable
		case 409:
			k = Conflict
		case 413:
			k = TooLarge
		case 503:
			k = ServiceUnavailable
		}
		return nil, &Error{Kind: k, Status: resp.StatusCode, UnknownCommit: mutation && k == Protocol || mutation && resp.StatusCode == 503}
	}
	if resp.Header.Get("Content-Type") != "application/json" || resp.ContentLength > limit {
		return nil, &Error{Kind: Protocol, UnknownCommit: mutation}
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil || int64(len(raw)) > limit {
		clear(raw)
		return nil, &Error{Kind: Protocol, UnknownCommit: mutation}
	}
	return raw, nil
}
func (c *Client) intent(ctx context.Context, credential, id, method, suffix string, body []byte, limit int64, created bool) ([]byte, error) {
	if !validID(id) {
		return nil, failure(Invalid)
	}
	return c.call(ctx, credential, method, "/intents/"+id+suffix, body, limit, created, method != "GET")
}
func (c *Client) Descriptor(ctx context.Context, credential, id string) (transport.DirectChannelDescriptorV2, error) {
	raw, e := c.intent(ctx, credential, id, "GET", "/descriptor", nil, 8192, false)
	if e != nil {
		return transport.DirectChannelDescriptorV2{}, e
	}
	v, e := decode(raw, transport.DecodeDirectChannelDescriptorV2)
	cid, _ := credentialID(credential)
	if e == nil && (v.DirectIntentID != id || (v.S.CredentialID != cid && v.P.CredentialID != cid)) {
		e = failure(Protocol)
	}
	return v, e
}
func (c *Client) Publication(ctx context.Context, credential, id string) (transport.DirectChannelPublicationV2, error) {
	raw, e := c.intent(ctx, credential, id, "GET", "/publication", nil, 12288, false)
	if e != nil {
		return transport.DirectChannelPublicationV2{}, e
	}
	v, e := decode(raw, transport.DecodeDirectChannelPublicationV2)
	cid, _ := credentialID(credential)
	if e == nil && (v.Descriptor.DirectIntentID != id || (v.Descriptor.S.CredentialID != cid && v.Descriptor.P.CredentialID != cid)) {
		e = failure(Protocol)
	}
	return v, e
}
func (c *Client) Publish(ctx context.Context, credential, id string, p transport.DirectChannelPublicationV2, verifier string) (result transport.DirectChannelPublicationV2, resultErr error) {
	defer markUnknown(&resultErr)
	raw, e := p.CanonicalBytes()
	cid, ok := credentialID(credential)
	if e != nil || !ok || cid != p.Descriptor.S.CredentialID || !validBinary(verifier) || p.Descriptor.DirectIntentID != id {
		return transport.DirectChannelPublicationV2{}, failure(Invalid)
	}
	body, _ := json.Marshal(struct {
		Publication       json.RawMessage `json:"publication"`
		ReadinessVerifier string          `json:"readinessVerifier"`
	}{raw, verifier})
	defer clear(body)
	out, e := c.intent(ctx, credential, id, "PUT", "/publication", body, 12288, true)
	if e != nil {
		return transport.DirectChannelPublicationV2{}, e
	}
	v, e := decode(out, transport.DecodeDirectChannelPublicationV2)
	if e == nil && !bytes.Equal(raw, out) {
		e = failure(Protocol)
	}
	return v, e
}
func (c *Client) Challenge(ctx context.Context, credential, id string) (result transport.DirectChannelReadinessChallengeV2, resultErr error) {
	defer markUnknown(&resultErr)
	raw, e := c.intent(ctx, credential, id, "POST", "/readiness/challenge", nil, 4096, true)
	if e != nil {
		return transport.DirectChannelReadinessChallengeV2{}, e
	}
	v, e := decode(raw, transport.DecodeDirectChannelReadinessChallengeV2)
	cid, _ := credentialID(credential)
	if e == nil && (v.DirectIntentID != id || v.CredentialID != cid) {
		e = failure(Protocol)
	}
	return v, e
}
func (c *Client) Prove(ctx context.Context, credential, id string, p transport.DirectChannelReadinessProofV2) (result transport.DirectChannelReadinessProofV2, resultErr error) {
	defer markUnknown(&resultErr)
	body, e := p.CanonicalBytes()
	if e != nil || !validID(p.ChallengeID) {
		return transport.DirectChannelReadinessProofV2{}, failure(Invalid)
	}
	raw, e := c.intent(ctx, credential, id, "PUT", "/readiness/proofs/"+p.ChallengeID, body, 1024, true)
	if e != nil {
		return transport.DirectChannelReadinessProofV2{}, e
	}
	v, e := decode(raw, transport.DecodeDirectChannelReadinessProofV2)
	if e == nil && v != p {
		e = failure(Protocol)
	}
	return v, e
}

type Activation struct {
	ChannelID   string    `json:"channelId"`
	ActivatedAt time.Time `json:"activatedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

func (c *Client) Activate(ctx context.Context, credential, id string) (result Activation, resultErr error) {
	defer markUnknown(&resultErr)
	raw, e := c.intent(ctx, credential, id, "POST", "/activate", nil, 1024, true)
	var v Activation
	if e != nil {
		return v, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil {
		return Activation{}, failure(Protocol)
	}
	b, _ := json.Marshal(v)
	if !bytes.Equal(b, raw) || !validBinary(v.ChannelID) || v.ActivatedAt.IsZero() || !v.ExpiresAt.After(v.ActivatedAt) {
		return Activation{}, failure(Protocol)
	}
	return v, nil
}
func (c *Client) channel(ctx context.Context, credential, channel, suffix string, v canonical, limit int64, created, mutation bool) ([]byte, error) {
	if !validBinary(channel) {
		return nil, failure(Invalid)
	}
	body, e := v.CanonicalBytes()
	if e != nil {
		return nil, failure(Invalid)
	}
	return c.call(ctx, credential, "POST", "/channels/"+channel+suffix, body, limit, created, mutation)
}
func (c *Client) Send(ctx context.Context, credential string, m transport.DirectChannelMessageV2) (result transport.DirectMessageAdmissionReceiptV2, resultErr error) {
	defer markUnknown(&resultErr)
	cid, ok := credentialID(credential)
	if !ok {
		return transport.DirectMessageAdmissionReceiptV2{}, failure(Invalid)
	}
	raw, e := c.channel(ctx, credential, m.Header.ChannelID, "/messages", m, 8192, true, true)
	if e != nil {
		return transport.DirectMessageAdmissionReceiptV2{}, e
	}
	v, e := decode(raw, transport.DecodeDirectMessageAdmissionReceiptV2)
	hash, _ := transport.DirectChannelMessageHashV2(m)
	body, _ := m.CanonicalBytes()
	if e == nil && (v.Binding.MessageID != m.Header.MessageID || v.Binding.Context.ChannelID != m.Header.ChannelID || v.Binding.Context.DescriptorHash != m.Header.DescriptorHash || v.Binding.WireHash != hash || v.Binding.WireBytes != len(body) || v.Binding.Sender.CredentialID != cid || v.Binding.Sender.Role != m.Header.SenderRole) {
		e = failure(Protocol)
	}
	return v, e
}
func (c *Client) Inbox(ctx context.Context, credential string, q transport.DirectInboxRequestV2) (transport.DirectInboxPageV2, error) {
	cid, ok := credentialID(credential)
	if !ok || cid != q.Recipient.CredentialID {
		return transport.DirectInboxPageV2{}, failure(Invalid)
	}
	raw, e := c.channel(ctx, credential, q.Context.ChannelID, "/inbox/query", q, transport.DirectInboxPageMaxBytesV2, false, false)
	if e != nil {
		return transport.DirectInboxPageV2{}, e
	}
	v, e := decode(raw, transport.DecodeDirectInboxPageV2)
	if e == nil && (v.Context != q.Context || v.Recipient != q.Recipient || len(v.Deliveries) > q.Limit) {
		e = failure(Protocol)
	}
	return v, e
}
func (c *Client) Ack(ctx context.Context, credential string, q transport.DirectMessageAckV2) (result transport.DirectMessageAckReceiptV2, resultErr error) {
	defer markUnknown(&resultErr)
	cid, ok := credentialID(credential)
	if !ok || cid != q.Binding.Recipient.CredentialID {
		return transport.DirectMessageAckReceiptV2{}, failure(Invalid)
	}
	raw, e := c.channel(ctx, credential, q.Binding.Context.ChannelID, "/messages/"+q.Binding.MessageID+"/ack", q, 8192, false, true)
	if e != nil {
		return transport.DirectMessageAckReceiptV2{}, e
	}
	v, e := decode(raw, transport.DecodeDirectMessageAckReceiptV2)
	if e == nil && v.Binding != q.Binding {
		e = failure(Protocol)
	}
	return v, e
}
func (c *Client) SenderReceipt(ctx context.Context, credential string, q transport.DirectSenderReceiptRequestV2) (transport.DirectSenderReceiptV2, error) {
	cid, ok := credentialID(credential)
	if !ok || cid != q.Binding.Sender.CredentialID {
		return transport.DirectSenderReceiptV2{}, failure(Invalid)
	}
	raw, e := c.channel(ctx, credential, q.Binding.Context.ChannelID, "/sender-receipt", q, 8192, false, false)
	if e != nil {
		return transport.DirectSenderReceiptV2{}, e
	}
	v, e := decode(raw, transport.DecodeDirectSenderReceiptV2)
	if e == nil && v.ValidateForRequest(q) != nil {
		e = failure(Protocol)
	}
	return v, e
}

func markUnknown(err *error) {
	if e, ok := (*err).(*Error); ok && e.Kind == Protocol {
		e.UnknownCommit = true
	}
}

var _ error = (*Error)(nil)
