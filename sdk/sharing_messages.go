package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

// SharingMessageRequest addresses the opposite principal of an enrolled pair.
// Reuse MessageID and identical input after an uncertain preparation/send.
type SharingMessageRequest struct {
	GrantID   string
	MessageID string
	Parts     []MessagePart
	ReplyTo   *SharingMessage
}

// PreparedSharingMessage is a durable retry handle; it contains no plaintext.
// Reconstruct handles after restart with UnresolvedSharingMessages.
type PreparedSharingMessage struct {
	MessageID string
	state     pairMessageState
}

// GrantID identifies the pair whose durable reservation this handle represents.
func (p PreparedSharingMessage) GrantID() string { return p.state.Binding.GrantID }

// CanRetry is false for incomplete or rejected reservations.
func (p PreparedSharingMessage) CanRetry() bool { return p.state.WireBytes > 0 && !p.state.Rejected }

// AbortPreparedSharingMessage releases an incomplete reservation that could
// never have been sent. Its tombstone continues to reject conflicting ID reuse.
// Finalized ciphertext requires an authoritative admission/rejection result.
func (c *Client) AbortPreparedSharingMessage(p PreparedSharingMessage) error {
	if p.MessageID != p.state.Binding.MessageID || c.principalID.Load() != p.state.Binding.PrincipalID {
		return errors.New("sdk: message abort principal mismatch")
	}
	return c.kr.rejectPairMessage(p.state.Binding, false)
}

type SharingMessageReceipt struct {
	MessageID      string     `json:"messageId"`
	RequestDigest  []byte     `json:"requestDigest"`
	Status         string     `json:"status"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt"`
}

// SharingMessage content is untrusted data from the opposite principal.
type SharingMessage struct {
	GrantID    string
	Generation int64
	Message
	CorrelationID *string
	wire          *pairMessageWire
}

// Pair causality is inside the authenticated ciphertext: the outer canonical
// wire repeats these values for relay routing but is not itself an AEAD input.
type sharingMessageProtectedBinding struct {
	GrantID              string `json:"grantId"`
	Generation           int64  `json:"generation"`
	NetworkID            string `json:"networkId"`
	ID                   string `json:"id"`
	ThreadID             string `json:"threadId"`
	CorrelationID        string `json:"correlationId"`
	Kind                 string `json:"kind"`
	SenderPrincipalID    string `json:"senderPrincipalId"`
	RecipientPrincipalID string `json:"recipientPrincipalId"`
}

type sharingMessageContent struct {
	Version int                            `json:"version"`
	Binding sharingMessageProtectedBinding `json:"binding"`
	Parts   []MessagePart                  `json:"parts"`
}

func sharingProtectedBinding(w pairMessageWire) sharingMessageProtectedBinding {
	correlation := ""
	if w.CorrelationID != nil {
		correlation = *w.CorrelationID
	}
	return sharingMessageProtectedBinding{w.GrantID, w.Generation, w.NetworkID, w.ID, w.ThreadID, correlation, w.Kind, w.SenderPrincipalID, w.RecipientPrincipalID}
}
func decodeSharingContent(plain []byte, w pairMessageWire) ([]MessagePart, error) {
	var content sharingMessageContent
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&content); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("sdk: trailing sharing message content")
	}
	canonical, err := json.Marshal(content)
	if err != nil || !bytes.Equal(canonical, plain) || content.Version != 1 || content.Binding != sharingProtectedBinding(w) {
		return nil, errors.New("sdk: authenticated sharing message binding mismatch")
	}
	if _, err := domain.EncodeMessageContent(content.Parts); err != nil {
		return nil, err
	}
	return content.Parts, nil
}

// SharingMessageQuotaError exposes the server's consent quota and retry hint.
type SharingMessageQuotaError struct {
	Limit      string     `json:"limit"`
	Maximum    int64      `json:"max"`
	ResetAt    *time.Time `json:"resetAt"`
	RetryAfter string     `json:"-"`
	StatusCode int        `json:"-"`
}

func (e *SharingMessageQuotaError) Error() string {
	return fmt.Sprintf("sdk: sharing message quota %s exceeded (maximum %d)", e.Limit, e.Maximum)
}
func sharingMessageError(err error, headers http.Header) error {
	var re *restError
	if !errors.As(err, &re) {
		return err
	}
	var body struct {
		Error string `json:"error"`
		SharingMessageQuotaError
	}
	if json.Unmarshal([]byte(re.body), &body) == nil && body.Error == "sharing_pair_quota_exceeded" && body.Limit != "" {
		body.RetryAfter = headers.Get("Retry-After")
		body.StatusCode = re.status
		return &body.SharingMessageQuotaError
	}
	return err
}

var errSharingConnectionProofRequired = errors.New("sdk: sharing pair requires proof on the current connection")

type sharingMessageSession struct {
	status              SharingPairStatus
	principal, endpoint string
	connection          int64
	key                 [32]byte
}

func (s sharingMessageSession) peer() string {
	if s.principal == s.status.IssuerPrincipalID {
		return s.status.RecipientPrincipalID
	}
	return s.status.IssuerPrincipalID
}
func (s sharingMessageSession) current(c *Client) bool {
	return c.connected.Load() && c.principalID.Load() == s.principal && c.endpointID.Load() == s.endpoint && c.connGeneration.Load() == s.connection
}
func pairMessageQuery(s sharingMessageSession) url.Values {
	return url.Values{"generation": {strconv.FormatInt(s.status.Generation, 10)}, "endpointId": {s.endpoint}}
}

// Status and local descriptor must agree before any message operation. This
// never enrolls or proves a connection; EnrollSharingPair must do that explicitly.
func (c *Client) sharingMessageSession(ctx context.Context, grant string) (sharingMessageSession, error) {
	var s sharingMessageSession
	if !validPairPathID(grant) {
		return s, errors.New("sdk: invalid sharing grant")
	}
	s.principal = c.principalID.Load()
	s.endpoint = c.endpointID.Load()
	s.connection = c.connGeneration.Load()
	credential, _ := c.credential.Load().(string)
	if !s.current(c) || s.principal == "" || s.endpoint == "" || !strings.HasPrefix(credential, "pgn_epd_v1_") {
		return s, errors.New("sdk: sharing messages require a connected endpoint credential")
	}
	cursor := ""
	for {
		page, next, err := c.ListSharingPairs(ctx, cursor)
		if err != nil {
			return s, err
		}
		for _, status := range page {
			if status.GrantID == grant {
				s.status = status
				break
			}
		}
		if s.status.GrantID != "" || next == "" {
			break
		}
		if next <= cursor {
			return s, errors.New("sdk: invalid sharing cursor")
		}
		cursor = next
	}
	if s.status.Generation < 1 {
		return s, errors.New("sdk: sharing pair not found")
	}
	generation := s.status.Generation
	if err := c.rest.do(ctx, http.MethodGet, "/sharing-pairs/"+grant+"/status?"+pairMessageQuery(s).Encode(), nil, &s.status); err != nil {
		return s, err
	}
	status := s.status
	if status.GrantID != grant || status.Generation != generation || status.State != "active" || status.ActivationEpoch == nil || (s.principal != status.IssuerPrincipalID && s.principal != status.RecipientPrincipalID) {
		return s, errors.New("sdk: sharing pair is not active for this principal")
	}
	c.cryptoMu.Lock()
	ready := c.sharingReady[status.NetworkID] > 0 && c.sharingReady[status.NetworkID] == s.connection
	c.cryptoMu.Unlock()
	if !ready || !s.current(c) {
		return s, errSharingConnectionProofRequired
	}
	p, err := c.kr.loadPendingPairEpoch(grant, uint64(status.Generation))
	if err != nil {
		return s, err
	}
	if _, issuer, recipient, err := validatePairDescriptor(p.Descriptor, status.descriptor(*status.ActivationEpoch), time.Now()); err != nil {
		return s, err
	} else if p.IssuerFingerprint != sha256.Sum256(issuer) || p.RecipientFingerprint != sha256.Sum256(recipient) {
		return s, errors.New("sdk: sharing pin mismatch")
	}
	s.key, err = c.kr.EpochKey(status.NetworkID, *status.ActivationEpoch)
	if err != nil {
		return s, err
	}
	if !bytes.Equal(s.key[:], p.EpochKey) || !s.current(c) {
		return s, errors.New("sdk: sharing activation key or connection mismatch")
	}
	return s, nil
}

func (c *Client) PrepareSharingMessage(ctx context.Context, req SharingMessageRequest) (PreparedSharingMessage, error) {
	var out PreparedSharingMessage
	s, err := c.sharingMessageSession(ctx, req.GrantID)
	if err != nil {
		return out, err
	}
	plain, err := domain.EncodeMessageContent(req.Parts)
	if err != nil {
		return out, err
	}
	if len(plain) > s.status.Limits.MaxMessageWireBytes {
		return out, &SharingMessageQuotaError{Limit: "maxMessageWireBytes", Maximum: int64(s.status.Limits.MaxMessageWireBytes), StatusCode: http.StatusRequestEntityTooLarge}
	}
	id := req.MessageID
	if id == "" {
		u, err := uuid.NewV7()
		if err != nil {
			return out, err
		}
		id = u.String()
	}
	w := pairMessageWire{Version: 1, GrantID: s.status.GrantID, Generation: s.status.Generation, NetworkID: s.status.NetworkID, ID: id, ThreadID: id, Kind: string(domain.MessageKindAsk), SenderPrincipalID: s.principal, RecipientPrincipalID: s.peer()}
	if req.ReplyTo != nil {
		previous := req.ReplyTo.wire
		if previous == nil || previous.GrantID != w.GrantID || previous.Generation != w.Generation || previous.NetworkID != w.NetworkID || previous.SenderPrincipalID != s.peer() || previous.RecipientPrincipalID != s.principal || !validPairUUID(previous.ID) || !validPairUUID(previous.ThreadID) {
			return out, errors.New("sdk: reply predecessor is outside this pair")
		}
		predecessor := previous.ID
		w.CorrelationID = &predecessor
		w.ThreadID = previous.ThreadID
		w.Kind = string(domain.MessageKindReply)
	}
	input, _ := json.Marshal([]any{w.GrantID, w.Generation, w.NetworkID, w.ID, w.ThreadID, w.CorrelationID, w.Kind, w.SenderPrincipalID, w.RecipientPrincipalID, json.RawMessage(plain)})
	b := pairMessageBinding{s.principal, w.GrantID, uint64(w.Generation), w.NetworkID, w.ID, sha256.Sum256(input)}
	state, exists, err := c.kr.reservePairMessage(b)
	out = PreparedSharingMessage{MessageID: id, state: state}
	if err != nil {
		return out, err
	}
	if exists {
		if state.Rejected {
			return out, errors.New("sdk: message reservation was rejected")
		}
		if state.WireBytes == 0 {
			return out, errors.New("sdk: unresolved reservation cannot be reencrypted")
		}
		return out, nil
	}
	if !s.current(c) {
		return out, errors.New("sdk: sharing connection changed after reservation")
	}
	w.AAD = e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: s.status.IssuerTenantID, NetworkID: w.NetworkID, ObjectType: e2ee.ObjectTypeMessage, ObjectID: w.ID, Sender: w.SenderPrincipalID, Recipient: w.RecipientPrincipalID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), KeyEpochID: *s.status.ActivationEpoch}
	protected, err := json.Marshal(sharingMessageContent{1, sharingProtectedBinding(w), req.Parts})
	if err != nil {
		return out, err
	}
	w.Envelope, err = e2ee.Encrypt(protected, s.key, w.AAD)
	if err != nil {
		return out, err
	}
	wire, err := json.Marshal(w)
	if err != nil {
		return out, err
	}
	if len(wire) > s.status.Limits.MaxMessageWireBytes {
		if err := c.kr.rejectPairMessage(b, false); err != nil {
			return out, err
		}
		out.state.Retired = true
		out.state.Rejected = true
		return out, &SharingMessageQuotaError{Limit: "maxMessageWireBytes", Maximum: int64(s.status.Limits.MaxMessageWireBytes), StatusCode: http.StatusRequestEntityTooLarge}
	}
	out.state, err = c.kr.storePairMessage(b, wire, sha256.Sum256(wire))
	return out, err
}

func validPairUUID(id string) bool {
	u, err := uuid.Parse(id)
	return err == nil && u.Version() == 7 && u.String() == id
}
func checkPrepared(s sharingMessageSession, p PreparedSharingMessage) error {
	b := p.state.Binding
	if p.MessageID != b.MessageID || !b.valid() || b.PrincipalID != s.principal || b.GrantID != s.status.GrantID || b.Generation != uint64(s.status.Generation) || b.NetworkID != s.status.NetworkID || p.state.WireBytes == 0 || p.state.Rejected {
		return errors.New("sdk: prepared sharing message binding mismatch")
	}
	return nil
}

// UnresolvedSharingMessages exposes durable retry handles, including incomplete
// reservations. Incomplete handles fail closed when sent and are never encrypted.
func (c *Client) UnresolvedSharingMessages() ([]PreparedSharingMessage, error) {
	principal := c.principalID.Load()
	records, err := c.kr.unresolvedPairMessages(principal)
	if err != nil {
		return nil, err
	}
	out := make([]PreparedSharingMessage, 0, len(records))
	for _, r := range records {
		out = append(out, PreparedSharingMessage{r.Binding.MessageID, r})
	}
	return out, nil
}

func (c *Client) GetSharingMessageReceipt(ctx context.Context, p PreparedSharingMessage) (SharingMessageReceipt, error) {
	var receipt SharingMessageReceipt
	s, err := c.sharingMessageSession(ctx, p.state.Binding.GrantID)
	if err != nil {
		return receipt, err
	}
	if err := checkPrepared(s, p); err != nil {
		return receipt, err
	}
	path := "/sharing-pairs/" + s.status.GrantID + "/messages/" + p.MessageID + "/receipt?" + pairMessageQuery(s).Encode()
	if err := c.rest.do(ctx, http.MethodGet, path, nil, &receipt); err != nil {
		return receipt, err
	}
	if !s.current(c) || receipt.MessageID != p.MessageID || !bytes.Equal(receipt.RequestDigest, p.state.WireDigest[:]) || (receipt.Status != "pending" && receipt.Status != "acknowledged") {
		return receipt, errors.New("sdk: sender receipt binding mismatch")
	}
	if err := c.kr.retirePairMessage(p.state.Binding, p.state.WireDigest, receipt.Status); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func (c *Client) SendPreparedSharingMessage(ctx context.Context, p PreparedSharingMessage) (SharingMessageReceipt, error) {
	var receipt SharingMessageReceipt
	s, err := c.sharingMessageSession(ctx, p.state.Binding.GrantID)
	if err != nil {
		return receipt, err
	}
	if err := checkPrepared(s, p); err != nil {
		return receipt, err
	}
	unlock, err := c.kr.lockPairMessages(s.principal)
	if err != nil {
		return receipt, err
	}
	records, _, err := c.kr.readPairMessageIndex(s.principal)
	unlock()
	if err != nil {
		return receipt, err
	}
	stored, ok := records[p.MessageID]
	if !ok || stored.Binding != p.state.Binding || stored.WireDigest != p.state.WireDigest {
		return receipt, errors.New("sdk: prepared reservation mismatch")
	}
	if stored.Rejected {
		return receipt, errors.New("sdk: message reservation was rejected")
	}
	if stored.Retired {
		return c.GetSharingMessageReceipt(ctx, p)
	}
	raw, err := c.kr.loadPairMessage(p.state.Binding)
	if err != nil {
		return receipt, err
	}
	if sha256.Sum256(raw) != p.state.WireDigest {
		return receipt, errors.New("sdk: prepared wire digest mismatch")
	}
	var wire pairMessageWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return receipt, err
	}
	if err := validateSharingWire(wire, s, false); err != nil {
		return receipt, err
	}
	body := struct {
		Generation           int64                   `json:"generation"`
		EndpointID           string                  `json:"endpointId"`
		ID                   string                  `json:"id"`
		ThreadID             string                  `json:"threadId"`
		CorrelationID        *string                 `json:"correlationId"`
		Kind                 string                  `json:"kind"`
		RecipientPrincipalID string                  `json:"recipientPrincipalId"`
		Envelope             e2ee.EncryptedPayloadV1 `json:"envelope"`
		AAD                  e2ee.AAD                `json:"aad"`
	}{wire.Generation, s.endpoint, wire.ID, wire.ThreadID, wire.CorrelationID, wire.Kind, wire.RecipientPrincipalID, wire.Envelope, wire.AAD}
	if !s.current(c) {
		return receipt, errors.New("sdk: sharing connection changed")
	}
	var headers http.Header
	if err := c.rest.doWithHeaders(ctx, http.MethodPost, "/sharing-pairs/"+wire.GrantID+"/messages", body, nil, &headers); err != nil {
		sendErr := sharingMessageError(err, headers)
		var quota *SharingMessageQuotaError
		if errors.As(sendErr, &quota) && ((quota.StatusCode == http.StatusRequestEntityTooLarge && quota.Limit == "maxMessageWireBytes") || (quota.StatusCode == http.StatusConflict && quota.Limit == "maxTurnsPerThread")) {
			// A prior ambiguous attempt may have been admitted. Resolve it first.
			confirmed, receiptErr := c.GetSharingMessageReceipt(ctx, p)
			if receiptErr == nil {
				return confirmed, nil
			}
			var re *restError
			if errors.As(receiptErr, &re) && re.status == http.StatusNotFound {
				// Hidden/revoked authority also returns 404. Only fresh active authority
				// for this exact binding permits treating the rejection as definitive.
				active, activeErr := c.sharingMessageSession(ctx, wire.GrantID)
				if activeErr == nil && checkPrepared(active, p) == nil && active.status.ActivationEpoch != nil && *active.status.ActivationEpoch == wire.AAD.KeyEpochID {
					if rejectErr := c.kr.rejectPairMessage(p.state.Binding, true); rejectErr != nil {
						return receipt, rejectErr
					}
				}
			}
		}
		return receipt, sendErr
	}
	return c.GetSharingMessageReceipt(ctx, p)
}

func validateSharingWire(w pairMessageWire, s sharingMessageSession, incoming bool) error {
	sender, recipient := s.principal, s.peer()
	if incoming {
		sender, recipient = recipient, sender
	}
	a := w.AAD
	created, err := time.Parse(time.RFC3339Nano, a.CreatedAt)
	if w.Version != 1 || w.GrantID != s.status.GrantID || w.Generation != s.status.Generation || w.NetworkID != s.status.NetworkID || !validPairUUID(w.ID) || !validPairUUID(w.ThreadID) || w.SenderPrincipalID != sender || w.RecipientPrincipalID != recipient || w.Envelope.Validate() != nil || w.Envelope.KeyEpochID != *s.status.ActivationEpoch || a.KeyEpochID != *s.status.ActivationEpoch || a.ProtocolVersion != transport.ProtocolVersion || a.TenantID != s.status.IssuerTenantID || a.NetworkID != w.NetworkID || a.ObjectType != e2ee.ObjectTypeMessage || a.ObjectID != w.ID || a.Sender != sender || a.Recipient != recipient || a.ProtectedContext != nil || a.NativeContent != nil || err != nil || created.UTC().Format(time.RFC3339Nano) != a.CreatedAt {
		return errors.New("sdk: sharing wire binding mismatch")
	}
	if w.Kind == string(domain.MessageKindAsk) {
		if w.ThreadID != w.ID || w.CorrelationID != nil {
			return errors.New("sdk: invalid sharing ASK thread")
		}
	} else if w.Kind == string(domain.MessageKindReply) {
		if w.CorrelationID == nil || !validPairUUID(*w.CorrelationID) {
			return errors.New("sdk: invalid sharing reply predecessor")
		}
	} else {
		return errors.New("sdk: unsupported sharing message kind")
	}
	return nil
}

func invokeSharingHandler(ctx context.Context, handler func(context.Context, SharingMessage) error, m SharingMessage) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("sdk: sharing message handler panicked")
		}
	}()
	return handler(ctx, m)
}

// ReceiveSharingMessages drains the current pending inbox. Delivery is at least
// once: handler failure or an uncertain ACK leaves the message pending.
func (c *Client) ReceiveSharingMessages(ctx context.Context, grant string, handler func(context.Context, SharingMessage) error) error {
	if handler == nil {
		return errors.New("sdk: sharing message handler is required")
	}
	s, err := c.sharingMessageSession(ctx, grant)
	if err != nil {
		return err
	}
	cursor := ""
	for {
		if !s.current(c) {
			return errors.New("sdk: sharing connection changed")
		}
		query := pairMessageQuery(s)
		query.Set("cursor", cursor)
		query.Set("limit", "50")
		var page []pairMessageWire
		var headers http.Header
		if err := c.rest.doWithHeaders(ctx, http.MethodGet, "/sharing-pairs/"+grant+"/messages/inbox?"+query.Encode(), nil, &page, &headers); err != nil {
			return err
		}
		if len(page) > 50 {
			return errors.New("sdk: sharing inbox page exceeds limit")
		}
		next := headers.Get("X-Next-Cursor")
		if next != "" && (!validPairUUID(next) || next <= cursor || len(page) == 0 || next != page[len(page)-1].ID) {
			return errors.New("sdk: invalid sharing inbox cursor")
		}
		previous := cursor
		for _, wire := range page {
			if !s.current(c) {
				return errors.New("sdk: sharing connection changed")
			}
			if wire.ID <= previous {
				return errors.New("sdk: unordered sharing inbox")
			}
			previous = wire.ID
			if err := validateSharingWire(wire, s, true); err != nil {
				return err
			}
			plain, err := e2ee.Decrypt(wire.Envelope, s.key, wire.AAD)
			if err != nil {
				return err
			}
			parts, err := decodeSharingContent(plain, wire)
			if err != nil {
				return err
			}
			created, _ := time.Parse(time.RFC3339Nano, wire.AAD.CreatedAt)
			copyWire := wire
			m := SharingMessage{GrantID: grant, Generation: wire.Generation, Message: Message{ID: wire.ID, NetworkID: wire.NetworkID, ThreadID: wire.ThreadID, Kind: wire.Kind, SenderPrincipalID: wire.SenderPrincipalID, RecipientPrincipalID: wire.RecipientPrincipalID, Parts: parts, CreatedAt: created}, CorrelationID: wire.CorrelationID, wire: &copyWire}
			if err := invokeSharingHandler(ctx, handler, m); err != nil {
				return err
			}
			if !s.current(c) {
				return errors.New("sdk: sharing connection changed before ACK")
			}
			if err := c.rest.do(ctx, http.MethodPost, "/sharing-pairs/"+grant+"/messages/"+wire.ID+"/ack", map[string]any{"generation": s.status.Generation, "endpointId": s.endpoint}, nil); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}
