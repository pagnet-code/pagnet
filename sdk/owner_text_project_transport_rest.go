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
)

// OwnerTextProjectInboxPage leaves processing, decryption and acknowledgment to
// the caller. Messages may be delivered again until explicitly acknowledged.
type OwnerTextProjectInboxPage struct {
	Messages   []json.RawMessage
	NextCursor string
}

// OwnerTextProjectMessageQuotaError exposes project limits and retry hints.
type OwnerTextProjectMessageQuotaError struct {
	Limit      string     `json:"limit"`
	Maximum    int64      `json:"max"`
	ResetAt    *time.Time `json:"resetAt"`
	RetryAfter string     `json:"-"`
	StatusCode int        `json:"-"`
}

func (e *OwnerTextProjectMessageQuotaError) Error() string {
	return fmt.Sprintf("sdk: owner text project message quota %s exceeded (maximum %d)", e.Limit, e.Maximum)
}
func ownerTextProjectTransportError(err error, headers http.Header) error {
	var re *restError
	if !errors.As(err, &re) || (re.status != 413 && re.status != 409 && re.status != 429) {
		return err
	}
	var body struct {
		Error string `json:"error"`
		OwnerTextProjectMessageQuotaError
	}
	if json.Unmarshal([]byte(re.body), &body) == nil && body.Error == "sharing_project_quota_exceeded" && body.Limit != "" {
		body.StatusCode, body.RetryAfter = re.status, headers.Get("Retry-After")
		return &body.OwnerTextProjectMessageQuotaError
	}
	return err
}

type ownerTextProjectTransportSession struct {
	endpoint, principal, credential string
	generation                      int64
}

func (s ownerTextProjectTransportSession) current(c *Client) error {
	credential, _ := c.credential.Load().(string)
	if !c.connected.Load() || c.endpointID.Load() != s.endpoint || c.principalID.Load() != s.principal || c.connGeneration.Load() != s.generation || credential != s.credential {
		return errors.New("sdk: owner text endpoint connection changed")
	}
	return nil
}
func (c *Client) ownerTextProjectTransportSession(ctx context.Context, project string) (ownerTextProjectTransportSession, error) {
	credential, _ := c.credential.Load().(string)
	s := ownerTextProjectTransportSession{c.endpointID.Load(), c.principalID.Load(), credential, c.connGeneration.Load()}
	if err := c.ownerTextProjectEnrollmentConnected(); err != nil {
		return s, err
	}
	d, hash, err := c.ownerTextMessageDescriptor(project)
	if err != nil {
		return s, err
	}
	installation := ""
	for _, member := range d.Roster {
		if member.PrincipalID == s.principal {
			installation = member.InstallationID
		}
	}
	status, err := c.OwnerTextProjectStatus(ctx, project)
	if err != nil {
		return s, err
	}
	validate := func() error {
		if err := s.current(c); err != nil {
			return err
		}
		if err := validateOwnerTextProjectStatus(status, project, s.principal, installation); err != nil {
			return err
		}
		if err := validateOwnerTextProjectDescriptor(status, project, s.principal, installation, c.identityPub, d.PolicyHash, time.Now()); err != nil {
			return err
		}
		if !bytes.Equal(status.DescriptorHash, hash) {
			return errors.New("sdk: owner text project descriptor changed")
		}
		return nil
	}
	if err = validate(); err != nil {
		return s, err
	}
	if !status.EndpointProved {
		enrollment, err := c.EnrollOwnerTextProjectWithPolicyHash(ctx, project, installation, d.PolicyHash)
		if err != nil {
			return s, err
		}
		status = enrollment.Status
		if err = validate(); err != nil {
			return s, err
		}
	}
	if status.State != "active" || !status.Ready || !status.EndpointProved {
		return s, errors.New("sdk: owner text messaging requires active enrollment and current endpoint proof")
	}
	return s, s.current(c)
}
func ownerTextProjectMessagesPath(project string) string {
	return "/owner-text-project-transports/" + project + "/messages"
}
func validateOwnerTextProjectReceipt(receipt OwnerTextProjectMessageReceipt, prepared PreparedOwnerTextProjectMessage) error {
	digest := sha256.Sum256(prepared.Wire)
	if receipt.MessageID != prepared.ID || receipt.AdmissionSeq <= 0 || !bytes.Equal(receipt.RequestDigest, digest[:]) || !validOwnerTextProjectReceiptTimes(receipt) {
		return errors.New("sdk: owner text project message receipt binding mismatch")
	}
	return nil
}
func (c *Client) ownerTextProjectMessageReceipt(ctx context.Context, project string, record ownerTextProjectMessageRecord, s ownerTextProjectTransportSession) (OwnerTextProjectMessageReceipt, error) {
	var receipt OwnerTextProjectMessageReceipt
	if err := s.current(c); err != nil {
		return receipt, err
	}
	if _, err := c.ownerTextProjectTransportSession(ctx, project); err != nil {
		return receipt, err
	}
	d, hash, err := c.ownerTextMessageDescriptor(project)
	if err != nil {
		return receipt, err
	}
	if record.Reservation.Header.ProjectID != project || record.Reservation.Header.DescriptorHash != fmt.Sprintf("%x", hash) || record.Reservation.Header.NetworkID != d.NetworkID || record.Reservation.Header.PolicyHash != d.PolicyHash {
		return receipt, errors.New("sdk: owner text receipt descriptor binding mismatch")
	}
	if err := s.current(c); err != nil {
		return receipt, err
	}
	err = c.rest.do(ctx, http.MethodGet, ownerTextProjectMessagesPath(project)+"/"+record.Reservation.Header.ID+"/receipt?"+url.Values{"endpointId": {s.endpoint}}.Encode(), nil, &receipt)
	if err == nil {
		err = validateOwnerTextProjectRecordReceipt(receipt, record)
	}
	if err == nil {
		err = s.current(c)
	}
	if err == nil {
		err = c.kr.retireOwnerTextProjectMessage(s.principal, c.identityPriv, project, record.Reservation.Header.ID, receipt)
	}
	return receipt, err
}

// SendPreparedOwnerTextProjectMessage loads the immutable wire from the spool.
// An ambiguous response is reconciled with a sender receipt; if reconciliation
// fails, a later explicit retry uses the same message ID and encryption bytes.
// Confirmed admission retires ciphertext while retaining authenticated thread evidence.
func (c *Client) SendPreparedOwnerTextProjectMessage(ctx context.Context, project, messageID string) (OwnerTextProjectMessageReceipt, error) {
	var receipt OwnerTextProjectMessageReceipt
	prepared, err := c.LoadPreparedOwnerTextProjectMessage(project, messageID)
	if err != nil {
		return receipt, err
	}
	s, err := c.ownerTextProjectTransportSession(ctx, project)
	if err != nil {
		return receipt, err
	}
	var headers http.Header
	if err = s.current(c); err != nil {
		return receipt, err
	}
	err = c.rest.ownerTextProjectRawPost(ctx, ownerTextProjectMessagesPath(project)+"?"+url.Values{"endpointId": {s.endpoint}}.Encode(), prepared.Wire, &receipt, &headers)
	if err != nil {
		var re *restError
		if (!errors.As(err, &re) || re.status >= 500 || re.status == http.StatusRequestTimeout) && !errors.Is(err, ErrCredentialDead) {
			record, loadErr := c.kr.loadOwnerTextProjectMessageBinding(s.principal, c.identityPriv, messageID)
			if loadErr == nil {
				if reconciled, receiptErr := c.ownerTextProjectMessageReceipt(ctx, project, record, s); receiptErr == nil {
					return reconciled, nil
				}
			}
		}
		return receipt, ownerTextProjectTransportError(err, headers)
	}
	if err = s.current(c); err == nil {
		err = validateOwnerTextProjectReceipt(receipt, prepared)
	}
	if err == nil {
		err = c.kr.retireOwnerTextProjectMessage(s.principal, c.identityPriv, project, messageID, receipt)
	}
	return receipt, err
}

// OwnerTextProjectMessageReceipt reconciles an uncertain send against its
// authenticated local binding. The project and endpoint proof must remain live;
// receipts are not available after revocation or expiry.
func (c *Client) OwnerTextProjectMessageReceipt(ctx context.Context, project, messageID string) (OwnerTextProjectMessageReceipt, error) {
	var receipt OwnerTextProjectMessageReceipt
	if !projectUUID(project, false) || !projectUUID(messageID, true) || c.kr == nil {
		return receipt, errors.New("sdk: invalid owner text receipt identity")
	}
	s, err := c.ownerTextProjectTransportSession(ctx, project)
	if err != nil {
		return receipt, err
	}
	record, err := c.kr.loadOwnerTextProjectMessageBinding(s.principal, c.identityPriv, messageID)
	if err != nil {
		return receipt, err
	}
	if record.Reservation.Header.ProjectID != project || record.Reservation.Header.SenderPrincipalID != s.principal {
		return receipt, errors.New("sdk: local owner text receipt binding mismatch")
	}
	return c.ownerTextProjectMessageReceipt(ctx, project, record, s)
}

// OwnerTextProjectInbox fetches one page without acknowledging any message.
// Pass each wire to DecryptOwnerTextProjectMessage with its verified predecessor.
func (c *Client) OwnerTextProjectInbox(ctx context.Context, project, cursor string, limit int) (OwnerTextProjectInboxPage, error) {
	var page OwnerTextProjectInboxPage
	if limit < 0 || limit > 100 {
		return page, errors.New("sdk: invalid project inbox limit")
	}
	if cursor != "" {
		if n, err := strconv.ParseInt(cursor, 10, 64); err != nil || n < 1 || strconv.FormatInt(n, 10) != cursor {
			return page, errors.New("sdk: invalid project inbox cursor")
		}
	}
	s, err := c.ownerTextProjectTransportSession(ctx, project)
	if err != nil {
		return page, err
	}
	query := url.Values{"endpointId": {s.endpoint}}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	var headers http.Header
	err = c.rest.doWithHeaders(ctx, http.MethodGet, ownerTextProjectMessagesPath(project)+"?"+query.Encode(), nil, &page.Messages, &headers)
	if err != nil {
		return page, ownerTextProjectTransportError(err, headers)
	}
	if err = s.current(c); err != nil {
		return OwnerTextProjectInboxPage{}, err
	}
	d, hash, err := c.ownerTextMessageDescriptor(project)
	if err != nil {
		return OwnerTextProjectInboxPage{}, err
	}
	effectiveLimit := limit
	if effectiveLimit == 0 {
		effectiveLimit = 50
	}
	if len(page.Messages) > effectiveLimit {
		return OwnerTextProjectInboxPage{}, errors.New("sdk: owner text inbox exceeds requested page size")
	}
	for _, raw := range page.Messages {
		w, _, _, err := parseOwnerTextProjectMessage(raw, d, hash)
		if err != nil {
			return OwnerTextProjectInboxPage{}, err
		}
		if w.RecipientPrincipalID != s.principal {
			return OwnerTextProjectInboxPage{}, errors.New("sdk: project inbox recipient mismatch")
		}
	}
	page.NextCursor = headers.Get("X-Next-Cursor")
	if page.NextCursor != "" {
		if n, err := strconv.ParseInt(page.NextCursor, 10, 64); err != nil || n < 1 || strconv.FormatInt(n, 10) != page.NextCursor {
			return OwnerTextProjectInboxPage{}, errors.New("sdk: invalid project inbox next cursor")
		}
	}
	if page.NextCursor != "" {
		next, _ := strconv.ParseInt(page.NextCursor, 10, 64)
		previous, _ := strconv.ParseInt(cursor, 10, 64)
		if next <= previous || len(page.Messages) == 0 {
			return OwnerTextProjectInboxPage{}, errors.New("sdk: owner text inbox cursor did not advance")
		}
	}
	if err = s.current(c); err != nil {
		return OwnerTextProjectInboxPage{}, err
	}
	return page, nil
}

// AckOwnerTextProjectMessage must be called only after the caller successfully
// processes a decrypted message. A failed ACK leaves it available for redelivery.
func (c *Client) AckOwnerTextProjectMessage(ctx context.Context, project, messageID string) error {
	if !projectUUID(messageID, true) {
		return errors.New("sdk: invalid project message ID")
	}
	s, err := c.ownerTextProjectTransportSession(ctx, project)
	if err != nil {
		return err
	}
	var headers http.Header
	err = c.rest.doWithHeaders(ctx, http.MethodPost, ownerTextProjectMessagesPath(project)+"/"+messageID+"/ack?"+url.Values{"endpointId": {s.endpoint}}.Encode(), nil, nil, &headers)
	if err != nil {
		return ownerTextProjectTransportError(err, headers)
	}
	return s.current(c)
}

func validOwnerTextProjectReceiptTimes(receipt OwnerTextProjectMessageReceipt) bool {
	_, offset := receipt.CreatedAt.Zone()
	if receipt.CreatedAt.IsZero() || offset != 0 {
		return false
	}
	if receipt.Status == "pending" {
		return receipt.AcknowledgedAt == nil
	}
	if receipt.Status != "acknowledged" || receipt.AcknowledgedAt == nil || receipt.AcknowledgedAt.IsZero() || receipt.AcknowledgedAt.Before(receipt.CreatedAt) {
		return false
	}
	_, offset = receipt.AcknowledgedAt.Zone()
	return offset == 0
}

// ownerTextProjectRawPost preserves the spool's exact canonical wire bytes.
func (r *restClient) ownerTextProjectRawPost(ctx context.Context, path string, wire []byte, out any, headers *http.Header) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.base+path, bytes.NewReader(wire))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.cred())
	req.Header.Set("User-Agent", r.userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return fmt.Errorf("sdk: REST POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if headers != nil {
		*headers = resp.Header.Clone()
	}
	const maxResponseBytes = 16 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("sdk: read REST response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return fmt.Errorf("sdk: REST response exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		re := &restError{status: resp.StatusCode, body: strings.TrimSpace(string(raw))}
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("%w: %s", ErrCredentialDead, re.Error())
		}
		return re
	}
	if out != nil && len(raw) > 0 {
		if err = json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("sdk: decode REST response: %w", err)
		}
	}
	return nil
}
