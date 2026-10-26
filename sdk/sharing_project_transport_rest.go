package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// SharingProjectMessageReceipt binds admission to the exact durable wire.
type SharingProjectMessageReceipt struct {
	MessageID      string     `json:"messageId"`
	AdmissionSeq   int64      `json:"admissionSeq"`
	RequestDigest  []byte     `json:"requestDigest"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"createdAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt"`
}

// SharingProjectInboxPage leaves processing, decryption and acknowledgment to
// the caller. Messages may be delivered again until explicitly acknowledged.
type SharingProjectInboxPage struct {
	Messages   []json.RawMessage
	NextCursor string
}

// SharingProjectMessageQuotaError exposes project limits and retry hints.
type SharingProjectMessageQuotaError struct {
	Limit      string     `json:"limit"`
	Maximum    int64      `json:"max"`
	ResetAt    *time.Time `json:"resetAt"`
	RetryAfter string     `json:"-"`
	StatusCode int        `json:"-"`
}

func (e *SharingProjectMessageQuotaError) Error() string {
	return fmt.Sprintf("sdk: sharing project message quota %s exceeded (maximum %d)", e.Limit, e.Maximum)
}
func projectTransportError(err error, headers http.Header) error {
	var re *restError
	if !errors.As(err, &re) || (re.status != 413 && re.status != 409 && re.status != 429) {
		return err
	}
	var body struct {
		Error string `json:"error"`
		SharingProjectMessageQuotaError
	}
	if json.Unmarshal([]byte(re.body), &body) == nil && body.Error == "sharing_project_quota_exceeded" && body.Limit != "" {
		body.StatusCode, body.RetryAfter = re.status, headers.Get("Retry-After")
		return &body.SharingProjectMessageQuotaError
	}
	return err
}

type projectTransportSession struct {
	endpoint, principal string
	generation          int64
}

func (s projectTransportSession) current(c *Client) error {
	if !c.connected.Load() || c.endpointID.Load() != s.endpoint || c.principalID.Load() != s.principal || c.connGeneration.Load() != s.generation {
		return errors.New("sdk: project endpoint connection changed")
	}
	return nil
}
func (c *Client) projectTransportSession(ctx context.Context, project string) (projectTransportSession, error) {
	s := projectTransportSession{c.endpointID.Load(), c.principalID.Load(), c.connGeneration.Load()}
	if err := c.projectEnrollmentConnected(); err != nil {
		return s, err
	}
	d, hash, err := c.projectMessageDescriptor(project)
	if err != nil {
		return s, err
	}
	status, err := c.SharingProjectStatus(ctx, project)
	if err != nil {
		return s, err
	}
	if err = validateSharingProjectDescriptor(status, project, s.principal, c.identityPub, d.PolicyHash, time.Now()); err != nil {
		return s, err
	}
	if !bytes.Equal(status.DescriptorHash, hash) {
		return s, errors.New("sdk: sharing project descriptor changed")
	}
	if !status.EndpointProved {
		enrollment, err := c.EnrollSharingProjectWithPolicyHash(ctx, project, d.PolicyHash)
		if err != nil {
			return s, err
		}
		status = enrollment.Status
		if !bytes.Equal(status.DescriptorHash, hash) {
			return s, errors.New("sdk: sharing project descriptor changed")
		}
	}
	if status.State != "active" || !status.EndpointProved {
		return s, errors.New("sdk: project messaging requires active enrollment and current endpoint proof")
	}
	return s, s.current(c)
}
func projectMessagesPath(project string) string {
	return "/sharing-project-transports/" + project + "/messages"
}
func validateProjectReceipt(receipt SharingProjectMessageReceipt, prepared PreparedSharingProjectMessage) error {
	digest := sha256.Sum256(prepared.Wire)
	if receipt.MessageID != prepared.ID || receipt.AdmissionSeq <= 0 || !bytes.Equal(receipt.RequestDigest, digest[:]) || receipt.CreatedAt.IsZero() || (receipt.Status != "pending" && receipt.Status != "acknowledged") {
		return errors.New("sdk: project message receipt binding mismatch")
	}
	return nil
}
func (c *Client) projectMessageReceipt(ctx context.Context, project string, record projectMessageRecord, s projectTransportSession) (SharingProjectMessageReceipt, error) {
	var receipt SharingProjectMessageReceipt
	if err := s.current(c); err != nil {
		return receipt, err
	}
	err := c.rest.do(ctx, http.MethodGet, projectMessagesPath(project)+"/"+record.Reservation.Header.ID+"/receipt?"+url.Values{"endpointId": {s.endpoint}}.Encode(), nil, &receipt)
	if err == nil {
		err = validateProjectRecordReceipt(receipt, record)
	}
	if err == nil {
		err = s.current(c)
	}
	if err == nil {
		err = c.kr.retireProjectMessage(s.principal, c.identityPriv, project, record.Reservation.Header.ID, receipt)
	}
	return receipt, err
}

// SendPreparedSharingProjectMessage loads the immutable wire from the spool.
// An ambiguous response is reconciled with a sender receipt; if reconciliation
// fails, a later explicit retry uses the same message ID and encryption bytes.
// Confirmed admission retires ciphertext while retaining authenticated thread evidence.
func (c *Client) SendPreparedSharingProjectMessage(ctx context.Context, project, messageID string) (SharingProjectMessageReceipt, error) {
	var receipt SharingProjectMessageReceipt
	prepared, err := c.LoadPreparedSharingProjectMessage(project, messageID)
	if err != nil {
		return receipt, err
	}
	s, err := c.projectTransportSession(ctx, project)
	if err != nil {
		return receipt, err
	}
	var headers http.Header
	err = c.rest.doWithHeaders(ctx, http.MethodPost, projectMessagesPath(project), struct {
		EndpointID string          `json:"endpointId"`
		Wire       json.RawMessage `json:"wire"`
	}{s.endpoint, prepared.Wire}, &receipt, &headers)
	if err != nil {
		var re *restError
		if !errors.As(err, &re) && !errors.Is(err, ErrCredentialDead) {
			record, loadErr := c.kr.loadProjectMessageBinding(s.principal, c.identityPriv, messageID)
			if loadErr == nil {
				if reconciled, receiptErr := c.projectMessageReceipt(ctx, project, record, s); receiptErr == nil {
					return reconciled, nil
				}
			}
		}
		return receipt, projectTransportError(err, headers)
	}
	if err = s.current(c); err == nil {
		err = validateProjectReceipt(receipt, prepared)
	}
	if err == nil {
		err = c.kr.retireProjectMessage(s.principal, c.identityPriv, project, messageID, receipt)
	}
	return receipt, err
}

// SharingProjectMessageReceipt reconciles an uncertain send using the exact
// locally authenticated prepared/admitted binding, including after project expiry
// or revocation. Only the current authenticated sender endpoint can request it.
func (c *Client) SharingProjectMessageReceipt(ctx context.Context, project, messageID string) (SharingProjectMessageReceipt, error) {
	var receipt SharingProjectMessageReceipt
	if !projectUUID(project, false) || !projectUUID(messageID, true) || c.kr == nil {
		return receipt, errors.New("sdk: invalid project receipt identity")
	}
	if err := c.projectEnrollmentConnected(); err != nil {
		return receipt, err
	}
	s := projectTransportSession{c.endpointID.Load(), c.principalID.Load(), c.connGeneration.Load()}
	record, err := c.kr.loadProjectMessageBinding(s.principal, c.identityPriv, messageID)
	if err != nil {
		return receipt, err
	}
	if record.Reservation.Header.ProjectID != project || record.Reservation.Header.SenderPrincipalID != s.principal {
		return receipt, errors.New("sdk: local project receipt binding mismatch")
	}
	return c.projectMessageReceipt(ctx, project, record, s)
}

// SharingProjectInbox fetches one page without acknowledging any message.
// Pass each wire to DecryptSharingProjectMessage with its verified predecessor.
func (c *Client) SharingProjectInbox(ctx context.Context, project, cursor string, limit int) (SharingProjectInboxPage, error) {
	var page SharingProjectInboxPage
	if limit < 0 || limit > 100 {
		return page, errors.New("sdk: invalid project inbox limit")
	}
	if cursor != "" {
		if n, err := strconv.ParseInt(cursor, 10, 64); err != nil || n < 0 || strconv.FormatInt(n, 10) != cursor {
			return page, errors.New("sdk: invalid project inbox cursor")
		}
	}
	s, err := c.projectTransportSession(ctx, project)
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
	err = c.rest.doWithHeaders(ctx, http.MethodGet, projectMessagesPath(project)+"?"+query.Encode(), nil, &page.Messages, &headers)
	if err != nil {
		return page, projectTransportError(err, headers)
	}
	if err = s.current(c); err != nil {
		return SharingProjectInboxPage{}, err
	}
	d, hash, err := c.projectMessageDescriptor(project)
	if err != nil {
		return SharingProjectInboxPage{}, err
	}
	for _, raw := range page.Messages {
		w, _, _, err := parseSharingProjectMessage(raw, d, hash)
		if err != nil {
			return SharingProjectInboxPage{}, err
		}
		if w.RecipientPrincipalID != s.principal {
			return SharingProjectInboxPage{}, errors.New("sdk: project inbox recipient mismatch")
		}
	}
	page.NextCursor = headers.Get("X-Next-Cursor")
	if page.NextCursor != "" {
		if n, err := strconv.ParseInt(page.NextCursor, 10, 64); err != nil || n < 0 || strconv.FormatInt(n, 10) != page.NextCursor {
			return SharingProjectInboxPage{}, errors.New("sdk: invalid project inbox next cursor")
		}
	}
	return page, nil
}

// AckSharingProjectMessage must be called only after the caller successfully
// processes a decrypted message. A failed ACK leaves it available for redelivery.
func (c *Client) AckSharingProjectMessage(ctx context.Context, project, messageID string) error {
	if !projectUUID(messageID, true) {
		return errors.New("sdk: invalid project message ID")
	}
	s, err := c.projectTransportSession(ctx, project)
	if err != nil {
		return err
	}
	var headers http.Header
	err = c.rest.doWithHeaders(ctx, http.MethodPost, projectMessagesPath(project)+"/"+messageID+"/ack", map[string]string{"endpointId": s.endpoint}, nil, &headers)
	if err != nil {
		return projectTransportError(err, headers)
	}
	return s.current(c)
}
