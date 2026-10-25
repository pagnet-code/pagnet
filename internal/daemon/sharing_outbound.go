package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/sdk"
)

// These internal methods require their caller to establish MANUAL owner authority.
// queued means durable intent; prepared means durable SDK ciphertext; admitted
// means proven server admission; acknowledged requires an observed peer receipt.
type sharingOutboundInput struct {
	OperationID        string
	GrantID            string
	ExpectedGeneration int64
	Text               string
	ReplyToID          string
}
type sharingOutboundRecord struct {
	Input     sharingOutboundInput
	Digest    [32]byte
	MessageID string
	Phase     string
	Receipt   *sdk.SharingMessageReceipt
	Error     string
	RetryAt   time.Time
}
type sharingOutboundEndpoint interface {
	LookupSharingMessage(string) (sdk.SharingMessageLocalState, bool, error)
	AbortPreparedSharingMessage(sdk.PreparedSharingMessage) error
	PrepareSharingMessage(context.Context, sdk.SharingMessageRequest) (sdk.PreparedSharingMessage, error)
	SendPreparedSharingMessage(context.Context, sdk.PreparedSharingMessage) (sdk.SharingMessageReceipt, error)
	ImportReceivedSharingMessage(context.Context, string, []byte) (sdk.SharingMessage, error)
	ListSharingPairs(context.Context, string) ([]sdk.SharingPairStatus, string, error)
	OnSharingPairReady(func())
}

func canonicalOutboundID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.String() == id
}
func (m *sharingMailbox) outboundAAD(operation, message string) []byte {
	aad, _ := json.Marshal(struct {
		Domain                 string
		Binding                sharingMailboxBinding
		OperationID, MessageID string
	}{"sharing-outbound-v1", m.binding, operation, message})
	return aad
}
func (m *sharingMailbox) decodeOutbound(operation, message string, sealed []byte) (sharingOutboundRecord, error) {
	var out sharingOutboundRecord
	plain, err := m.unseal(sealed, m.outboundAAD(operation, message))
	if err == nil {
		err = json.Unmarshal(plain, &out)
	}
	input, _ := json.Marshal(out.Input)
	if err != nil || out.Input.OperationID != operation || out.MessageID != message || sha256.Sum256(input) != out.Digest {
		return sharingOutboundRecord{}, errors.New("sharing outbound integrity error")
	}
	return out, nil
}
func (m *sharingMailbox) outboundStatus(ctx context.Context, operation string) (sharingOutboundRecord, error) {
	var message string
	var sealed []byte
	if err := m.db.QueryRowContext(ctx, "SELECT message_id,sealed FROM outbound WHERE operation_id=?", operation).Scan(&message, &sealed); err != nil {
		return sharingOutboundRecord{}, err
	}
	return m.decodeOutbound(operation, message, sealed)
}
func (m *sharingMailbox) submitOutbound(ctx context.Context, in sharingOutboundInput) (sharingOutboundRecord, error) {
	if !canonicalOutboundID(in.OperationID) || !canonicalOutboundID(in.GrantID) || in.ExpectedGeneration <= 0 || !utf8.ValidString(in.Text) || len(in.Text) > sharingMailboxMaxRecord/2 || (in.ReplyToID != "" && !canonicalOutboundID(in.ReplyToID)) {
		return sharingOutboundRecord{}, errors.New("sharing outbound input invalid")
	}
	plainInput, _ := json.Marshal(in)
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return sharingOutboundRecord{}, err
	}
	defer tx.Rollback()
	var message string
	var sealed []byte
	err = tx.QueryRowContext(ctx, "SELECT message_id,sealed FROM outbound WHERE operation_id=?", in.OperationID).Scan(&message, &sealed)
	if err == nil {
		previous, err := m.decodeOutbound(in.OperationID, message, sealed)
		if err != nil {
			return sharingOutboundRecord{}, err
		}
		previousInput, _ := json.Marshal(previous.Input)
		if !bytes.Equal(previousInput, plainInput) {
			return sharingOutboundRecord{}, errors.New("sharing outbound operation conflict")
		}
		return previous, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return sharingOutboundRecord{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return sharingOutboundRecord{}, err
	}
	record := sharingOutboundRecord{Input: in, Digest: sha256.Sum256(plainInput), MessageID: id.String(), Phase: "queued"}
	plain, _ := json.Marshal(record)
	if len(plain) > sharingMailboxMaxRecord {
		return sharingOutboundRecord{}, errors.New("sharing outbound record full")
	}
	sealed, err = m.seal(plain, m.outboundAAD(in.OperationID, record.MessageID))
	if err != nil {
		return sharingOutboundRecord{}, err
	}
	var count, total int64
	if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(sealed)),0) FROM outbound").Scan(&count, &total); err != nil {
		return sharingOutboundRecord{}, err
	}
	if count >= sharingMailboxMaxCount || total+int64(len(sealed))+(count+1)*4096 > sharingMailboxMaxBytes {
		return sharingOutboundRecord{}, errors.New("sharing outbound journal full")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO outbound(operation_id,message_id,sealed) VALUES(?,?,?)", in.OperationID, record.MessageID, sealed); err != nil {
		return sharingOutboundRecord{}, err
	}
	return record, tx.Commit()
}
func (m *sharingMailbox) saveOutbound(ctx context.Context, record sharingOutboundRecord) error {
	plain, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(plain) > sharingMailboxMaxRecord {
		return errors.New("sharing outbound record full")
	}
	sealed, err := m.seal(plain, m.outboundAAD(record.Input.OperationID, record.MessageID))
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var total, previous int64
	if err = tx.QueryRowContext(ctx, "SELECT coalesce(sum(length(sealed)),0) FROM outbound").Scan(&total); err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, "SELECT length(sealed) FROM outbound WHERE operation_id=? AND message_id=?", record.Input.OperationID, record.MessageID).Scan(&previous); err != nil {
		return err
	}
	if total-previous+int64(len(sealed)) > sharingMailboxMaxBytes {
		return errors.New("sharing outbound journal full")
	}
	if _, err = tx.ExecContext(ctx, "UPDATE outbound SET sealed=? WHERE operation_id=? AND message_id=?", sealed, record.Input.OperationID, record.MessageID); err != nil {
		return err
	}
	return tx.Commit()
}

type sharingOutboundWorker struct {
	mailbox      *sharingMailbox
	mu           sync.Mutex
	endpoint     sharingOutboundEndpoint
	actionCancel context.CancelFunc
	actionDone   chan struct{}
	wake         chan struct{}
}

func newSharingOutboundWorker(m *sharingMailbox) *sharingOutboundWorker {
	return &sharingOutboundWorker{mailbox: m, wake: make(chan struct{}, 1)}
}
func (w *sharingOutboundWorker) signal() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}
func (w *sharingOutboundWorker) setEndpoint(endpoint sharingBridgeEndpoint) {
	w.mu.Lock()
	if w.actionCancel != nil {
		w.actionCancel()
	}
	done := w.actionDone
	w.endpoint, _ = endpoint.(sharingOutboundEndpoint)
	ep := w.endpoint
	w.mu.Unlock()
	// Retiring SDK state must wait until the previous endpoint's journal work
	// has stopped; cancellation prevents a new reservation after retirement.
	if done != nil {
		<-done
	}
	if ep != nil {
		ep.OnSharingPairReady(w.signal)
		w.signal()
	}
}
func (w *sharingOutboundWorker) submit(ctx context.Context, in sharingOutboundInput) (sharingOutboundRecord, error) {
	record, err := w.mailbox.submitOutbound(ctx, in)
	if err == nil {
		w.signal()
	}
	return record, err
}
func (w *sharingOutboundWorker) retry(ctx context.Context, id string) (sharingOutboundRecord, error) {
	record, err := w.mailbox.outboundStatus(ctx, id)
	if err == nil {
		w.signal()
	}
	return record, err
}
func (w *sharingOutboundWorker) run(ctx context.Context) {
	var timer *time.Timer
	var retry <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
		case <-retry:
		}
		if timer != nil {
			timer.Stop()
			timer = nil
		}
		retry = nil
		var earliest time.Time
		deferUntil := func(deadline time.Time) {
			if !deadline.IsZero() && (earliest.IsZero() || deadline.Before(earliest)) {
				earliest = deadline
			}
		}
		w.mu.Lock()
		ep := w.endpoint
		if ep == nil {
			w.mu.Unlock()
			continue
		}
		actionCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		w.actionCancel, w.actionDone = cancel, done
		w.mu.Unlock()
		records, err := w.pending(actionCtx)
		if err == nil {
			for _, record := range records {
				if actionCtx.Err() != nil {
					break
				}
				if time.Now().Before(record.RetryAt) {
					deferUntil(record.RetryAt)
					continue
				}
				delay, err := w.advance(actionCtx, ep, record)
				if err != nil && actionCtx.Err() == nil {
					// Preserve the last durable phase while exposing only a
					// fixed local diagnostic, never an SDK/server error body.
					current, loadErr := w.mailbox.outboundStatus(actionCtx, record.Input.OperationID)
					if loadErr == nil {
						current.RetryAt = time.Time{}
						current.Error = "action_unavailable"
						if err.Error() == "sharing outbound integrity error" {
							current.Error = "integrity_error"
						}
						if delay > 0 {
							current.Error = "quota_deferred"
							current.RetryAt = time.Now().Add(delay)
						}
						if saveErr := w.mailbox.saveOutbound(actionCtx, current); saveErr == nil && delay > 0 {
							deferUntil(current.RetryAt)
						}
					}
				}
			}
		}
		cancel()
		w.mu.Lock()
		w.actionCancel, w.actionDone = nil, nil
		close(done)
		w.mu.Unlock()
		if !earliest.IsZero() {
			timer = time.NewTimer(max(time.Until(earliest), 0))
			retry = timer.C
		}
	}
}
func (w *sharingOutboundWorker) pending(ctx context.Context) ([]sharingOutboundRecord, error) {
	rows, err := w.mailbox.db.QueryContext(ctx, "SELECT operation_id,message_id,sealed FROM outbound ORDER BY rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []sharingOutboundRecord
	for rows.Next() {
		var operation, message string
		var sealed []byte
		if err = rows.Scan(&operation, &message, &sealed); err != nil {
			return nil, err
		}
		record, err := w.mailbox.decodeOutbound(operation, message, sealed)
		if err != nil {
			return nil, err
		}
		if record.Phase == "queued" || record.Phase == "prepared" {
			records = append(records, record)
		}
	}
	return records, rows.Err()
}
func (w *sharingOutboundWorker) advance(ctx context.Context, ep sharingOutboundEndpoint, r sharingOutboundRecord) (time.Duration, error) {
	r.Error = ""
	r.RetryAt = time.Time{}
	fail := func(code string) (time.Duration, error) {
		r.Phase = "failed"
		r.Error = code
		return 0, w.mailbox.saveOutbound(ctx, r)
	}
	local, found, err := ep.LookupSharingMessage(r.MessageID)
	if err != nil {
		return 0, errors.New("sharing outbound integrity error")
	}
	if found {
		if local.Prepared.GrantID() != r.Input.GrantID || local.Prepared.Generation() != r.Input.ExpectedGeneration || local.Prepared.MessageID != r.MessageID {
			return 0, errors.New("sharing outbound integrity error")
		}
		switch local.Disposition {
		case sdk.SharingMessageAdmitted:
			r.Phase = "admitted"
			return 0, w.mailbox.saveOutbound(ctx, r)
		case sdk.SharingMessageRejected:
			return fail("rejected")
		case sdk.SharingMessageIncomplete:
			if err = ep.AbortPreparedSharingMessage(local.Prepared); err != nil {
				return 0, errors.New("sharing outbound abort unavailable")
			}
			return fail("preparation_incomplete")
		case sdk.SharingMessagePrepared:
			if !local.Prepared.CanRetry() {
				return 0, errors.New("sharing outbound integrity error")
			}
		default:
			return 0, errors.New("sharing outbound integrity error")
		}
	} else {
		if r.Phase != "queued" {
			return 0, errors.New("sharing outbound integrity error")
		}
		// Listing establishes a pair-specific byte bound before SDK preparation. The
		// SDK independently enforces the complete encrypted wire size and authority.
		var pair *sdk.SharingPairStatus
		cursor := ""
		for {
			if _, exists, lookupErr := ep.LookupSharingMessage(r.MessageID); lookupErr != nil {
				return 0, errors.New("sharing outbound integrity error")
			} else if exists {
				return w.advance(ctx, ep, r)
			}
			page, next, listErr := ep.ListSharingPairs(ctx, cursor)
			if listErr != nil {
				return outboundRetryDelay(listErr)
			}
			for _, p := range page {
				if p.GrantID == r.Input.GrantID {
					copy := p
					pair = &copy
				}
			}
			if pair != nil || next == "" {
				break
			}
			if next <= cursor {
				return 0, errors.New("sharing outbound pair unavailable")
			}
			cursor = next
		}
		if pair == nil {
			return 0, errors.New("sharing outbound pair unavailable")
		}
		if pair.Generation != r.Input.ExpectedGeneration || pair.State == "revoked" || (pair.IssuerPrincipalID != w.mailbox.binding.ServiceID && pair.RecipientPrincipalID != w.mailbox.binding.ServiceID) {
			return fail("pair_authority_changed")
		}
		if len(r.Input.Text) > pair.Limits.MaxMessageWireBytes {
			return fail("text_exceeds_pair_limit")
		}
		req := sdk.SharingMessageRequest{GrantID: r.Input.GrantID, MessageID: r.MessageID, ExpectedGeneration: r.Input.ExpectedGeneration, Parts: []sdk.MessagePart{sdk.TextPart(r.Input.Text)}}
		if r.Input.ReplyToID != "" {
			inbound, loadErr := w.mailbox.load(ctx, r.Input.GrantID, r.Input.ExpectedGeneration, r.Input.ReplyToID)
			if loadErr != nil {
				return fail("reply_unavailable")
			}
			// Import authenticates peer, direction, generation, and predecessor fields.
			if _, exists, lookupErr := ep.LookupSharingMessage(r.MessageID); lookupErr != nil {
				return 0, errors.New("sharing outbound integrity error")
			} else if exists {
				return w.advance(ctx, ep, r)
			}
			reply, importErr := ep.ImportReceivedSharingMessage(ctx, r.Input.GrantID, inbound.ReplyMaterial)
			if importErr != nil {
				return outboundRetryDelay(importErr)
			}
			peer := pair.IssuerPrincipalID
			if peer == w.mailbox.binding.ServiceID {
				peer = pair.RecipientPrincipalID
			}
			if reply.ID != r.Input.ReplyToID || reply.GrantID != r.Input.GrantID || reply.Generation != r.Input.ExpectedGeneration || reply.RecipientPrincipalID != w.mailbox.binding.ServiceID || reply.SenderPrincipalID != peer {
				return fail("reply_invalid")
			}
			req.ReplyTo = &reply
		}
		if _, exists, lookupErr := ep.LookupSharingMessage(r.MessageID); lookupErr != nil {
			return 0, errors.New("sharing outbound integrity error")
		} else if exists {
			return w.advance(ctx, ep, r)
		}
		prepared, prepareErr := ep.PrepareSharingMessage(ctx, req)
		if prepareErr != nil {
			return w.observeFailure(ctx, ep, r, prepareErr)
		}
		local.Prepared = prepared
	}
	r.Phase = "prepared"
	if err = w.mailbox.saveOutbound(ctx, r); err != nil {
		return 0, err
	}
	// Refresh local disposition immediately before sending: admission can retire
	// the spool even when a preceding daemon receipt commit was lost.
	fresh, exists, err := ep.LookupSharingMessage(r.MessageID)
	if err != nil || !exists {
		return 0, errors.New("sharing outbound integrity error")
	}
	if fresh.Disposition != sdk.SharingMessagePrepared {
		return w.advance(ctx, ep, r)
	}
	receipt, sendErr := ep.SendPreparedSharingMessage(ctx, fresh.Prepared)
	if sendErr != nil {
		return w.observeFailure(ctx, ep, r, sendErr)
	}
	r.Receipt = &receipt
	r.Phase = "admitted"
	if receipt.Status == "acknowledged" && receipt.AcknowledgedAt != nil {
		r.Phase = "acknowledged"
	}
	return 0, w.mailbox.saveOutbound(ctx, r)
}

// Network errors can arrive after the SDK has durably recorded admission,
// rejection, or ciphertext. Observe that evidence before exposing local status.
func (w *sharingOutboundWorker) observeFailure(ctx context.Context, ep sharingOutboundEndpoint, r sharingOutboundRecord, actionErr error) (time.Duration, error) {
	local, found, err := ep.LookupSharingMessage(r.MessageID)
	if err != nil {
		return 0, errors.New("sharing outbound integrity error")
	}
	if !found && r.Phase == "prepared" {
		return 0, errors.New("sharing outbound integrity error")
	}
	var quota *sdk.SharingMessageQuotaError
	if !found && r.Phase == "queued" && errors.As(actionErr, &quota) && quota.StatusCode == 413 && quota.Limit == "maxMessageWireBytes" {
		r.Phase = "failed"
		r.Error = "text_exceeds_pair_limit"
		return 0, w.mailbox.saveOutbound(ctx, r)
	}
	if found {
		if local.Disposition != sdk.SharingMessagePrepared {
			return w.advance(ctx, ep, r)
		}
		if local.Prepared.GrantID() != r.Input.GrantID || local.Prepared.Generation() != r.Input.ExpectedGeneration || !local.Prepared.CanRetry() {
			return 0, errors.New("sharing outbound integrity error")
		}
		r.Phase = "prepared"
		if err = w.mailbox.saveOutbound(ctx, r); err != nil {
			return 0, err
		}
	}
	return outboundRetryDelay(actionErr)
}

func outboundRetryDelay(err error) (time.Duration, error) {
	var quota *sdk.SharingMessageQuotaError
	if !errors.As(err, &quota) || quota.StatusCode != 429 {
		return 0, errors.New("sharing outbound action unavailable")
	}
	delay := time.Second
	if seconds, e := strconv.ParseInt(quota.RetryAfter, 10, 64); e == nil && seconds > 0 {
		delay = time.Duration(min(seconds, int64((1<<63-1)/time.Second))) * time.Second
	} else if deadline, e := http.ParseTime(quota.RetryAfter); e == nil {
		delay = max(delay, time.Until(deadline))
	}
	if quota.ResetAt != nil {
		delay = max(delay, time.Until(*quota.ResetAt))
	}
	return delay, errors.New("sharing outbound quota deferred")
}
