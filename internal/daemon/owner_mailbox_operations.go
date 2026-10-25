package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/pagnet-code/pagnet/transport"
)

// Offsets are bytes. Read chunks end at a UTF-8 boundary and their JSON worst
// case (six bytes per input byte) fits comfortably inside one encrypted frame.
const ownerMailboxReadBytes = 8 << 10

type ownerMailboxRequest struct {
	Version            int    `json:"version"`
	RequestID          string `json:"requestId"`
	Action             string `json:"action"`
	OperationID        string `json:"operationId"`
	GrantID            string `json:"grantId"`
	ExpectedGeneration int64  `json:"expectedGeneration"`
	Text               string `json:"text"`
	ReplyToID          string `json:"replyToId"`
	MessageID          string `json:"messageId"`
	Offset             int    `json:"offset"`
	Limit              int    `json:"limit"`
	Cursor             string `json:"cursor"`
}
type ownerMailboxResponse struct {
	Version   int    `json:"version"`
	RequestID string `json:"requestId"`
	Code      string `json:"code"`
	Data      any    `json:"data,omitempty"`
}

// Called with the socket lock held. Only the execution goroutine owns request
// plaintext; directional keys remain under the connection lock.
func (c *ownerMailboxConnection) operation(env transport.Envelope, p transport.HostSessionPayload) {
	var op transport.OwnerMailboxOperationPayload
	if env.DecodePayload(&op) != nil {
		for id := range c.sessions {
			c.erase(id)
		}
		return
	}
	s := c.sessions[op.SessionID]
	if s == nil {
		return
	}
	if op.Protocol != transport.OwnerMailboxProtocolV1 || op.RequestID == "" || len(op.RequestID) > 128 ||
		len(op.Ciphertext) < 16 || len(op.Ciphertext) > e2ee.OwnerMailboxMaxPlaintext+16 || s.busy ||
		op.Sequence != s.clientSequence || !sameOwnerMailboxAuthority(s.authority, p) ||
		!ownerMailboxMatches(s.descriptor, p) || !c.daemon.sharingBridges.ownerMailboxReady(s.descriptor, p, time.Now()) || s.ctx.Err() != nil {
		c.erase(op.SessionID)
		return
	}
	plain, err := e2ee.OpenOwnerMailboxFrame(s.descriptor, s.keys.ClientToHost[:], e2ee.OwnerMailboxClientToHost, op.Sequence, op.Ciphertext)
	if err != nil {
		c.erase(op.SessionID)
		return
	}
	var req ownerMailboxRequest
	err = json.Unmarshal(plain, &req)
	clear(plain)
	if err != nil || req.Version != 1 || req.RequestID != op.RequestID {
		c.erase(op.SessionID)
		return
	}
	s.clientSequence++
	s.busy = true
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	bridge := c.daemon.sharingBridges
	bridge.mu.Lock()
	if !bridge.ownerMailboxReadyLocked(s.descriptor, p, time.Now()) {
		bridge.mu.Unlock()
		cancel()
		c.erase(op.SessionID)
		return
	}
	active := bridge.active[s.descriptor.InstallationID]
	worker := bridge.outbound[s.descriptor.InstallationID]
	if worker != nil && worker.mailbox.binding != active.binding {
		bridge.mu.Unlock()
		cancel()
		c.erase(op.SessionID)
		return
	}
	bridge.mu.Unlock()
	go func() {
		defer cancel()
		// Socket close and endpoint retirement cancel in-flight I/O without polling.
		done := make(chan struct{})
		go func() {
			select {
			case <-c.native.closed:
				cancel()
			case <-active.endpoint.Done():
				cancel()
			case <-ctx.Done():
			case <-done:
			}
		}()
		response := ownerMailboxResponse{Version: 1, RequestID: req.RequestID, Code: "unavailable"}
		if worker != nil {
			response.Data, err = executeOwnerMailbox(ctx, worker, active.endpoint, req)
			if err == nil {
				response.Code = "ok"
			}
		}
		close(done)
		if err != nil {
			response.Data = nil
			response.Code = "operation_failed"
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.sessions[op.SessionID] != s {
			return
		}
		current, authErr := c.native.AuthenticatedNativeHostSession()
		if ctx.Err() != nil || authErr != nil || !sameOwnerMailboxAuthority(s.authority, current) || !bridge.ownerMailboxReady(s.descriptor, current, time.Now()) {
			c.erase(op.SessionID)
			return
		}
		raw, marshalErr := json.Marshal(response)
		if marshalErr != nil || len(raw) > e2ee.OwnerMailboxMaxPlaintext {
			raw, _ = json.Marshal(ownerMailboxResponse{Version: 1, RequestID: req.RequestID, Code: "response_too_large"})
		}
		ciphertext, sealErr := e2ee.SealOwnerMailboxFrame(s.descriptor, s.keys.HostToClient[:], e2ee.OwnerMailboxHostToClient, s.hostSequence, raw)
		clear(raw)
		if sealErr != nil {
			c.erase(op.SessionID)
			return
		}
		result := transport.OwnerMailboxResultPayload{Protocol: transport.OwnerMailboxProtocolV1, SessionID: op.SessionID, RequestID: req.RequestID, Sequence: s.hostSequence, Ciphertext: ciphertext}
		s.hostSequence++
		if c.send(transport.MsgOwnerMailboxResult, result) != nil {
			c.erase(op.SessionID)
			return
		}
		s.busy = false
	}()
}

func executeOwnerMailbox(ctx context.Context, w *sharingOutboundWorker, endpoint sharingBridgeEndpoint, r ownerMailboxRequest) (any, error) {
	switch r.Action {
	case "pairs":
		ep, ok := endpoint.(interface {
			ListSharingPairs(context.Context, string) ([]sdk.SharingPairStatus, string, error)
		})
		if !ok || len(r.Cursor) > 4096 {
			return nil, errors.New("unavailable")
		}
		pairs, next, err := ep.ListSharingPairs(ctx, r.Cursor)
		if err != nil {
			return nil, err
		}
		type pair struct {
			GrantID    string                `json:"grantId"`
			Generation int64                 `json:"generation"`
			State      string                `json:"state"`
			ExpiresAt  string                `json:"expiresAt"`
			Limits     sdk.SharingPairLimits `json:"limits"`
		}
		out := make([]pair, 0, len(pairs))
		for _, p := range pairs {
			out = append(out, pair{p.GrantID, p.Generation, p.State, p.ExpiresAt, p.Limits})
		}
		return struct {
			Pairs  []pair `json:"pairs"`
			Cursor string `json:"cursor"`
		}{out, next}, nil
	case "inbox", "outbox":
		return w.mailbox.ownerList(ctx, r.Cursor, r.Limit, r.Action == "outbox")
	case "read":
		if r.Offset < 0 || r.ExpectedGeneration <= 0 {
			return nil, errors.New("invalid")
		}
		record, err := w.mailbox.load(ctx, r.GrantID, r.ExpectedGeneration, r.MessageID)
		if err != nil {
			return nil, err
		}
		if r.Offset > len(record.Text) || (r.Offset < len(record.Text) && !utf8.RuneStart(record.Text[r.Offset])) {
			return nil, errors.New("invalid")
		}
		end := min(len(record.Text), r.Offset+ownerMailboxReadBytes)
		for end < len(record.Text) && !utf8.RuneStart(record.Text[end]) {
			end--
		}
		return struct {
			Text       string `json:"text"`
			NextOffset int    `json:"nextOffset"`
			TotalBytes int    `json:"totalBytes"`
		}{record.Text[r.Offset:end], end, len(record.Text)}, nil
	case "send", "status", "retry":
		var record sharingOutboundRecord
		var err error
		switch r.Action {
		case "send":
			record, err = w.submit(ctx, sharingOutboundInput{OperationID: r.OperationID, GrantID: r.GrantID, ExpectedGeneration: r.ExpectedGeneration, Text: r.Text, ReplyToID: r.ReplyToID})
		case "status":
			record, err = w.mailbox.outboundStatus(ctx, r.OperationID)
		case "retry":
			record, err = w.retry(ctx, r.OperationID)
		}
		if err != nil {
			return nil, err
		}
		// Do not serialize journal input, reply material, receipt internals, or errors.
		return struct {
			OperationID string    `json:"operationId"`
			MessageID   string    `json:"messageId"`
			Phase       string    `json:"phase"`
			RetryAt     time.Time `json:"retryAt"`
		}{record.Input.OperationID, record.MessageID, record.Phase, record.RetryAt}, nil
	}
	return nil, errors.New("unsupported")
}

const ownerMailboxPageSize = 20
const ownerMailboxPreviewBytes = 256
const ownerMailboxPageBytes = 60 << 10

type ownerInboxItem struct {
	GrantID           string    `json:"grantId"`
	Generation        int64     `json:"generation"`
	MessageID         string    `json:"messageId"`
	Preview           string    `json:"preview"`
	SenderPrincipalID string    `json:"senderPrincipalId"`
	Kind              string    `json:"kind"`
	CreatedAt         time.Time `json:"createdAt"`
}
type ownerOutboxItem struct {
	OperationID        string    `json:"operationId"`
	MessageID          string    `json:"messageId"`
	GrantID            string    `json:"grantId"`
	ExpectedGeneration int64     `json:"expectedGeneration"`
	Phase              string    `json:"phase"`
	RetryAt            time.Time `json:"retryAt"`
	Preview            string    `json:"preview"`
}

// Older journals can contain metadata too large for an encrypted list frame.
// Preserve operation discovery and cursor progress without returning that data.
type ownerOutboxPlaceholder struct {
	OperationID string `json:"operationId"`
	MessageID   string `json:"messageId"`
	Phase       string `json:"phase"`
	Oversized   bool   `json:"oversized"`
}
type ownerMailboxPage struct {
	Items      []any   `json:"items"`
	NextCursor *string `json:"nextCursor"`
}

func ownerMailboxPreview(text string) string {
	end := min(len(text), ownerMailboxPreviewBytes)
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end]
}

// SQLite rowids provide stable cursors while arrivals append to the journal.
// Authenticate each sealed record before selecting any display fields. The
// encoded item budget leaves room for the response wrapper and request ID.
func (m *sharingMailbox) ownerList(ctx context.Context, cursor string, limit int, outbound bool) (ownerMailboxPage, error) {
	page := ownerMailboxPage{Items: []any{}}
	var after int64
	if cursor != "" {
		var err error
		after, err = strconv.ParseInt(cursor, 10, 64)
		if err != nil || after <= 0 || strconv.FormatInt(after, 10) != cursor {
			return page, errors.New("invalid")
		}
	}
	if limit < 0 || limit > ownerMailboxPageSize {
		return page, errors.New("invalid")
	}
	if limit == 0 {
		limit = ownerMailboxPageSize
	}
	query := "SELECT rowid,grant_id,generation,message_id,sealed FROM inbound WHERE rowid>? ORDER BY rowid LIMIT ?"
	if outbound {
		query = "SELECT rowid,operation_id,message_id,sealed FROM outbound WHERE rowid>? ORDER BY rowid LIMIT ?"
	}
	rows, err := m.db.QueryContext(ctx, query, after, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	var last int64
	bytes := 0
	for rows.Next() {
		var id int64
		var item any
		if outbound {
			var operation, message string
			var sealed []byte
			if err := rows.Scan(&id, &operation, &message, &sealed); err != nil {
				return page, err
			}
			record, err := m.decodeOutbound(operation, message, sealed)
			if err != nil {
				return page, err
			}
			item = ownerOutboxItem{record.Input.OperationID, record.MessageID, record.Input.GrantID, record.Input.ExpectedGeneration, record.Phase, record.RetryAt, ownerMailboxPreview(record.Input.Text)}
		} else {
			var grant, message string
			var generation int64
			var sealed []byte
			if err := rows.Scan(&id, &grant, &generation, &message, &sealed); err != nil {
				return page, err
			}
			plain, err := m.unseal(sealed, m.aad(grant, generation, message))
			if err != nil {
				return page, err
			}
			var record sharingMailboxRecord
			err = json.Unmarshal(plain, &record)
			clear(plain)
			if err != nil {
				return page, err
			}
			if record.Message.GrantID != grant || record.Message.Generation != generation || record.Message.ID != message || record.Message.RecipientPrincipalID != m.binding.ServiceID {
				return page, errors.New("invalid")
			}
			item = ownerInboxItem{grant, generation, message, ownerMailboxPreview(record.Text), record.Message.SenderPrincipalID, record.Message.Kind, record.Message.CreatedAt}
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return page, err
		}
		if outbound && len(encoded)+1 > ownerMailboxPageBytes {
			record := item.(ownerOutboxItem)
			item = ownerOutboxPlaceholder{record.OperationID, record.MessageID, record.Phase, true}
			encoded, err = json.Marshal(item)
			if err != nil {
				return page, err
			}
		}
		if len(page.Items) == limit || bytes+len(encoded)+1 > ownerMailboxPageBytes {
			if len(page.Items) == 0 {
				return page, errors.New("item too large")
			}
			value := strconv.FormatInt(last, 10)
			page.NextCursor = &value
			break
		}
		page.Items = append(page.Items, item)
		bytes += len(encoded) + 1
		last = id
	}
	return page, rows.Err()
}
