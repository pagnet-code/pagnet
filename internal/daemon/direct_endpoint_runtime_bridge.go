//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/runtimeconnect"
	"github.com/pagnet-code/pagnet/transport"
)

var errDirectRuntimeRecovery = errors.New("direct runtime recovery required")
var errDirectRuntimeRejected = errors.New("direct runtime binding rejected")

// All dependencies are dormant. Authority must use the existing endpoint custody
// and consent lease gates; Qwen must be bound to this exact native session and
// retain its capability/workspace preflight. OpenASK verifies authenticated
// ciphertext, and SealReply creates an encrypted reply, using daemon custody.
// Remote text is passed only as prompt data, without local operator metadata.
type directRuntimeQwen interface {
	AdmitPrompt(context.Context, string, string) (runtimeconnect.PromptResult, error)
	ResumePrompt(context.Context, runtimeconnect.PromptResult) (runtimeconnect.PromptResult, error)
}
type directRuntimeClient interface {
	Inbox(context.Context, string, transport.DirectInboxRequestV2) (transport.DirectInboxPageV2, error)
	Ack(context.Context, string, transport.DirectMessageAckV2) (transport.DirectMessageAckReceiptV2, error)
	Send(context.Context, string, transport.DirectChannelMessageV2) (transport.DirectMessageAdmissionReceiptV2, error)
	SenderReceipt(context.Context, string, transport.DirectSenderReceiptRequestV2) (transport.DirectSenderReceiptV2, error)
}
type directRuntimeBinding struct {
	Publication                     transport.DirectChannelPublicationV2
	Context                         transport.DirectDeliveryContextV2
	Recipient                       transport.DirectDeliveryPartyV2
	NativeSession, NativeGeneration string
	ConsentRevision                 int64
}
type directRuntimeDependencies struct {
	Now       func() time.Time
	Client    directRuntimeClient
	Qwen      func(directRuntimeBinding) (directRuntimeQwen, error)
	Authority func(context.Context, directRuntimeBinding, func(context.Context, string) error) error
	OpenASK   func(context.Context, directRuntimeBinding, transport.DirectChannelMessageV2) (string, error)
	SealReply func(context.Context, directRuntimeBinding, transport.DirectChannelMessageV2, string) (transport.DirectChannelMessageV2, error)
}
type directRuntimeAcceptance struct {
	Binding  directRuntimeBinding
	Delivery transport.DirectDeliveryV2
	Text     string
}
type directRuntimeTurn struct {
	Acceptance     directRuntimeAcceptance
	Owner, Stage   string
	Receipt        runtimeconnect.PromptResult
	Result         string
	Reply          []byte
	ReconcileUntil time.Time
	Admission      *transport.DirectMessageAdmissionReceiptV2
}
type directRuntimeHandle struct {
	key, session, owner string
	gate                *sync.Mutex // sole live capability; never reconstructed from durable rows
}
type directRuntimeStore struct {
	registry *NativeWorkerRegistry
	poisoned bool
}
type directRuntimeBridge struct {
	store *directRuntimeStore
	deps  directRuntimeDependencies
	mu    sync.Mutex // one synchronous call per processor, including retries
}

const directRuntimeTurnSchema = `CREATE TABLE native_direct_runtime_turn_v1(turn_key TEXT PRIMARY KEY,session_key TEXT NOT NULL,owner TEXT NOT NULL,record BLOB NOT NULL CHECK(length(record)<=524288))`
const directRuntimeSessionSchema = `CREATE TABLE native_direct_runtime_session_v1(session_key TEXT PRIMARY KEY,turn_key TEXT NOT NULL,owner TEXT NOT NULL)`

func (s *directRuntimeStore) schema(ctx context.Context, c *sql.Conn) error {
	for name, expected := range map[string]string{"native_direct_runtime_turn_v1": directRuntimeTurnSchema, "native_direct_runtime_session_v1": directRuntimeSessionSchema} {
		var got string
		err := c.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&got)
		if errors.Is(err, sql.ErrNoRows) {
			if _, err = c.ExecContext(ctx, expected); err != nil {
				return err
			}
			got = expected
		} else if err != nil {
			return err
		}
		if got != expected {
			return errDirectRuntimeRejected
		}
		var triggers int
		if err = c.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name=?", name).Scan(&triggers); err != nil {
			return err
		}
		if triggers != 0 {
			return errDirectRuntimeRejected
		}
	}
	return nil
}
func (s *directRuntimeStore) locked(ctx context.Context, fn func(*sql.Conn) error) error {
	if s == nil {
		return errDirectRuntimeRejected
	}
	return nativeRegistryCustodyTransaction(ctx, s.registry, &s.poisoned, s.schema, fn, nil)
}
func directRuntimeDigest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func directRuntimeValidText(s string) bool {
	return utf8.ValidString(s) && len(s) <= 65536 && strings.TrimSpace(s) != ""
}
func (s *directRuntimeStore) claim(ctx context.Context, a directRuntimeAcceptance) (h directRuntimeHandle, done bool, err error) {
	h.session = directRuntimeDigest([]string{a.Binding.NativeSession, a.Binding.NativeGeneration})
	h.key = directRuntimeDigest(struct {
		Session string
		Context transport.DirectDeliveryContextV2
		ID      string
	}{h.session, a.Binding.Context, a.Delivery.Admission.Binding.MessageID})
	h.owner = uuid.NewString()
	defer func() {
		if err != nil || done {
			h = directRuntimeHandle{}
		}
	}()
	err = s.locked(ctx, func(c *sql.Conn) error {
		var raw []byte
		e := c.QueryRowContext(ctx, "SELECT CASE WHEN length(record)<=524288 THEN record ELSE NULL END FROM native_direct_runtime_turn_v1 WHERE turn_key=?", h.key).Scan(&raw)
		if e == nil {
			var old directRuntimeTurn
			if json.Unmarshal(raw, &old) != nil || !bytes.Equal(mustRuntimeJSON(old.Acceptance), mustRuntimeJSON(a)) {
				return errDirectRuntimeRejected
			}
			if old.Stage == "complete" {
				done = true
				return nil
			}
			return errDirectRuntimeRecovery // no TTL, owner stealing, or restart recovery
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		var count int
		if e = c.QueryRowContext(ctx, "SELECT count(*) FROM native_direct_runtime_turn_v1").Scan(&count); e != nil {
			return e
		}
		if count >= 4096 {
			return errDirectRuntimeRecovery
		}
		var owner string
		e = c.QueryRowContext(ctx, "SELECT owner FROM native_direct_runtime_session_v1 WHERE session_key=?", h.session).Scan(&owner)
		if e == nil {
			return errDirectRuntimeRecovery
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		h.gate = &sync.Mutex{}
		raw = mustRuntimeJSON(directRuntimeTurn{Acceptance: a, Owner: h.owner, Stage: "accepted"})
		if len(raw) > 524288 {
			return errDirectRuntimeRejected
		}
		if _, e = c.ExecContext(ctx, "INSERT INTO native_direct_runtime_session_v1 VALUES(?,?,?)", h.session, h.key, h.owner); e != nil {
			return e
		}
		_, e = c.ExecContext(ctx, "INSERT INTO native_direct_runtime_turn_v1 VALUES(?,?,?,?)", h.key, h.session, h.owner, raw)
		return e
	})
	return
}
func mustRuntimeJSON(v any) []byte { raw, _ := json.Marshal(v); return raw }
func (s *directRuntimeStore) load(ctx context.Context, h directRuntimeHandle) (v directRuntimeTurn, err error) {
	err = s.locked(ctx, func(c *sql.Conn) error {
		var raw []byte
		if e := c.QueryRowContext(ctx, "SELECT CASE WHEN length(record)<=524288 THEN record ELSE NULL END FROM native_direct_runtime_turn_v1 WHERE turn_key=? AND session_key=? AND owner=?", h.key, h.session, h.owner).Scan(&raw); e != nil {
			return errDirectRuntimeRecovery
		}
		if json.Unmarshal(raw, &v) != nil || v.Owner != h.owner {
			return errDirectRuntimeRecovery
		}
		if v.Stage != "complete" {
			var owner string
			if e := c.QueryRowContext(ctx, "SELECT owner FROM native_direct_runtime_session_v1 WHERE session_key=? AND turn_key=?", h.session, h.key).Scan(&owner); e != nil || owner != h.owner {
				return errDirectRuntimeRecovery
			}
		}
		return nil
	})
	return
}
func (s *directRuntimeStore) save(ctx context.Context, h directRuntimeHandle, prior string, v directRuntimeTurn) error {
	raw := mustRuntimeJSON(v)
	if len(raw) > 524288 || v.Owner != h.owner {
		return errDirectRuntimeRejected
	}
	return s.locked(ctx, func(c *sql.Conn) error {
		var oldRaw []byte
		var old directRuntimeTurn
		if e := c.QueryRowContext(ctx, "SELECT CASE WHEN length(record)<=524288 THEN record ELSE NULL END FROM native_direct_runtime_turn_v1 WHERE turn_key=? AND session_key=? AND owner=?", h.key, h.session, h.owner).Scan(&oldRaw); e != nil {
			return errDirectRuntimeRecovery
		}
		if json.Unmarshal(oldRaw, &old) != nil || old.Stage != prior || !bytes.Equal(mustRuntimeJSON(old.Acceptance), mustRuntimeJSON(v.Acceptance)) {
			return errDirectRuntimeRecovery
		}
		var owner string
		if e := c.QueryRowContext(ctx, "SELECT owner FROM native_direct_runtime_session_v1 WHERE session_key=? AND turn_key=?", h.session, h.key).Scan(&owner); e != nil || owner != h.owner {
			return errDirectRuntimeRecovery
		}
		if _, e := c.ExecContext(ctx, "UPDATE native_direct_runtime_turn_v1 SET record=? WHERE turn_key=? AND owner=?", raw, h.key, h.owner); e != nil {
			return e
		}
		if v.Stage == "complete" {
			_, e := c.ExecContext(ctx, "DELETE FROM native_direct_runtime_session_v1 WHERE session_key=? AND turn_key=? AND owner=?", h.session, h.key, h.owner)
			return e
		}
		return nil
	})
}

func newDirectRuntimeBridge(s *directRuntimeStore, d directRuntimeDependencies) (*directRuntimeBridge, error) {
	if s == nil || s.registry == nil || d.Client == nil || d.Qwen == nil || d.Authority == nil || d.OpenASK == nil || d.SealReply == nil {
		return nil, errDirectRuntimeRejected
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &directRuntimeBridge{store: s, deps: d}, nil
}

// Accept verifies and saves exact encrypted inbox acceptance before acknowledging.
// Callers retain the returned handle only in this process; a restarted processor
// parks unfinished rows for explicit recovery instead of reconstructing owners.
func (b *directRuntimeBridge) Accept(ctx context.Context, binding directRuntimeBinding, d transport.DirectDeliveryV2) (h directRuntimeHandle, done bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !consentText(binding.NativeSession) || !consentText(binding.NativeGeneration) || binding.ConsentRevision <= 0 || binding.Recipient.Role != "P" {
		return h, false, errDirectRuntimeRejected
	}
	raw, e := d.CanonicalBytes()
	if e != nil {
		return h, false, errDirectRuntimeRejected
	}
	d, e = transport.DecodeDirectDeliveryV2(raw)
	if e != nil {
		return h, false, errDirectRuntimeRejected
	}
	if !directRuntimeUnexpired(d.Admission, b.deps.Now()) || d.DeliveryState != "pending" || d.Admission.Binding.Context != binding.Context || d.Admission.Binding.Recipient != binding.Recipient || d.Admission.ValidateForPublication(binding.Publication) != nil {
		return h, false, errDirectRuntimeRejected
	}
	ask, e := transport.DecodeDirectChannelMessageV2(d.Wire)
	if e != nil || ask.Header.Kind != "ASK" || transport.ValidateDirectChannelMessageForDescriptorV2(ask, binding.Publication.Descriptor) != nil {
		return h, false, errDirectRuntimeRejected
	}
	var text string
	err = b.deps.Authority(ctx, binding, func(opctx context.Context, credential string) error {
		var e error
		text, e = b.deps.OpenASK(opctx, binding, ask)
		return e
	})
	if err != nil {
		return h, false, err
	}
	if !directRuntimeValidText(text) {
		return h, false, errDirectRuntimeRejected
	}
	h, done, err = b.store.claim(ctx, directRuntimeAcceptance{binding, d, text})
	if err != nil {
		return
	}
	err = b.deps.Authority(ctx, binding, func(opctx context.Context, credential string) error {
		ack, e := b.deps.Client.Ack(opctx, credential, transport.DirectMessageAckV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/ack", Binding: d.Admission.Binding})
		if e != nil {
			return e
		}
		return ack.ValidateForAdmission(d.Admission)
	})
	return
}

// Process resumes only the owner returned by Accept. Persisted started markers
// fence every repeat admission, including definitive rejection and panic paths.
func (b *directRuntimeBridge) Process(ctx context.Context, h directRuntimeHandle) error {
	if h.gate == nil {
		return errDirectRuntimeRecovery
	}
	h.gate.Lock()
	defer h.gate.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	v, e := b.store.load(ctx, h)
	if e != nil {
		return e
	}
	if v.Stage == "complete" {
		return nil
	}
	binding := v.Acceptance.Binding
	ask, e := transport.DecodeDirectChannelMessageV2(v.Acceptance.Delivery.Wire)
	if e != nil {
		return errDirectRuntimeRejected
	}
	if v.Stage == "accepted" {
		e = b.deps.Authority(ctx, binding, func(opctx context.Context, _ string) error {
			if !directRuntimeUnexpired(v.Acceptance.Delivery.Admission, b.deps.Now()) {
				return errDirectRuntimeRejected
			}
			expires, _ := time.Parse(time.RFC3339Nano, v.Acceptance.Delivery.Admission.ExpiresAt)
			opctx, cancel := context.WithDeadline(opctx, expires)
			defer cancel()
			q, e := b.deps.Qwen(binding)
			if e != nil {
				return e
			}
			v.Stage = "started"
			if e = b.store.save(opctx, h, "accepted", v); e != nil {
				return e
			}
			if !directRuntimeUnexpired(v.Acceptance.Delivery.Admission, b.deps.Now()) || opctx.Err() != nil {
				return errDirectRuntimeRejected
			}
			receipt, e := q.AdmitPrompt(opctx, ask.Header.MessageID, v.Acceptance.Text)
			if e != nil || !receipt.Accepted || receipt.PromptID == "" || receipt.LastEventID < 0 {
				return errDirectRuntimeRecovery
			}
			v.Receipt = receipt
			v.Stage = "admitted"
			return b.store.save(opctx, h, "started", v)
		})
		if e != nil {
			return e
		}
	}
	if v.Stage == "started" {
		return errDirectRuntimeRecovery
	}
	if v.Stage == "admitted" {
		e = b.deps.Authority(ctx, binding, func(opctx context.Context, _ string) error {
			q, e := b.deps.Qwen(binding)
			if e != nil {
				return e
			}
			result, e := q.ResumePrompt(opctx, v.Receipt)
			if e != nil || result.Uncertain || !result.Accepted || result.PromptID != v.Receipt.PromptID || !directRuntimeValidText(result.ResultText) {
				return errDirectRuntimeRecovery
			}
			v.Result = result.ResultText
			v.Stage = "result"
			return b.store.save(opctx, h, "admitted", v)
		})
		if e != nil {
			return e
		}
	}
	if v.Stage == "result" {
		e = b.deps.Authority(ctx, binding, func(opctx context.Context, _ string) error {
			reply, e := b.deps.SealReply(opctx, binding, ask, v.Result)
			if e != nil {
				return e
			}
			if transport.ValidateDirectChannelReplyToV2(reply, ask) != nil || transport.ValidateDirectChannelMessageForDescriptorV2(reply, binding.Publication.Descriptor) != nil {
				return errDirectRuntimeRejected
			}
			v.Reply, e = reply.CanonicalBytes()
			if e != nil {
				return e
			}
			v.Stage = "outbox"
			return b.store.save(opctx, h, "result", v)
		})
		if e != nil {
			return e
		}
	}
	if v.Stage != "outbox" {
		return errDirectRuntimeRecovery
	}
	return b.deps.Authority(ctx, binding, func(opctx context.Context, credential string) error {
		reply, e := transport.DecodeDirectChannelMessageV2(v.Reply)
		if e != nil {
			return errDirectRuntimeRejected
		}
		hash, _ := transport.DirectChannelMessageHashV2(reply)
		incoming := v.Acceptance.Delivery.Admission.Binding
		rb := transport.DirectMessageBindingV2{Context: incoming.Context, MessageID: reply.Header.MessageID, WireHash: hash, WireBytes: len(v.Reply), Sender: incoming.Recipient, Recipient: incoming.Sender}
		// Reconcile first on every attempt; absence permits only identical saved bytes.
		q := transport.DirectSenderReceiptRequestV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/sender-receipt-request", Binding: rb}
		status, e := b.deps.Client.SenderReceipt(opctx, credential, q)
		if e != nil {
			return e
		}
		if status.ValidateForRequest(q) != nil {
			return errDirectRuntimeRejected
		}
		var receipt transport.DirectMessageAdmissionReceiptV2
		if status.Status == "admitted" {
			receipt = *status.Admission
		} else if status.Status == "not_found" {
			if v.ReconcileUntil.IsZero() {
				// Persist the first dispatch window before Send. A later not_found cannot
				// distinguish never-admitted from an admission aged out of server retention.
				v.ReconcileUntil = b.deps.Now().Add(24 * time.Hour)
				expiry, err := time.Parse(time.RFC3339Nano, binding.Publication.Descriptor.ExpiresAt)
				if err != nil {
					return errDirectRuntimeRejected
				}
				if expiry.Before(v.ReconcileUntil) {
					v.ReconcileUntil = expiry
				}
				if e = b.store.save(opctx, h, "outbox", v); e != nil {
					return e
				}
			}
			if !b.deps.Now().Before(v.ReconcileUntil) {
				return errDirectRuntimeRecovery
			}
			sendctx, cancel := context.WithDeadline(opctx, v.ReconcileUntil)
			defer cancel()
			if sendctx.Err() != nil {
				return errDirectRuntimeRecovery
			}
			receipt, e = b.deps.Client.Send(sendctx, credential, reply)
			if e != nil {
				return e
			}
		} else {
			return errDirectRuntimeRecovery
		}
		if receipt.Binding != rb || receipt.ValidateForPublication(binding.Publication) != nil {
			return errDirectRuntimeRejected
		}
		v.Admission = &receipt
		v.Stage = "complete"
		return b.store.save(opctx, h, "outbox", v)
	})
}

func directRuntimeUnexpired(r transport.DirectMessageAdmissionReceiptV2, now time.Time) bool {
	admitted, e1 := time.Parse(time.RFC3339Nano, r.AdmittedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	return e1 == nil && e2 == nil && !now.Before(admitted) && now.Before(expires)
}

// ReceiveOne reads a non-destructive inbox page. It never advances a durable
// cursor: only exact local acceptance followed by Ack consumes a delivery.
func (b *directRuntimeBridge) ReceiveOne(ctx context.Context, binding directRuntimeBinding) (directRuntimeHandle, bool, error) {
	q := transport.DirectInboxRequestV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/inbox-request", Context: binding.Context, Recipient: binding.Recipient, Limit: 1}
	var page transport.DirectInboxPageV2
	err := b.deps.Authority(ctx, binding, func(opctx context.Context, credential string) error {
		var e error
		page, e = b.deps.Client.Inbox(opctx, credential, q)
		return e
	})
	if err != nil {
		return directRuntimeHandle{}, false, err
	}
	if _, err = page.CanonicalBytes(); err != nil || page.Context != q.Context || page.Recipient != q.Recipient || len(page.Deliveries) > 1 {
		return directRuntimeHandle{}, false, errDirectRuntimeRejected
	}
	if len(page.Deliveries) == 0 {
		return directRuntimeHandle{}, false, nil
	}
	return b.Accept(ctx, binding, page.Deliveries[0])
}
