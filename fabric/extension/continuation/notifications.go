package continuation

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

const maxNotificationBytes = 16384

// PrivateDelivery belongs only to authenticated private notification/admin
// infrastructure. Serialization and normal formatting never disclose its token.
type PrivateDelivery struct {
	ID         string
	Recipient  fabric.Principal
	Revision   uint64
	ExpiresAt  time.Time
	Published  bool
	capability Capability
}

func (PrivateDelivery) MarshalJSON() ([]byte, error) { return nil, stale() }
func (*PrivateDelivery) UnmarshalJSON([]byte) error  { return stale() }
func (PrivateDelivery) String() string               { return "[private continuation delivery]" }
func (PrivateDelivery) GoString() string             { return "[private continuation delivery]" }
func (d PrivateDelivery) Capability() Capability     { return d.capability }

type notificationPlain struct {
	Format        uint32
	ID            string
	Recipient     fabric.Principal
	Revision      uint64
	Expiry, Token string
}

func notificationRecipient(p fabric.Principal) string {
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(append([]byte("pagnet.continuation.recipient.v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}
func notificationPurpose(recipient string, revision uint64) string {
	return "notification." + recipient + "." + strconv.FormatUint(revision, 10)
}

// A capability and every exact recipient's encrypted outbox entry share the
// SAME FULL continuation transaction. Root publication is a separate phase.
func (s *Store) writeNotifications(ctx context.Context, tx *sql.Tx, v Snapshot, cap Capability, revision uint64, expiry string) error {
	for _, recipient := range v.AllowedResumePrincipals {
		key := notificationRecipient(recipient)
		raw, e := json.Marshal(notificationPlain{1, v.DeferralID, recipient, revision, expiry, cap.Token()})
		if e != nil || len(raw) > maxNotificationBytes {
			return internal()
		}
		cipher, e := s.sealBlob(notificationPurpose(key, revision), v.DeferralID, raw, maxNotificationBytes)
		clear(raw)
		if e != nil {
			return e
		}
		var previous int64
		if e = tx.QueryRowContext(ctx, "SELECT COALESCE((SELECT length(payload) FROM private_notifications WHERE id=? AND recipient=?),0)", v.DeferralID, key).Scan(&previous); e != nil {
			return internal()
		}
		if e = s.charge(ctx, tx, 0, int64(len(cipher))-previous); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO private_notifications VALUES(?,?,?,?,0) ON CONFLICT(id,recipient) DO UPDATE SET revision=excluded.revision,payload=excluded.payload,published=0", v.DeferralID, key, revision, cipher); e != nil {
			return internal()
		}
	}
	return nil
}
func (s *Store) decodeNotification(id, key string, revision uint64, cipher []byte) (notificationPlain, error) {
	var v notificationPlain
	raw, e := s.openBlob(notificationPurpose(key, revision), id, cipher, maxNotificationBytes)
	if e != nil {
		return v, e
	}
	defer clear(raw)
	if decode(raw, &v, maxNotificationBytes) != nil || v.Format != 1 || v.ID != id || v.Revision != revision || notificationRecipient(v.Recipient) != key {
		return v, internal()
	}
	return v, nil
}

// PrivateNotification requires the genuinely authenticated exact allowed full
// recipient and current pending revision. Old publications cannot revive work.
func (s *Store) PrivateNotification(ctx context.Context, c fabric.ExecutionContext, id string) (PrivateDelivery, error) {
	var result PrivateDelivery
	if s.authenticated(c) != nil || !hexID(id) {
		return result, stale()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.transaction(ctx)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	r, e := s.load(ctx, tx, id)
	if e != nil {
		return result, e
	}
	snapshot, e := s.snapshot(r.snapshot)
	if e != nil || !allowed(snapshot, c.PrincipalView()) || r.state != Pending {
		return result, stale()
	}
	expiry, e := time.Parse(time.RFC3339Nano, r.expires)
	if e != nil || !expiry.After(time.Now()) {
		return result, stale()
	}
	key := notificationRecipient(c.PrincipalView())
	var revision uint64
	var cipher []byte
	var published bool
	if e = tx.QueryRowContext(ctx, "SELECT revision,CASE WHEN length(payload)<=? THEN payload END,published FROM private_notifications WHERE id=? AND recipient=?", maxNotificationBytes+maxSealOverhead, id, key).Scan(&revision, &cipher, &published); e != nil || revision != uint64(r.revision) {
		return result, stale()
	}
	value, e := s.decodeNotification(id, key, revision, cipher)
	if e != nil || value.Recipient != c.PrincipalView() || value.Expiry != r.expires {
		return result, stale()
	}
	tokenID, hash, e := parseToken(value.Token)
	if e != nil || tokenID != id || subtle.ConstantTimeCompare(hash, r.hash) != 1 {
		return result, stale()
	}
	return PrivateDelivery{id, value.Recipient, revision, expiry, published, Capability{value.Token}}, nil
}

// AcknowledgePrivateNotification records private delivery, not execution. It
// requires exact current capability possession; Root proof checks belong to the
// separately configured publication adapter before this acknowledgement.
func (s *Store) AcknowledgePrivateNotification(ctx context.Context, c fabric.ExecutionContext, token string, revision uint64) error {
	id, hash, e := parseToken(token)
	if e != nil || s.authenticated(c) != nil {
		return stale()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.transaction(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := s.load(ctx, tx, id)
	if e != nil {
		return e
	}
	v, e := s.snapshot(r.snapshot)
	if e != nil || !allowed(v, c.PrincipalView()) || r.state != Pending || uint64(r.revision) != revision || subtle.ConstantTimeCompare(hash, r.hash) != 1 {
		return stale()
	}
	expiry, e := time.Parse(time.RFC3339Nano, r.expires)
	if e != nil || !expiry.After(time.Now()) {
		return stale()
	}
	res, e := tx.ExecContext(ctx, "UPDATE private_notifications SET published=1 WHERE id=? AND recipient=? AND revision=?", id, notificationRecipient(c.PrincipalView()), revision)
	if e != nil {
		return internal()
	}
	n, e := res.RowsAffected()
	if e != nil || n != 1 {
		return stale()
	}
	return tx.Commit()
}

// VerifyPrivatePublication is a trusted infrastructure check before the
// installation signs a separate publication receipt. Exact capability
// possession cannot change recipient, revision, expiry or source state.
func (s *Store) VerifyPrivatePublication(ctx context.Context, token string, revision uint64, recipient fabric.Principal) (PrivateDelivery, error) {
	var result PrivateDelivery
	id, hash, e := parseToken(token)
	if e != nil {
		return result, stale()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.transaction(ctx)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	r, e := s.load(ctx, tx, id)
	if e != nil {
		return result, e
	}
	v, e := s.snapshot(r.snapshot)
	if e != nil || !allowed(v, recipient) || r.state != Pending || uint64(r.revision) != revision || subtle.ConstantTimeCompare(hash, r.hash) != 1 {
		return result, stale()
	}
	expiry, e := time.Parse(time.RFC3339Nano, r.expires)
	if e != nil || !expiry.After(time.Now()) {
		return result, stale()
	}
	key := notificationRecipient(recipient)
	var cipher []byte
	var published bool
	if e = tx.QueryRowContext(ctx, "SELECT CASE WHEN length(payload)<=? THEN payload END,published FROM private_notifications WHERE id=? AND recipient=? AND revision=?", maxNotificationBytes+maxSealOverhead, id, key, revision).Scan(&cipher, &published); e != nil {
		return result, stale()
	}
	n, e := s.decodeNotification(id, key, revision, cipher)
	if e != nil || n.Recipient != recipient || n.Expiry != r.expires || n.Token != token {
		return result, stale()
	}
	return PrivateDelivery{id, recipient, revision, expiry, published, Capability{token}}, nil
}
func (s *Store) verifyNotifications(ctx context.Context, total *int64, expected int64) error {
	rows, e := s.db.QueryContext(ctx, "SELECT n.id,n.recipient,n.revision,CASE WHEN length(n.payload)<=? THEN n.payload END,n.published,c.cap_hash,c.cap_revision,c.expires FROM private_notifications n LEFT JOIN continuations c ON c.id=n.id ORDER BY n.id,n.recipient", maxNotificationBytes+maxSealOverhead)
	if e != nil {
		return internal()
	}
	defer rows.Close()
	var count int64
	for rows.Next() {
		var id, key, expiry string
		var revision, parentRevision uint64
		var cipher, hash []byte
		var published bool
		if e = rows.Scan(&id, &key, &revision, &cipher, &published, &hash, &parentRevision, &expiry); e != nil {
			return internal()
		}
		count++
		if (count+63)/64 > s.options.MaxRecords || int64(len(cipher)) > s.options.MaxBytes-*total {
			return internal()
		}
		*total += int64(len(cipher))
		if revision != parentRevision {
			return internal()
		}
		v, e := s.decodeNotification(id, key, revision, cipher)
		if e != nil || v.Expiry != expiry {
			return internal()
		}
		tokenID, want, e := parseToken(v.Token)
		if e != nil || tokenID != id || subtle.ConstantTimeCompare(want, hash) != 1 {
			return internal()
		}
	}
	if count != expected {
		return internal()
	}
	return rows.Err()
}
