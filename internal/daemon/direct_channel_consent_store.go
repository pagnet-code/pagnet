//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/transport"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const directChannelConsentMaxRecords = 1024
const directChannelConsentMaxBytes = 16384

var errDirectChannelConsent = errors.New("direct channel consent unavailable, unsafe or conflicting")

// Consent is public local opt-in metadata, never authority to use a channel.
// Lock order: registry mutex, custody flock, sole SQLite BEGIN IMMEDIATE.
// No enrollment material, namespace lock, or additional files are used.
type directChannelConsentStore struct {
	registry                                    *NativeWorkerRegistry
	installation, server, tenant, account, host string
	poisoned                                    bool // guarded by registry.mu; uncertain COMMIT requires reopening
}
type directChannelConsentKey struct {
	Server, Tenant, Account, Host, Intent, Role, Principal string
}
type directChannelConsentBinding struct {
	Key                                                     directChannelConsentKey
	Instance, Origin, OwnershipGeneration, NativeGeneration string
	AuthorizationSnapshotDigest, PeerPrincipal, GrantID     string
	GrantGeneration                                         int64
	Epoch, ExpiresAt                                        string
}
type directChannelConsentRecord struct {
	Key      directChannelConsentKey
	Revision int64
	Enabled  bool
	Binding  *directChannelConsentBinding
}
type directChannelConsentRow struct {
	directChannelConsentRecord
	MutationID, Operation string
	ExpectedRevision      int64
	Digest                []byte
}

// The caller must obtain session from an authenticated host connection and
// authorize access to this local API. HostSessionPayload is scope data; passing
// a payload does not authenticate its contents. Installation comes only from
// the private registry, never from a caller-supplied key.
func newDirectChannelConsentStore(ctx context.Context, r *NativeWorkerRegistry, server string, session transport.HostSessionPayload) (*directChannelConsentStore, error) {
	if r == nil || managedPrepareServerOrigin(server) != server || server == "" || len(server) > 2048 {
		return nil, errDirectChannelConsent
	}
	s := &directChannelConsentStore{registry: r, server: server, tenant: session.TenantID, account: session.AccountID, host: session.HostID}
	for _, v := range []string{s.tenant, s.account, s.host} {
		if !consentText(v) {
			return nil, errDirectChannelConsent
		}
	}
	err := s.locked(ctx, func(c *sql.Conn) error {
		if e := c.QueryRowContext(ctx, `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&s.installation); e != nil || !consentText(s.installation) {
			return errDirectChannelConsent
		}
		_, e := s.rows(ctx, c)
		return e
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}
func consentText(v string) bool {
	return utf8.ValidString(v) && v != "" && len(v) <= 512 && strings.TrimSpace(v) == v && !strings.ContainsAny(v, "\x00\r\n")
}
func (s *directChannelConsentStore) validKey(k directChannelConsentKey) bool {
	if s == nil || k.Server != s.server || k.Tenant != s.tenant || k.Account != s.account || k.Host != s.host || (k.Role != "S" && k.Role != "P") {
		return false
	}
	return consentText(k.Intent) && consentText(k.Principal)
}
func (b directChannelConsentBinding) valid() bool {
	for _, v := range []string{b.Instance, b.Origin, b.OwnershipGeneration, b.NativeGeneration, b.PeerPrincipal, b.GrantID, b.Epoch} {
		if !consentText(v) {
			return false
		}
	}
	h, e := hex.DecodeString(b.AuthorizationSnapshotDigest)
	expiry, e2 := time.Parse(time.RFC3339Nano, b.ExpiresAt)
	return e == nil && len(h) == 32 && hex.EncodeToString(h) == b.AuthorizationSnapshotDigest && !bytes.Equal(h, make([]byte, 32)) && b.GrantGeneration > 0 && b.PeerPrincipal != b.Key.Principal && e2 == nil && expiry.Year() >= 1 && expiry.Year() <= 9999 && expiry.UTC().Format(time.RFC3339Nano) == b.ExpiresAt
}

const directChannelConsentSchema = `CREATE TABLE native_direct_channel_consent_v1(installation TEXT NOT NULL,server TEXT NOT NULL,tenant TEXT NOT NULL,account TEXT NOT NULL,host TEXT NOT NULL,intent TEXT NOT NULL,role TEXT NOT NULL,principal TEXT NOT NULL,version INTEGER NOT NULL CHECK(version=1),revision INTEGER NOT NULL CHECK(revision>0),enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),binding BLOB NOT NULL,last_mutation_id TEXT NOT NULL,last_expected_revision INTEGER NOT NULL CHECK(last_expected_revision>=0),last_operation TEXT NOT NULL CHECK(last_operation IN ('enable','disable')),request_digest BLOB NOT NULL CHECK(length(request_digest)=32),PRIMARY KEY(installation,server,tenant,account,host,intent,role,principal),CHECK(revision=last_expected_revision+1))`

func (s *directChannelConsentStore) schema(ctx context.Context, c *sql.Conn) error {
	var schema string
	e := c.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name='native_direct_channel_consent_v1'`).Scan(&schema)
	if errors.Is(e, sql.ErrNoRows) {
		_, e = c.ExecContext(ctx, directChannelConsentSchema)
		if e != nil {
			return e
		}
		schema = directChannelConsentSchema
	}
	if e != nil || schema != directChannelConsentSchema {
		return errDirectChannelConsent
	}
	var triggers int
	if e = c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name='native_direct_channel_consent_v1'`).Scan(&triggers); e != nil || triggers != 0 {
		return errDirectChannelConsent
	}
	return nil
}
func (s *directChannelConsentStore) locked(ctx context.Context, fn func(*sql.Conn) error) error {
	return s.lockedCompletion(ctx, fn, nil)
}

// completion runs after transaction cleanup, before releasing registry.mu.
func (s *directChannelConsentStore) lockedCompletion(ctx context.Context, fn func(*sql.Conn) error, completion func(error)) (resultErr error) {
	if s == nil || s.registry == nil {
		return errDirectChannelConsent
	}
	r := s.registry
	unlock, e := directEndpointTryLock(ctx, &r.mu)
	if e != nil {
		return e
	}
	defer unlock()
	if completion != nil {
		defer func() {
			if recovered := recover(); recovered != nil {
				completion(errDirectChannelConsent)
				panic(recovered)
			}
			completion(resultErr)
		}()
	}
	if s.poisoned || r.closed {
		return errDirectChannelConsent
	}
	root, e := nativeRegistryProtectedDirectory(r.root)
	if e != nil {
		return e
	}
	defer root.Close()
	if e = nativeShareHolderPrivate(root, true); e != nil {
		return e
	}
	custody, e := directEndpointTryNativeRegistryCustodyLock(ctx, root)
	if e != nil {
		return e
	}
	defer custody.Close()
	if _, e = nativeRegistryInspectFiles(root, r.custodyIdentity, false); e != nil {
		return e
	}
	c, e := r.db.Conn(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	var timeout int
	if e = c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&timeout); e != nil {
		return e
	}
	committed, beginAttempted := false, false
	// Cleanup outlives request cancellation. Never return a transaction-bearing
	// or reconfigured connection to the registry pool if cleanup is uncertain.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		discard := func() { _ = c.Raw(func(any) error { return driver.ErrBadConn }) }
		if beginAttempted && !committed {
			if _, err := c.ExecContext(cleanup, "ROLLBACK"); err != nil {
				discard()
				r.directConsentLeases.revokeAll()
				if resultErr == nil {
					resultErr = err
				}
				return
			}
		}
		if _, err := c.ExecContext(cleanup, fmt.Sprintf("PRAGMA busy_timeout=%d", timeout)); err != nil {
			discard()
			r.directConsentLeases.revokeAll()
			if resultErr == nil {
				resultErr = err
			}
		}
	}()
	if _, e = c.ExecContext(ctx, "PRAGMA busy_timeout=0"); e != nil {
		return e
	}
	beginAttempted = true
	if _, e = c.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		var sqliteErr *sqlite.Error
		if errors.As(e, &sqliteErr) && (sqliteErr.Code()&0xff == sqlite3.SQLITE_BUSY || sqliteErr.Code()&0xff == sqlite3.SQLITE_LOCKED) {
			beginAttempted = false
			return errDirectEndpointLocalBusy
		}
		return e
	}
	if _, e = nativeRegistryInspectFiles(root, r.custodyIdentity, false); e != nil {
		return e
	}
	if e = s.schema(ctx, c); e != nil {
		return e
	}
	if e = fn(c); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	_, e = c.ExecContext(ctx, "COMMIT")
	committed = e == nil
	if e != nil {
		s.poisoned = true
		r.directConsentLeases.revokeAll()
	}
	return e
}

func consentKeyValid(k directChannelConsentKey) bool {
	if k.Server == "" || len(k.Server) > 2048 || managedPrepareServerOrigin(k.Server) != k.Server || (k.Role != "S" && k.Role != "P") {
		return false
	}
	for _, v := range []string{k.Tenant, k.Account, k.Host, k.Intent, k.Principal} {
		if !consentText(v) {
			return false
		}
	}
	return true
}
func consentRequestDigest(operation string, k directChannelConsentKey, b *directChannelConsentBinding, revision int64) []byte {
	raw, _ := json.Marshal(struct {
		Operation        string
		Key              directChannelConsentKey
		Binding          *directChannelConsentBinding
		ExpectedRevision int64
	}{operation, k, b, revision})
	h := sha256.Sum256(append([]byte("pagnet/direct-channel-consent/v1\x00"), raw...))
	return h[:]
}
func (s *directChannelConsentStore) rows(ctx context.Context, c *sql.Conn) ([]directChannelConsentRow, error) {
	var installation string
	if e := c.QueryRowContext(ctx, `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&installation); e != nil || installation != s.installation {
		return nil, errDirectChannelConsent
	}
	rows, e := c.QueryContext(ctx, `SELECT CASE WHEN length(CAST(installation AS BLOB))<=512 THEN installation ELSE NULL END,CASE WHEN length(CAST(server AS BLOB))<=2048 THEN server ELSE NULL END,CASE WHEN length(CAST(tenant AS BLOB))<=512 THEN tenant ELSE NULL END,CASE WHEN length(CAST(account AS BLOB))<=512 THEN account ELSE NULL END,CASE WHEN length(CAST(host AS BLOB))<=512 THEN host ELSE NULL END,CASE WHEN length(CAST(intent AS BLOB))<=512 THEN intent ELSE NULL END,CASE WHEN length(CAST(role AS BLOB))<=1 THEN role ELSE NULL END,CASE WHEN length(CAST(principal AS BLOB))<=512 THEN principal ELSE NULL END,version,revision,enabled,CASE WHEN length(binding)<=16384 THEN binding ELSE NULL END,CASE WHEN length(CAST(last_mutation_id AS BLOB))<=512 THEN last_mutation_id ELSE NULL END,last_expected_revision,CASE WHEN length(CAST(last_operation AS BLOB))<=7 THEN last_operation ELSE NULL END,CASE WHEN length(request_digest)=32 THEN request_digest ELSE NULL END FROM native_direct_channel_consent_v1 ORDER BY server,tenant,account,host,intent,role,principal LIMIT 1025`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var result []directChannelConsentRow
	for rows.Next() {
		var r directChannelConsentRow
		var id string
		var version, enabled int
		var raw []byte
		k := &r.Key
		if e = rows.Scan(&id, &k.Server, &k.Tenant, &k.Account, &k.Host, &k.Intent, &k.Role, &k.Principal, &version, &r.Revision, &enabled, &raw, &r.MutationID, &r.ExpectedRevision, &r.Operation, &r.Digest); e != nil {
			return nil, errDirectChannelConsent
		}
		if id != s.installation || !consentKeyValid(r.Key) || version != 1 || r.Revision <= 0 || r.ExpectedRevision < 0 || r.ExpectedRevision == math.MaxInt64 || r.Revision != r.ExpectedRevision+1 || (enabled != 0 && enabled != 1) || !consentText(r.MutationID) || len(r.Digest) != 32 || len(raw) == 0 || len(raw) > directChannelConsentMaxBytes {
			return nil, errDirectChannelConsent
		}
		r.Enabled = enabled == 1
		if json.Unmarshal(raw, &r.Binding) != nil {
			return nil, errDirectChannelConsent
		}
		canonical, _ := json.Marshal(r.Binding)
		if !bytes.Equal(raw, canonical) || (r.Binding != nil && (!r.Binding.valid() || r.Binding.Key != r.Key)) || (r.Enabled && r.Binding == nil) {
			return nil, errDirectChannelConsent
		}
		// Disable retains no binding. Its key and durable revision are sufficient
		// to prevent a stale enable from resurrecting consent.
		if (r.Operation != "enable" && r.Operation != "disable") || (r.Operation == "enable") != r.Enabled || (!r.Enabled && r.Binding != nil) || !bytes.Equal(r.Digest, consentRequestDigest(r.Operation, r.Key, r.Binding, r.ExpectedRevision)) {
			return nil, errDirectChannelConsent
		}
		result = append(result, r)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if len(result) > directChannelConsentMaxRecords {
		return nil, errDirectChannelConsent
	}
	return result, nil
}
func (s *directChannelConsentStore) Enable(ctx context.Context, b directChannelConsentBinding, expectedRevision int64, mutationID string) (directChannelConsentRecord, error) {
	if !b.valid() {
		return directChannelConsentRecord{}, errDirectChannelConsent
	}
	// Expiry is checked inside the transaction after exact-retry detection.
	return s.mutate(ctx, b.Key, &b, expectedRevision, mutationID, "enable")
}
func (s *directChannelConsentStore) Disable(ctx context.Context, k directChannelConsentKey, expectedRevision int64, mutationID string) (directChannelConsentRecord, error) {
	return s.mutate(ctx, k, nil, expectedRevision, mutationID, "disable")
}
func (s *directChannelConsentStore) mutate(ctx context.Context, k directChannelConsentKey, b *directChannelConsentBinding, expected int64, id, operation string) (directChannelConsentRecord, error) {
	var result directChannelConsentRecord
	if !s.validKey(k) || !consentKeyValid(k) || !consentText(id) || expected < 0 || expected == math.MaxInt64 {
		return result, errDirectChannelConsent
	}
	digest := consentRequestDigest(operation, k, b, expected)
	e := s.locked(ctx, func(c *sql.Conn) error {
		all, e := s.rows(ctx, c)
		if e != nil {
			return e
		}
		var existing *directChannelConsentRow
		for i := range all {
			if all[i].Key == k {
				existing = &all[i]
				break
			}
		}
		if existing != nil && existing.MutationID == id {
			if existing.Operation != operation || existing.ExpectedRevision != expected || !bytes.Equal(existing.Digest, digest) {
				return errDirectChannelConsent
			}
			result = existing.directChannelConsentRecord
			return nil
		}
		revision := int64(0)
		if existing != nil {
			revision = existing.Revision
		}
		if revision != expected || (existing == nil && len(all) >= directChannelConsentMaxRecords) {
			return errDirectChannelConsent
		}
		raw, _ := json.Marshal(b)
		if len(raw) > directChannelConsentMaxBytes {
			return errDirectChannelConsent
		}
		enabled := 0
		if operation == "enable" {
			enabled = 1
		}
		_, e = c.ExecContext(ctx, `INSERT INTO native_direct_channel_consent_v1 VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?,?,?,?) ON CONFLICT(installation,server,tenant,account,host,intent,role,principal) DO UPDATE SET revision=excluded.revision,enabled=excluded.enabled,binding=excluded.binding,last_mutation_id=excluded.last_mutation_id,last_expected_revision=excluded.last_expected_revision,last_operation=excluded.last_operation,request_digest=excluded.request_digest`, s.installation, k.Server, k.Tenant, k.Account, k.Host, k.Intent, k.Role, k.Principal, expected+1, enabled, raw, id, expected, operation, digest)
		if e != nil {
			return e
		}
		// Revoke before releasing the registry fence, including a failed or
		// uncertain completion after the write. Exact retries never reach here.
		s.registry.directConsentLeases.revoke(directChannelConsentLeaseKey{s.installation, k})
		if b != nil {
			expiry, _ := time.Parse(time.RFC3339Nano, b.ExpiresAt)
			if !time.Now().Before(expiry) {
				return errDirectChannelConsent
			}
		}
		result = directChannelConsentRecord{Key: k, Revision: expected + 1, Enabled: enabled == 1, Binding: b}
		return nil
	})
	if e != nil {
		return directChannelConsentRecord{}, e
	}
	return result, nil
}
func (s *directChannelConsentStore) Get(ctx context.Context, k directChannelConsentKey) (directChannelConsentRecord, error) {
	result := directChannelConsentRecord{Key: k}
	if !s.validKey(k) || !consentKeyValid(k) {
		return directChannelConsentRecord{}, errDirectChannelConsent
	}
	e := s.locked(ctx, func(c *sql.Conn) error {
		all, e := s.rows(ctx, c)
		if e != nil {
			return e
		}
		for _, r := range all {
			if r.Key == k {
				result = r.directChannelConsentRecord
				break
			}
		}
		return nil
	})
	if e != nil {
		return directChannelConsentRecord{}, e
	}
	return result, nil
}
func (s *directChannelConsentStore) List(ctx context.Context) ([]directChannelConsentRecord, error) {
	var result []directChannelConsentRecord
	e := s.locked(ctx, func(c *sql.Conn) error {
		all, e := s.rows(ctx, c)
		if e != nil {
			return e
		}
		for _, r := range all {
			if s.validKey(r.Key) {
				result = append(result, r.directChannelConsentRecord)
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return result, nil
}
