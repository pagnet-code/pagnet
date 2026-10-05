package durable

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
	"github.com/pagnet-code/pagnet/fabric/internal/privatefs"
	_ "modernc.org/sqlite"
)

type Store struct {
	mu        sync.Mutex
	db        *sql.DB
	lock      io.Closer
	scope     Scope
	config    Config
	protector DataProtector
	reference KeyReference
	byType    map[string][]string
	closed    bool
}

const schema = `CREATE TABLE identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),scope BLOB NOT NULL,config BLOB NOT NULL,key_ref BLOB NOT NULL,key_check BLOB NOT NULL);
CREATE TABLE budget(singleton INTEGER PRIMARY KEY CHECK(singleton=1),rows INTEGER NOT NULL,bytes INTEGER NOT NULL);
INSERT INTO budget VALUES(1,0,0);
CREATE TABLE subscriptions(id TEXT PRIMARY KEY,pending INTEGER NOT NULL);
CREATE TABLE events(source TEXT NOT NULL,id TEXT NOT NULL,digest TEXT NOT NULL,kind TEXT NOT NULL,cipher BLOB NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL,retain_until INTEGER NOT NULL,cost INTEGER NOT NULL,PRIMARY KEY(source,id));
CREATE INDEX events_retention ON events(retain_until,source,id);
CREATE INDEX events_expiry ON events(expires,source,id);
CREATE TABLE deliveries(subscription TEXT NOT NULL,source TEXT NOT NULL,id TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','claimed','acked','failed')),due INTEGER NOT NULL,lease INTEGER NOT NULL,attempt INTEGER NOT NULL,generation INTEGER NOT NULL,worker TEXT NOT NULL,token_hash TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(subscription,source,id),FOREIGN KEY(source,id) REFERENCES events(source,id),FOREIGN KEY(subscription) REFERENCES subscriptions(id));
CREATE INDEX deliveries_due ON deliveries(subscription,state,due,source,id);
CREATE INDEX deliveries_lease ON deliveries(subscription,state,lease,source,id);
CREATE INDEX deliveries_event ON deliveries(source,id,state);
PRAGMA user_version=1;`

func invalid(s string) error { return fabric.NewError(fabric.CodeInvalidInput, s) }
func unavailable() error {
	return fabric.NewError(fabric.CodeProtocolError, "Private durable event state unavailable")
}
func conflict() error {
	return fabric.NewError(fabric.CodeInvalidInput, "Event identity already binds different content")
}
func stale() error {
	return fabric.NewError(fabric.CodeStaleContinuation, "Event delivery claim is stale or unavailable")
}
func validText(s string, n int) bool {
	return len(s) > 0 && len(s) <= n && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func normalize(c Config) (Config, error) {
	if c.MaxSubscriptions < 1 || c.MaxSubscriptions > 1024 || len(c.Subscriptions) > c.MaxSubscriptions || c.MaxFanout < 1 || c.MaxFanout > c.MaxSubscriptions || c.MaxRows < 1 || c.MaxRows > 10000000 || c.MaxBytes < 1 || c.MaxBytes > 1<<40 || c.MaxDatabaseBytes < 4096 || c.MaxDatabaseBytes > 1<<40 || c.MaxEventBytes < 1 || c.MaxEventBytes > 1<<20 || c.MaxCipherBytes < c.MaxEventBytes || c.MaxCipherBytes > 2<<20 || int64(c.MaxCipherBytes) > c.MaxBytes || c.MaxPendingPerSubscription < 1 || c.MaxPendingPerSubscription > c.MaxRows || c.MaxAttempts < 1 || c.MaxAttempts > 100000 || c.LeaseTTL < time.Millisecond || c.LeaseTTL > time.Hour || c.RetryDelay < time.Millisecond || c.RetryDelay > time.Hour || c.DeliveryTTL < time.Millisecond || c.DeliveryTTL > 30*24*time.Hour || c.DedupTTL < c.DeliveryTTL || c.DedupTTL > 365*24*time.Hour {
		return c, invalid("Invalid durable event limits")
	}
	copySubs := make([]Subscription, len(c.Subscriptions))
	configBudget := 0
	seen := map[string]bool{}
	for i, s := range c.Subscriptions {
		if !fabric.ValidNamespacedName(s.ID) || seen[s.ID] || len(s.Types) < 1 || len(s.Types) > 64 {
			return c, invalid("Invalid durable event subscription")
		}
		seen[s.ID] = true
		configBudget += len(s.ID) + 64
		types := append([]string(nil), s.Types...)
		sort.Strings(types)
		for j, t := range types {
			configBudget += len(t) + 4
			if !fabric.ValidNamespacedName(t) || (j > 0 && types[j-1] == t) {
				return c, invalid("Invalid durable event subscription type")
			}
		}
		if configBudget > 512<<10 {
			return c, invalid("Durable subscription configuration exceeds byte limit")
		}
		copySubs[i] = Subscription{ID: s.ID, Types: types}
	}
	sort.Slice(copySubs, func(i, j int) bool { return copySubs[i].ID < copySubs[j].ID })
	c.Subscriptions = copySubs
	return c, nil
}

// ValidateConfig validates and owns normalized finite configuration without IO.
// Explicit composition uses it before committing a setup intent.
func ValidateConfig(c Config) (Config, error) { return normalize(c) }

func Bootstrap(ctx context.Context, dir string, scope Scope, c Config, p DataProtector) (*Store, error) {
	return open(ctx, dir, scope, c, p, true)
}
func Open(ctx context.Context, dir string, scope Scope, c Config, p DataProtector) (*Store, error) {
	return open(ctx, dir, scope, c, p, false)
}
func open(ctx context.Context, dir string, scope Scope, c Config, p DataProtector, create bool) (*Store, error) {
	if ctx == nil || !validText(scope.Audience, 4096) || !validText(scope.Domain, 4096) || p == nil {
		return nil, invalid("Durable events require explicit scope and data protector")
	}
	c, err := normalize(c)
	if err != nil {
		return nil, err
	}
	ref := p.Reference()
	if !validText(ref.ID, 256) || !validText(ref.Version, 128) {
		return nil, invalid("Invalid data protector reference")
	}
	if create {
		if err = privatefs.CreateDirectory(dir); err != nil && !os.IsExist(err) {
			return nil, unavailable()
		}
	}
	lock, err := privatefs.Acquire(dir, "writer.lock")
	if err != nil {
		return nil, unavailable()
	}
	keep := false
	defer func() {
		if !keep {
			lock.Close()
		}
	}()
	path := filepath.Join(dir, "events.sqlite")
	if create {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, unavailable()
		}
		if err = f.Close(); err != nil {
			return nil, unavailable()
		}
	}
	if privatefs.CheckFile(path, c.MaxDatabaseBytes) != nil {
		return nil, unavailable()
	}
	absolute, err := filepath.Abs(path)
	if err != nil || strings.HasPrefix(absolute, `\\`) {
		return nil, unavailable()
	}
	slash := filepath.ToSlash(absolute)
	if !strings.HasPrefix(slash, "/") {
		slash = "/" + slash
	}
	u := url.URL{Scheme: "file", Path: slash}
	q := u.Query()
	q.Set("mode", "rw")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, unavailable()
	}
	defer func() {
		if !keep {
			db.Close()
		}
	}()
	db.SetMaxOpenConns(1)
	if _, err = db.ExecContext(ctx, "PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA max_page_count="+fmtInt(c.MaxDatabaseBytes/4096)); err != nil {
		return nil, unavailable()
	}
	s := &Store{db: db, lock: lock, scope: scope, config: c, protector: p, reference: ref, byType: map[string][]string{}}
	scopeRaw, _ := json.Marshal(scope)
	cfgRaw, _ := json.Marshal(c)
	refRaw, _ := json.Marshal(ref)
	checkAAD := s.aad("", "", "identity")
	if create {
		sealed, err := p.Seal(checkAAD, append(append([]byte(nil), scopeRaw...), cfgRaw...))
		if err != nil || len(sealed) > c.MaxCipherBytes {
			return nil, unavailable()
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, unavailable()
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, schema); err != nil {
			return nil, unavailable()
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO identity VALUES(1,?,?,?,?)", scopeRaw, cfgRaw, refRaw, sealed); err != nil {
			return nil, unavailable()
		}
		for _, sub := range c.Subscriptions {
			if _, err = tx.ExecContext(ctx, "INSERT INTO subscriptions VALUES(?,0)", sub.ID); err != nil {
				return nil, unavailable()
			}
		}
		if err = tx.Commit(); err != nil {
			return nil, unavailable()
		}
		if privatefs.SyncDirectory(dir, "events.sqlite") != nil {
			return nil, unavailable()
		}
	}
	var version int
	var check string
	var savedScope, savedCfg, savedRef, sealed []byte
	if db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version) != nil || version != 1 || db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check) != nil || check != "ok" || db.QueryRowContext(ctx, "SELECT scope,config,key_ref,key_check FROM identity WHERE singleton=1 AND length(scope)<=16384 AND length(config)<=1048576 AND length(key_ref)<=1024 AND length(key_check)<=?", c.MaxCipherBytes).Scan(&savedScope, &savedCfg, &savedRef, &sealed) != nil {
		return nil, unavailable()
	}
	if string(savedScope) != string(scopeRaw) || string(savedCfg) != string(cfgRaw) || string(savedRef) != string(refRaw) {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Durable event scope/configuration/key reference mismatch")
	}
	plain, err := p.Open(checkAAD, sealed)
	if err != nil {
		return nil, unavailable()
	}
	defer clear(plain)
	if string(plain) != string(append(append([]byte(nil), scopeRaw...), cfgRaw...)) {
		return nil, unavailable()
	}
	for _, sub := range c.Subscriptions {
		for _, kind := range sub.Types {
			s.byType[kind] = append(s.byType[kind], sub.ID)
		}
	}
	if err = s.verify(ctx); err != nil {
		return nil, err
	}
	keep = true
	return s, nil
}
func fmtInt(n int64) string { // bounded PRAGMA integer, never interpolate operator strings
	b, _ := json.Marshal(n)
	return string(b)
}
func (s *Store) aad(source, id, digest string) []byte {
	b, _ := json.Marshal(struct {
		Version            string
		Scope              Scope
		Key                KeyReference
		Source, ID, Digest string
	}{"events-durable-1", s.scope, s.reference, source, id, digest})
	return b
}
func (s *Store) verify(ctx context.Context) error {
	var rows, bytes, totalRows, totalBytes int64
	if s.db.QueryRowContext(ctx, "SELECT rows,bytes FROM budget WHERE singleton=1").Scan(&rows, &bytes) != nil || s.db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM events)+(SELECT count(*) FROM deliveries),COALESCE(sum(length(cipher)+length(CAST(source AS BLOB))+length(CAST(id AS BLOB))+length(CAST(kind AS BLOB))+length(digest)+128+(SELECT COALESCE(sum(length(CAST(d.source AS BLOB))+length(CAST(d.id AS BLOB))+length(CAST(d.subscription AS BLOB))+1024),0) FROM deliveries d WHERE d.source=events.source AND d.id=events.id)),0) FROM events").Scan(&totalRows, &totalBytes) != nil || rows != totalRows || bytes != totalBytes || rows < 0 || rows > s.config.MaxRows || bytes < 0 || bytes > s.config.MaxBytes {
		return unavailable()
	}
	var bad int
	if s.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE cost != length(cipher)+length(CAST(source AS BLOB))+length(CAST(id AS BLOB))+length(CAST(kind AS BLOB))+length(digest)+128+(SELECT COALESCE(sum(length(CAST(d.source AS BLOB))+length(CAST(d.id AS BLOB))+length(CAST(d.subscription AS BLOB))+1024),0) FROM deliveries d WHERE d.source=events.source AND d.id=events.id)`).Scan(&bad) != nil || bad != 0 {
		return unavailable()
	}
	if s.db.QueryRowContext(ctx, `SELECT count(*) FROM subscriptions s WHERE pending != (SELECT count(*) FROM deliveries d WHERE d.subscription=s.id AND d.state IN ('pending','claimed')) OR pending<0 OR pending>?`, s.config.MaxPendingPerSubscription).Scan(&bad) != nil || bad != 0 {
		return unavailable()
	}
	if s.db.QueryRowContext(ctx, `SELECT count(*) FROM deliveries WHERE generation<0 OR attempt<0 OR attempt>? OR (state='claimed' AND (generation=0 OR attempt=0 OR length(token_hash)!=64 OR worker='' OR lease<=0)) OR (state!='claimed' AND (token_hash!='' OR worker!='' OR lease!=0))`, s.config.MaxAttempts).Scan(&bad) != nil || bad != 0 {
		return unavailable()
	}
	// Reopen validates every bounded ciphertext once, never at every append/claim.
	records, err := s.db.QueryContext(ctx, "SELECT source,id,digest,CASE WHEN length(cipher)<=? THEN cipher ELSE NULL END FROM events", s.config.MaxCipherBytes)
	if err != nil {
		return unavailable()
	}
	defer records.Close()
	for records.Next() {
		var source, id, digest string
		var cipher []byte
		if records.Scan(&source, &id, &digest, &cipher) != nil {
			return unavailable()
		}
		if _, err = s.decode(source, id, digest, cipher); err != nil {
			return err
		}
	}
	if records.Err() != nil {
		return unavailable()
	}
	return nil
}
func (s *Store) decode(source, id, digest string, cipher []byte) (event.Event, error) {
	if len(cipher) > s.config.MaxCipherBytes {
		return event.Event{}, unavailable()
	}
	raw, err := s.protector.Open(s.aad(source, id, digest), cipher)
	if err != nil {
		return event.Event{}, unavailable()
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != digest {
		return event.Event{}, unavailable()
	}
	e, err := events.Decode(raw, s.config.MaxEventBytes)
	if err != nil || e.Source() != source || e.ID() != id {
		return event.Event{}, unavailable()
	}
	return e, nil
}
func (s *Store) Publish(ctx context.Context, e event.Event) (Receipt, error) {
	if ctx == nil {
		return Receipt{}, invalid("Missing event context")
	}
	raw, err := events.Encode(e, s.config.MaxEventBytes)
	if err != nil {
		return Receipt{}, err
	}
	defer clear(raw)
	if !validText(e.Source(), 4096) || !validText(e.ID(), 256) || !validText(e.Type(), 256) {
		return Receipt{}, invalid("Invalid bounded event identity")
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	sealed, err := s.protector.Seal(s.aad(e.Source(), e.ID(), digest), raw)
	if err != nil || len(sealed) > s.config.MaxCipherBytes {
		return Receipt{}, unavailable()
	}
	defer clear(sealed)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Receipt{}, unavailable()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, unavailable()
	}
	defer tx.Rollback()
	var prior string
	var created int64
	err = tx.QueryRowContext(ctx, "SELECT digest,created FROM events WHERE source=? AND id=?", e.Source(), e.ID()).Scan(&prior, &created)
	if err == nil {
		if prior != digest {
			return Receipt{}, conflict()
		}
		return Receipt{Source: e.Source(), ID: e.ID(), Digest: digest, CommittedAt: time.Unix(0, created).UTC(), Duplicate: true}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, unavailable()
	}
	matched := s.byType[e.Type()]
	if len(matched) > s.config.MaxFanout {
		return Receipt{}, fabric.NewError(fabric.CodeTargetUnavailable, "Event fanout capacity exceeded")
	}
	cost := int64(len(sealed) + len(e.Source()) + len(e.ID()) + len(e.Type()) + len(digest) + 128)
	for _, sub := range matched {
		cost += int64(len(e.Source()) + len(e.ID()) + len(sub) + 1024)
	}
	var rows, bytes int64
	if tx.QueryRowContext(ctx, "SELECT rows,bytes FROM budget WHERE singleton=1").Scan(&rows, &bytes) != nil {
		return Receipt{}, unavailable()
	}
	if int64(1+len(matched)) > s.config.MaxRows-rows || cost > s.config.MaxBytes-bytes {
		return Receipt{}, fabric.NewError(fabric.CodeTargetUnavailable, "Durable event capacity exceeded")
	}
	for _, sub := range matched {
		var pending int64
		if tx.QueryRowContext(ctx, "SELECT pending FROM subscriptions WHERE id=?", sub).Scan(&pending) != nil {
			return Receipt{}, unavailable()
		}
		if pending >= s.config.MaxPendingPerSubscription {
			return Receipt{}, fabric.NewError(fabric.CodeTargetUnavailable, "Durable subscription capacity exceeded")
		}
	}
	now := time.Now().UTC()
	n := now.UnixNano()
	if n > math.MaxInt64-int64(s.config.DedupTTL) {
		return Receipt{}, invalid("Event timestamp outside retention range")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)", e.Source(), e.ID(), digest, e.Type(), sealed, n, n+int64(s.config.DeliveryTTL), n+int64(s.config.DedupTTL), cost); err != nil {
		return Receipt{}, unavailable()
	}
	for _, sub := range matched {
		if _, err = tx.ExecContext(ctx, "INSERT INTO deliveries VALUES(?,?,?,'pending',?,0,0,0,'','','')", sub, e.Source(), e.ID(), n); err != nil {
			return Receipt{}, unavailable()
		}
		if _, err = tx.ExecContext(ctx, "UPDATE subscriptions SET pending=pending+1 WHERE id=?", sub); err != nil {
			return Receipt{}, unavailable()
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE budget SET rows=rows+?,bytes=bytes+? WHERE singleton=1", 1+len(matched), cost); err != nil {
		return Receipt{}, unavailable()
	}
	if err = tx.Commit(); err != nil {
		return Receipt{}, unavailable()
	}
	return Receipt{Source: e.Source(), ID: e.ID(), Digest: digest, CommittedAt: now}, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.db.Close(), s.lock.Close())
}
