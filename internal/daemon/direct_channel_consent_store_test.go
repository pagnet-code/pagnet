//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func consentFixture(t *testing.T) (*directChannelConsentStore, directChannelConsentBinding) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	r, e := OpenNativeWorkerRegistry(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	s, e := newDirectChannelConsentStore(context.Background(), r, "https://example.test", transport.HostSessionPayload{TenantID: "tenant", AccountID: "account", HostID: "host"})
	if e != nil {
		t.Fatal(e)
	}
	return s, directChannelConsentBinding{Key: directChannelConsentKey{Server: s.server, Tenant: s.tenant, Account: s.account, Host: s.host, Intent: "intent", Role: "S", Principal: "principal"}, Instance: "instance", Origin: "origin", OwnershipGeneration: "ownership", NativeGeneration: "native", AuthorizationSnapshotDigest: strings.Repeat("a", 64), PeerPrincipal: "peer", GrantID: "grant", GrantGeneration: 1, Epoch: "epoch", ExpiresAt: "2099-01-01T00:00:00Z"}
}
func TestDirectConsentPersistenceCAS(t *testing.T) {
	s, b := consentFixture(t)
	ctx := context.Background()
	missing, e := s.Get(ctx, b.Key)
	if e != nil || missing.Enabled || missing.Revision != 0 {
		t.Fatalf("missing: %+v %v", missing, e)
	}
	first, e := s.Enable(ctx, b, 0, "enable-1")
	if e != nil || first.Revision != 1 || !first.Enabled {
		t.Fatalf("enable: %+v %v", first, e)
	}
	retry, e := s.Enable(ctx, b, 0, "enable-1")
	if e != nil || !reflect.DeepEqual(first, retry) {
		t.Fatal("enable retry", e)
	}
	changed := b
	changed.NativeGeneration = "replacement"
	if _, e = s.Enable(ctx, changed, 0, "enable-1"); e == nil {
		t.Fatal("changed retry accepted")
	}
	if _, e = s.Enable(ctx, changed, 0, "enable-2"); e == nil {
		t.Fatal("stale replacement accepted")
	}
	replacement, e := s.Enable(ctx, changed, 1, "enable-2")
	if e != nil || replacement.Binding.NativeGeneration != "replacement" {
		t.Fatal("replacement", e)
	}
	if _, e = s.Disable(ctx, b.Key, 1, "disable"); e == nil {
		t.Fatal("stale disable accepted")
	}
	disabled, e := s.Disable(ctx, b.Key, 2, "disable")
	if e != nil || disabled.Enabled || disabled.Revision != 3 {
		t.Fatal("disable", e)
	}
	retry, e = s.Disable(ctx, b.Key, 2, "disable")
	if e != nil || !reflect.DeepEqual(disabled, retry) {
		t.Fatal("disable retry", e)
	}
	if _, e = s.Enable(ctx, b, 0, "enable-1"); e == nil {
		t.Fatal("old retry resurrected consent")
	}
	if _, e = s.Enable(ctx, b, 3, "disable"); e == nil {
		t.Fatal("mutation ID reused")
	}
	if _, e = s.Disable(ctx, b.Key, 3, "disable-again"); e != nil {
		t.Fatal(e)
	}
	// Reopen the registry itself, not merely the in-memory store.
	path := filepath.Dir(s.registry.root)
	if e = s.registry.Close(); e != nil {
		t.Fatal(e)
	}
	r, e := OpenNativeWorkerRegistry(path)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	reopened, e := newDirectChannelConsentStore(ctx, r, s.server, transport.HostSessionPayload{TenantID: s.tenant, AccountID: s.account, HostID: s.host})
	if e != nil {
		t.Fatal(e)
	}
	got, e := reopened.Get(ctx, b.Key)
	if e != nil || got.Enabled || got.Revision != 4 {
		t.Fatalf("restart: %+v %v", got, e)
	}
	other := b.Key
	other.Intent = "absent"
	got, e = reopened.Disable(ctx, other, 0, "disable-absent")
	if e != nil || got.Revision != 1 {
		t.Fatal("absent tombstone", e)
	}
	all, e := reopened.List(ctx)
	if e != nil || len(all) != 2 {
		t.Fatal("list", e)
	}
}
func TestDirectConsentScopeAndBindingValidation(t *testing.T) {
	s, b := consentFixture(t)
	ctx := context.Background()
	for _, field := range []string{"server", "tenant", "account", "host", "role", "principal", "intent"} {
		t.Run(field, func(t *testing.T) {
			bad := b
			switch field {
			case "server":
				bad.Key.Server = "https://other.test"
			case "tenant":
				bad.Key.Tenant = "other"
			case "account":
				bad.Key.Account = "other"
			case "host":
				bad.Key.Host = "other"
			case "role":
				bad.Key.Role = "X"
			case "principal":
				bad.Key.Principal = ""
			case "intent":
				bad.Key.Intent = ""
			}
			if _, e := s.Enable(ctx, bad, 0, "id"); e == nil {
				t.Fatal("scope accepted")
			}
			if _, e := s.Disable(ctx, bad.Key, 0, "id"); e == nil {
				t.Fatal("disable scope accepted")
			}
			if _, e := s.Get(ctx, bad.Key); e == nil {
				t.Fatal("get scope accepted")
			}
		})
	}
	for _, field := range []string{"digest", "expiry", "grant", "instance", "origin", "generation", "native", "peer", "epoch"} {
		t.Run(field, func(t *testing.T) {
			bad := b
			switch field {
			case "digest":
				bad.AuthorizationSnapshotDigest = strings.Repeat("A", 64)
			case "expiry":
				bad.ExpiresAt = "2099-01-01T01:00:00+01:00"
			case "grant":
				bad.GrantGeneration = 0
			case "instance":
				bad.Instance = ""
			case "origin":
				bad.Origin = ""
			case "generation":
				bad.OwnershipGeneration = ""
			case "native":
				bad.NativeGeneration = ""
			case "peer":
				bad.PeerPrincipal = bad.Key.Principal
			case "epoch":
				bad.Epoch = ""
			}
			if _, e := s.Enable(ctx, bad, 0, "id"); e == nil {
				t.Fatal("binding accepted")
			}
		})
	}
	if _, e := s.Enable(ctx, b, -1, "id"); e == nil {
		t.Fatal("negative revision")
	}
	if _, e := s.Disable(ctx, b.Key, math.MaxInt64, "id"); e == nil {
		t.Fatal("overflow")
	}
	if _, e := newDirectChannelConsentStore(ctx, s.registry, "https://EXAMPLE.test/", transport.HostSessionPayload{TenantID: s.tenant, AccountID: s.account, HostID: s.host}); e == nil {
		t.Fatal("noncanonical server")
	}
}
func TestDirectConsentCorruption(t *testing.T) {
	cases := []string{`UPDATE native_direct_channel_consent_v1 SET version=2`, `UPDATE native_direct_channel_consent_v1 SET revision=9223372036854775807,last_expected_revision=9223372036854775806`, `UPDATE native_direct_channel_consent_v1 SET binding=x'7b7d'`, `UPDATE native_direct_channel_consent_v1 SET request_digest=zeroblob(32)`, `UPDATE native_direct_channel_consent_v1 SET binding=zeroblob(16385)`, `ALTER TABLE native_direct_channel_consent_v1 ADD COLUMN extra TEXT`}
	for i, q := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			s, b := consentFixture(t)
			ctx := context.Background()
			if _, e := s.Enable(ctx, b, 0, "id"); e != nil {
				t.Fatal(e)
			}
			if _, e := s.registry.db.Exec(`PRAGMA ignore_check_constraints=ON`); e != nil {
				t.Fatal(e)
			}
			if _, e := s.registry.db.Exec(q); e != nil {
				t.Fatal(e)
			}
			if _, e := s.Get(ctx, b.Key); e == nil {
				t.Fatal("corruption accepted")
			}
			if _, e := s.List(ctx); e == nil {
				t.Fatal("corrupt list accepted")
			}
		})
	}
}
func TestDirectConsentCapacity(t *testing.T) {
	s, b := consentFixture(t)
	ctx := context.Background()
	// Seed through the same checked mutation path within one transaction to keep
	// the capacity test focused on the bound rather than filesystem sync cost.
	e := s.locked(ctx, func(c *sql.Conn) error {
		for i := 0; i < directChannelConsentMaxRecords; i++ {
			k := b.Key
			k.Intent = fmt.Sprint(i)
			digest := consentRequestDigest("disable", k, nil, 0)
			if _, e := c.ExecContext(ctx, `INSERT INTO native_direct_channel_consent_v1 VALUES(?,?,?,?,?,?,?,?,1,1,0,?,'seed',0,'disable',?)`, s.installation, k.Server, k.Tenant, k.Account, k.Host, k.Intent, k.Role, k.Principal, []byte("null"), digest); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Enable(ctx, b, 0, "full"); e == nil {
		t.Fatal("capacity exceeded")
	}
	if _, e = s.Disable(ctx, b.Key, 0, "full"); e == nil {
		t.Fatal("absent disable exceeded capacity")
	}
	k := b.Key
	k.Intent = "0"
	if _, e = s.Disable(ctx, k, 1, "disable-existing"); e != nil {
		t.Fatal("existing disable blocked", e)
	}
	if _, e = s.Enable(ctx, func() directChannelConsentBinding { x := b; x.Key = k; return x }(), 2, "enable-existing"); e != nil {
		t.Fatal(e)
	}
	digest := consentRequestDigest("disable", b.Key, nil, 0)
	if _, e = s.registry.db.Exec(`INSERT INTO native_direct_channel_consent_v1 VALUES(?,?,?,?,?,?,?,?,1,1,0,?,'overflow-row',0,'disable',?)`, s.installation, b.Key.Server, b.Key.Tenant, b.Key.Account, b.Key.Host, b.Key.Intent, b.Key.Role, b.Key.Principal, []byte("null"), digest); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Get(ctx, k); e == nil {
		t.Fatal("corrupt capacity overflow accepted")
	}

}
func TestDirectConsentCancellationAndLocks(t *testing.T) {
	s, b := consentFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.Enable(ctx, b, 0, "cancelled"); e == nil {
		t.Fatal("cancelled accepted")
	}
	s.registry.mu.Lock()
	ctx, cancel = context.WithTimeout(context.Background(), 25*time.Millisecond)
	_, e := s.Get(ctx, b.Key)
	cancel()
	s.registry.mu.Unlock()
	if e == nil {
		t.Fatal("mutex contention ignored")
	}
	root, e := nativeRegistryProtectedDirectory(s.registry.root)
	if e != nil {
		t.Fatal(e)
	}
	lock, e := nativeRegistryCustodyLock(root)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 25*time.Millisecond)
	_, e = s.Get(ctx, b.Key)
	cancel()
	lock.Close()
	root.Close()
	if e == nil {
		t.Fatal("custody contention ignored")
	}
	c, e := s.registry.db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	// Registry uses one connection: borrow a second independently opened registry.
	other, e := OpenNativeWorkerRegistry(filepath.Dir(s.registry.root))
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = c.ExecContext(context.Background(), "BEGIN IMMEDIATE"); e != nil {
		t.Fatal(e)
	}
	peer, e := newDirectChannelConsentStore(context.Background(), other, s.server, transport.HostSessionPayload{TenantID: s.tenant, AccountID: s.account, HostID: s.host})
	if e == nil {
		t.Fatal("SQLite contention ignored", peer)
	}
	c.ExecContext(context.Background(), "ROLLBACK")
	c.Close()
	ctx, cancel = context.WithCancel(context.Background())
	e = s.locked(ctx, func(*sql.Conn) error { cancel(); return nil })
	if !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation not preserved", e)
	}
	if _, e = s.Enable(context.Background(), b, 0, "recovered"); e != nil {
		t.Fatal("cleanup failed", e)
	}
}
func TestDirectConsentUncertainCommit(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			s, b := consentFixture(t)
			ctx := context.Background()
			e := s.locked(ctx, func(c *sql.Conn) error {
				digest := consentRequestDigest("disable", b.Key, nil, 0)
				if _, e := c.ExecContext(ctx, `INSERT INTO native_direct_channel_consent_v1 VALUES(?,?,?,?,?,?,?,?,1,1,0,?,'uncertain',0,'disable',?)`, s.installation, b.Key.Server, b.Key.Tenant, b.Key.Account, b.Key.Host, b.Key.Intent, b.Key.Role, b.Key.Principal, []byte("null"), digest); e != nil {
					return e
				}
				operation := "ROLLBACK"
				if committed {
					operation = "COMMIT"
				}
				_, e := c.ExecContext(ctx, operation)
				return e
			})
			if e == nil || !s.poisoned {
				t.Fatal("uncertain commit did not poison handle")
			}
			if _, e = s.Get(ctx, b.Key); e == nil {
				t.Fatal("poisoned store usable")
			}
			fresh, e := newDirectChannelConsentStore(ctx, s.registry, s.server, transport.HostSessionPayload{TenantID: s.tenant, AccountID: s.account, HostID: s.host})
			if e != nil {
				t.Fatal("connection cleanup failed", e)
			}
			recovered, e := fresh.Get(ctx, b.Key)
			if e != nil {
				t.Fatal(e)
			}
			expected := int64(0)
			if committed {
				expected = 1
			}
			if recovered.Revision != expected || recovered.Enabled {
				t.Fatal("incorrect uncertain-commit recovery", recovered)
			}
			if _, e = fresh.Enable(ctx, b, expected, "fresh"); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestDirectConsentExpiry(t *testing.T) {
	s, b := consentFixture(t)
	ctx := context.Background()
	b.ExpiresAt = time.Now().UTC().Format(time.RFC3339Nano)
	if _, e := s.Enable(ctx, b, 0, "boundary"); e == nil {
		t.Fatal("expired Enable accepted")
	}
	b.ExpiresAt = time.Now().Add(75 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	first, e := s.Enable(ctx, b, 0, "first")
	if e != nil {
		t.Fatal(e)
	}
	expiry, _ := time.Parse(time.RFC3339Nano, b.ExpiresAt)
	time.Sleep(time.Until(expiry) + time.Millisecond)
	retry, e := s.Enable(ctx, b, 0, "first")
	if e != nil || !reflect.DeepEqual(first, retry) {
		t.Fatal("expired exact retry rejected", e)
	}
	if _, e = s.Enable(ctx, b, 1, "expired-new"); e == nil {
		t.Fatal("new expired enable accepted")
	}
	if _, e = s.Disable(ctx, b.Key, 1, "expired-disable"); e != nil {
		t.Fatal(e)
	}
}
func TestDirectConsentRegistryEnrollmentUnchanged(t *testing.T) {
	j, sub, binding, _ := enrollmentFixture(t)
	ctx := context.Background()
	if _, e := j.reserve(sub, binding); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadDir(j.registry.root)
	if e != nil {
		t.Fatal(e)
	}
	var version int
	var payload, mac, fence, fenceMAC []byte
	if e = j.registry.db.QueryRow(`PRAGMA user_version`).Scan(&version); e != nil {
		t.Fatal(e)
	}
	if e = j.registry.db.QueryRow(`SELECT payload,mac FROM native_direct_enrollment_v1`).Scan(&payload, &mac); e != nil {
		t.Fatal(e)
	}
	if e = j.registry.db.QueryRow(`SELECT binding,mac FROM native_direct_enrollment_v1_fences`).Scan(&fence, &fenceMAC); e != nil {
		t.Fatal(e)
	}
	s, e := newDirectChannelConsentStore(ctx, j.registry, "https://example.test", transport.HostSessionPayload{TenantID: "tenant", AccountID: "account", HostID: "host"})
	if e != nil {
		t.Fatal(e)
	}
	k := directChannelConsentKey{Server: s.server, Tenant: s.tenant, Account: s.account, Host: s.host, Intent: "intent", Role: "S", Principal: "principal"}
	if _, e = s.Disable(ctx, k, 0, "disable"); e != nil {
		t.Fatal(e)
	}
	after, e := os.ReadDir(j.registry.root)
	if e != nil {
		t.Fatal(e)
	}
	names := func(entries []os.DirEntry) []string {
		out := []string{}
		for _, entry := range entries {
			out = append(out, entry.Name())
		}
		return out
	}
	if !reflect.DeepEqual(names(before), names(after)) {
		t.Fatal("consent created files")
	}
	var gotVersion int
	var gotPayload, gotMAC, gotFence, gotFenceMAC []byte
	if e = j.registry.db.QueryRow(`PRAGMA user_version`).Scan(&gotVersion); e != nil {
		t.Fatal(e)
	}
	if e = j.registry.db.QueryRow(`SELECT payload,mac FROM native_direct_enrollment_v1`).Scan(&gotPayload, &gotMAC); e != nil {
		t.Fatal(e)
	}
	if e = j.registry.db.QueryRow(`SELECT binding,mac FROM native_direct_enrollment_v1_fences`).Scan(&gotFence, &gotFenceMAC); e != nil {
		t.Fatal(e)
	}
	if version != gotVersion || !reflect.DeepEqual([][]byte{payload, mac, fence, fenceMAC}, [][]byte{gotPayload, gotMAC, gotFence, gotFenceMAC}) {
		t.Fatal("enrollment or schema version changed")
	}
}

func TestDirectConsentRevisionOverflow(t *testing.T) {
	s, b := consentFixture(t)
	ctx := context.Background()
	if _, e := s.Disable(ctx, b.Key, 0, "last"); e != nil {
		t.Fatal(e)
	}
	digest := consentRequestDigest("disable", b.Key, nil, math.MaxInt64-1)
	if _, e := s.registry.db.Exec(`UPDATE native_direct_channel_consent_v1 SET revision=?,last_expected_revision=?,request_digest=?`, int64(math.MaxInt64), int64(math.MaxInt64-1), digest); e != nil {
		t.Fatal(e)
	}
	r, e := s.Get(ctx, b.Key)
	if e != nil || r.Revision != math.MaxInt64 {
		t.Fatal("valid terminal revision", e)
	}
	if _, e = s.Disable(ctx, b.Key, math.MaxInt64, "overflow"); e == nil {
		t.Fatal("disable overflow accepted")
	}
	if _, e = s.Enable(ctx, b, math.MaxInt64, "overflow"); e == nil {
		t.Fatal("enable overflow accepted")
	}
	if _, e = s.Disable(ctx, b.Key, math.MaxInt64-1, "last"); e != nil {
		t.Fatal("exact terminal retry rejected", e)
	}
}
