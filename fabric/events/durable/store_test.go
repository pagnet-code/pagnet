package durable

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
)

func fixtureEvent(t *testing.T, id string) event.Event {
	t.Helper()
	e := event.New("1.0")
	e.SetID(id)
	e.SetSource("urn:fixture:original-source")
	e.SetType("fixture.original")
	e.SetTime(time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC))
	if err := e.SetData("application/json", json.RawMessage(`{"private":"durable-original-secret-fixture","n":9007199254740993123456789}`)); err != nil {
		t.Fatal(err)
	}
	return e
}
func fixtureConfig() Config {
	c := DefaultConfig([]Subscription{{ID: "fixture.observer", Types: []string{"fixture.original"}}})
	c.MaxEventBytes = 65536
	c.MaxCipherBytes = 69632
	c.MaxBytes = 1 << 20
	c.MaxDatabaseBytes = 4 << 20
	c.LeaseTTL = 100 * time.Millisecond
	c.RetryDelay = time.Millisecond
	return c
}
func fixtureKey(t *testing.T) ([]byte, *AESGCM) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	p, err := NewAESGCM(KeyReference{ID: "operator-fixture", Version: "1"}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, p
}
func fixtureStore(t *testing.T, c Config) (*Store, string, Scope, *AESGCM) {
	t.Helper()
	_, p := fixtureKey(t)
	dir := filepath.Join(t.TempDir(), "private-events")
	scope := Scope{Audience: "fixture.node", Domain: "urn:fixture:immutable-domain"}
	s, err := Bootstrap(t.Context(), dir, scope, c, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir, scope, p
}
func requirePublish(t *testing.T, s *Store, e event.Event) Receipt {
	t.Helper()
	r, err := s.Publish(t.Context(), e)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func requireClaim(t *testing.T, s *Store, now time.Time) Delivery {
	t.Helper()
	d, ok, err := s.Claim(t.Context(), "fixture.observer", "fixture.worker", now)
	if err != nil || !ok {
		t.Fatal("expected original delivery", ok, err)
	}
	return d
}

func TestEncryptedRestartExactIdentityConflictAndWrongKeys(t *testing.T) {
	s, dir, scope, p := fixtureStore(t, fixtureConfig())
	e := fixtureEvent(t, "original")
	r := requirePublish(t, s, e)
	if r.Duplicate || r.CommittedAt.IsZero() {
		t.Fatal("receipt precedes genuine commit")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "events.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, e.Data()) || bytes.Contains(data, []byte("durable-original-secret-fixture")) {
		t.Fatal("event payload persisted in plaintext")
	}
	reopened, err := Open(t.Context(), dir, scope, fixtureConfig(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	duplicate := requirePublish(t, reopened, e)
	if !duplicate.Duplicate || duplicate.Digest != r.Digest || !duplicate.CommittedAt.Equal(r.CommittedAt) {
		t.Fatal("reopen changed durable identity")
	}
	changed := e.Clone()
	_ = changed.SetData("application/json", json.RawMessage(`{"different":true}`))
	if _, err := reopened.Publish(t.Context(), changed); err == nil {
		t.Fatal("same identity replaced original content")
	}
	d := requireClaim(t, reopened, time.Now())
	if !bytes.Contains(d.Event.Data(), []byte("9007199254740993123456789")) {
		t.Fatal("large original number changed")
	}
	_ = reopened.Close()
	_, wrong := fixtureKey(t)
	if opened, err := Open(t.Context(), dir, scope, fixtureConfig(), wrong); err == nil {
		opened.Close()
		t.Fatal("wrong same-reference key accepted")
	}
	changedScope := scope
	changedScope.Domain = "urn:fixture:other-domain"
	if opened, err := Open(t.Context(), dir, changedScope, fixtureConfig(), p); err == nil {
		opened.Close()
		t.Fatal("foreign domain opened state")
	}
	c := fixtureConfig()
	c.Subscriptions = nil
	if opened, err := Open(t.Context(), dir, scope, c, p); err == nil {
		opened.Close()
		t.Fatal("subscriptions silently removed on reopen")
	}
}
func TestCipherTamperAndMissingStoreFailClosed(t *testing.T) {
	s, dir, scope, p := fixtureStore(t, fixtureConfig())
	requirePublish(t, s, fixtureEvent(t, "tampered"))
	if _, err := s.db.Exec("UPDATE events SET cipher=zeroblob(length(cipher))"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if opened, err := Open(t.Context(), dir, scope, fixtureConfig(), p); err == nil {
		opened.Close()
		t.Fatal("tampered original payload opened")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if err := os.Mkdir(missing, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), missing, scope, fixtureConfig(), p); err == nil {
		t.Fatal("missing store regenerated")
	}
	if _, err := os.Stat(filepath.Join(missing, "events.sqlite")); !os.IsNotExist(err) {
		t.Fatal("Open created missing database")
	}
}
func TestConcurrentClaimLeaseCASAndLateAck(t *testing.T) {
	s, _, _, _ := fixtureStore(t, fixtureConfig())
	r := requirePublish(t, s, fixtureEvent(t, "one"))
	now := r.CommittedAt.Add(time.Millisecond)
	var winners atomic.Int32
	var won Delivery
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, ok, err := s.Claim(t.Context(), "fixture.observer", "fixture.worker", now)
			if err != nil {
				t.Error(err)
			}
			if ok {
				winners.Add(1)
				mu.Lock()
				won = d
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("one lease acquired by multiple workers")
	}
	wrong := won.Claim
	wrong.Worker = "foreign.worker"
	if s.Ack(t.Context(), wrong, now) == nil {
		t.Fatal("foreign worker settled lease")
	}
	wrong = won.Claim
	wrong.Token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if s.Nack(t.Context(), wrong, now) == nil {
		t.Fatal("substituted claim token settled lease")
	}
	next := requireClaim(t, s, won.LeaseUntil.Add(time.Millisecond))
	if next.Claim.Generation != won.Claim.Generation+1 || next.Attempt != 2 {
		t.Fatal("expired original lease not durably superseded")
	}
	if s.Ack(t.Context(), won.Claim, next.LeaseUntil.Add(-time.Millisecond)) == nil {
		t.Fatal("late acknowledgement crossed generation")
	}
	if err := s.Ack(t.Context(), next.Claim, next.LeaseUntil.Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if s.Ack(t.Context(), next.Claim, next.LeaseUntil.Add(-time.Millisecond)) == nil {
		t.Fatal("settled claim accepted again")
	}
	st, err := s.State(t.Context())
	if err != nil || st.Acknowledged != 1 || st.Pending+st.Claimed != 0 {
		t.Fatal("wrong durable settlement state", st, err)
	}
}
func TestAtomicFanoutBudgetsAndExplicitDedupPurge(t *testing.T) {
	c := fixtureConfig()
	c.Subscriptions = append(c.Subscriptions, Subscription{ID: "fixture.other", Types: []string{"fixture.original"}})
	c.MaxPendingPerSubscription = 1
	c.DeliveryTTL = 5 * time.Millisecond
	c.DedupTTL = 10 * time.Millisecond
	s, _, _, _ := fixtureStore(t, c)
	e := fixtureEvent(t, "fanout")
	r := requirePublish(t, s, e)
	if _, err := s.Publish(t.Context(), fixtureEvent(t, "overflow")); err == nil {
		t.Fatal("per-subscription bound ignored")
	}
	st, _ := s.State(t.Context())
	if st.Pending != 2 || st.Rows != 3 {
		t.Fatal("partial fanout persisted", st)
	}
	if n, err := s.Purge(t.Context(), time.Now(), 10); err != nil || n != 0 {
		t.Fatal("unsettled/young identity purged")
	}
	for _, sub := range c.Subscriptions {
		d, ok, err := s.Claim(t.Context(), sub.ID, "fixture.worker", r.CommittedAt.Add(time.Millisecond))
		if err != nil || !ok {
			t.Fatal(err)
		}
		if s.Ack(t.Context(), d.Claim, r.CommittedAt.Add(2*time.Millisecond)) != nil {
			t.Fatal("ack failed")
		}
	}
	if n, err := s.Purge(t.Context(), r.CommittedAt, 10); err != nil || n != 0 {
		t.Fatal("tombstone retention shortened")
	}
	time.Sleep(15 * time.Millisecond)
	if n, err := s.Purge(t.Context(), time.Now(), 10); err != nil || n != 1 {
		t.Fatal("eligible explicit purge failed", n, err)
	}
	st, _ = s.State(t.Context())
	if st.Rows != 0 || st.Bytes != 0 {
		t.Fatal("purge leaked reservations", st)
	}
	newReceipt := requirePublish(t, s, e)
	if newReceipt.Duplicate {
		t.Fatal("explicit expiry did not forget identity")
	}
}
func TestExhaustedRetryAndExpiryAreFailureNotAcknowledgement(t *testing.T) {
	c := fixtureConfig()
	c.MaxAttempts = 2
	s, _, _, _ := fixtureStore(t, c)
	r := requirePublish(t, s, fixtureEvent(t, "retry"))
	now := r.CommittedAt.Add(time.Millisecond)
	d := requireClaim(t, s, now)
	if s.Nack(t.Context(), d.Claim, now) != nil {
		t.Fatal("first nack")
	}
	d = requireClaim(t, s, now.Add(c.RetryDelay))
	if s.Nack(t.Context(), d.Claim, now.Add(c.RetryDelay)) != nil {
		t.Fatal("final nack")
	}
	st, _ := s.State(t.Context())
	if st.Failed != 1 || st.Acknowledged != 0 || st.Pending+st.Claimed != 0 {
		t.Fatal("retry exhaustion misrepresented", st)
	}
	r = requirePublish(t, s, fixtureEvent(t, "expires"))
	if _, ok, err := s.Claim(t.Context(), "fixture.observer", "fixture.worker", r.CommittedAt.Add(c.DeliveryTTL)); err != nil || ok {
		t.Fatal("expired event delivered")
	}
	st, _ = s.State(t.Context())
	if st.Failed != 2 {
		t.Fatal("expiry silently dropped")
	}
}
func TestAESGCMOwnsSuppliedSecretAndBindsAAD(t *testing.T) {
	key, p := fixtureKey(t)
	clear(key)
	cipher, err := p.Seal([]byte("exact-scope"), []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Open([]byte("other-scope"), cipher); err == nil {
		t.Fatal("AAD substitution accepted")
	}
	plain, err := p.Open([]byte("exact-scope"), cipher)
	if err != nil || string(plain) != "original" {
		t.Fatal("caller key mutation affected private copy")
	}
}

func TestCrashCommittedReceiptReopensWithAtLeastOnceDelivery(t *testing.T) {
	if os.Getenv("PAGNET_EVENT_CRASH_FIXTURE") == "1" {
		key, err := hex.DecodeString(os.Getenv("PAGNET_EVENT_FIXTURE_KEY"))
		if err != nil {
			os.Exit(2)
		}
		p, err := NewAESGCM(KeyReference{ID: "operator-fixture", Version: "1"}, key)
		if err != nil {
			os.Exit(3)
		}
		s, err := Bootstrap(context.Background(), os.Getenv("PAGNET_EVENT_FIXTURE_DIR"), Scope{Audience: "fixture.node", Domain: "urn:fixture:immutable-domain"}, fixtureConfig(), p)
		if err != nil {
			os.Exit(4)
		}
		r, err := s.Publish(context.Background(), fixtureEvent(t, "crash-original"))
		if err != nil {
			os.Exit(5)
		}
		raw, _ := json.Marshal(r)
		if os.WriteFile(os.Getenv("PAGNET_EVENT_FIXTURE_RECEIPT"), raw, 0600) != nil {
			os.Exit(6)
		}
		os.Exit(0) // no Close; genuine process death releases writer ownership
	}
	key, p := fixtureKey(t)
	dir := filepath.Join(t.TempDir(), "crashed")
	receiptPath := filepath.Join(t.TempDir(), "receipt")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashCommittedReceiptReopensWithAtLeastOnceDelivery$")
	cmd.Env = append(os.Environ(), "PAGNET_EVENT_CRASH_FIXTURE=1", "PAGNET_EVENT_FIXTURE_KEY="+hex.EncodeToString(key), "PAGNET_EVENT_FIXTURE_DIR="+dir, "PAGNET_EVENT_FIXTURE_RECEIPT="+receiptPath)
	if err := cmd.Run(); err != nil {
		t.Fatal("crash fixture failed", err)
	}
	s, err := Open(t.Context(), dir, Scope{Audience: "fixture.node", Domain: "urn:fixture:immutable-domain"}, fixtureConfig(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := requirePublish(t, s, fixtureEvent(t, "crash-original"))
	if !r.Duplicate {
		t.Fatal("committed identity disappeared after death")
	}
	saved, _ := os.ReadFile(receiptPath)
	var original Receipt
	if json.Unmarshal(saved, &original) != nil || original.Digest != r.Digest || !original.CommittedAt.Equal(r.CommittedAt) {
		t.Fatal("receipt not backed by genuine restart durable state")
	}
	d := requireClaim(t, s, time.Now())
	if d.Event.ID() != "crash-original" {
		t.Fatal("original delivery missing")
	}
}

func TestExpiryWithoutConsumerIsExplicitFailureAndBudgetTamperRejected(t *testing.T) {
	c := fixtureConfig()
	c.DeliveryTTL = 5 * time.Millisecond
	c.DedupTTL = 10 * time.Millisecond
	s, dir, scope, p := fixtureStore(t, c)
	e := fixtureEvent(t, "unconsumed")
	requirePublish(t, s, e)
	time.Sleep(15 * time.Millisecond)
	if n, err := s.Purge(t.Context(), time.Now(), 1); err != nil || n != 0 {
		t.Fatal("purge silently lost unconsumed event")
	}
	if n, err := s.Expire(t.Context(), time.Now(), 1); err != nil || n != 1 {
		t.Fatal("explicit expiry failed", n, err)
	}
	st, err := s.Inspect(t.Context(), "fixture.observer", e.Source(), e.ID())
	if err != nil || st.State != "failed" || st.Reason != "delivery_expired" {
		t.Fatal("expiry not observable", st, err)
	}
	if n, err := s.Purge(t.Context(), time.Now(), 1); err != nil || n != 1 {
		t.Fatal("expired delivery could not be explicitly purged")
	}
	requirePublish(t, s, fixtureEvent(t, "tamper-count"))
	if _, err := s.db.Exec("UPDATE subscriptions SET pending=0"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if reopened, err := Open(t.Context(), dir, scope, c, p); err == nil {
		reopened.Close()
		t.Fatal("tampered subscription accounting accepted")
	}
}

func TestGlobalRowAdmissionDoesNotCommitPartialFanout(t *testing.T) {
	c := fixtureConfig()
	c.MaxRows = 1
	c.MaxPendingPerSubscription = 1
	s, _, _, _ := fixtureStore(t, c)
	if _, err := s.Publish(t.Context(), fixtureEvent(t, "too-many-rows")); err == nil {
		t.Fatal("global row limit ignored")
	}
	st, err := s.State(t.Context())
	if err != nil || st.Rows != 0 || st.Bytes != 0 || st.Pending != 0 {
		t.Fatal("rejected fanout partially persisted", st, err)
	}
}
