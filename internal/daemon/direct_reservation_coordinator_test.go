//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/nativedirect"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type reservationCoordinatorFake struct {
	t                                       *testing.T
	coordinator                             *directReservationCoordinator
	runtime                                 *runtimeBridgeFake
	source                                  nativedirect.NativeDirectASKSource
	mu                                      sync.Mutex
	result                                  *sessionworker.DirectASKReservation
	reserves, lookups                       int
	lost, unknown, absent, revoked, invalid bool
	concurrent                              bool
}

func (f *reservationCoordinatorFake) Inbox(_ context.Context, _ string, q transport.DirectInboxRequestV2) (transport.DirectInboxPageV2, error) {
	return transport.DirectInboxPageV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/inbox-page", Context: q.Context, Recipient: q.Recipient, Deliveries: []transport.DirectDeliveryV2{f.runtime.delivery}}, nil
}
func (f *reservationCoordinatorFake) reserveDirectASK(ctx context.Context, s nativedirect.NativeDirectASKSource, w json.RawMessage) (*sessionworker.DirectASKReservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key, _ := directReservationKey(s)
	record, err := f.coordinator.store.load(ctx, key)
	stageOK := record.Stage == "attempted" || f.concurrent && (record.Stage == "reserved" || record.Stage == "unknown")
	durableSource, _ := record.Source.CanonicalBytes()
	requestedSource, _ := s.CanonicalBytes()
	if err != nil || !stageOK || !bytes.Equal(durableSource, requestedSource) || !bytes.Equal(record.Wire, w) {
		f.t.Fatal("reserve before exact durable attempt", err)
	}
	f.reserves++
	if f.result != nil && f.result.Source.AdmissionID != s.AdmissionID {
		f.t.Fatal("changed admission id")
	}
	f.result = &sessionworker.DirectASKReservation{Source: s, Wire: bytes.Clone(w), State: "reserved"}
	if f.lost {
		return nil, errDirectEndpointRPCUnknown
	}
	return f.result, nil
}
func (f *reservationCoordinatorFake) lookupDirectASK(_ context.Context, s nativedirect.NativeDirectASKSource, w json.RawMessage) (*sessionworker.DirectASKReservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if f.absent {
		return nil, nil
	}
	if f.result == nil {
		return nil, nil
	}
	if f.result.Source.AdmissionID != s.AdmissionID || !bytes.Equal(f.result.Wire, w) {
		f.t.Fatal("lookup changed immutable record")
	}
	result := *f.result
	if f.unknown {
		result.State = "unknown"
	}
	return &result, nil
}
func reservationCoordinatorFixture(t *testing.T) (*directReservationCoordinator, *reservationCoordinatorFake) {
	_, runtime := runtimeBridgeFixture(t)
	source, _ := proxyDirectASKSource(t)
	source.NativeSessionID = runtime.binding.NativeSession
	source.NativeGeneration = runtime.binding.NativeGeneration
	source.Deadline = time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC)
	fake := &reservationCoordinatorFake{t: t, runtime: runtime, source: source}
	c := &directReservationCoordinator{store: &directReservationStore{registry: runtime.store.registry}}
	c.deps = directReservationDependencies{Binding: runtime.binding, Now: func() time.Time { return time.Date(2030, 1, 1, 0, 1, 0, 0, time.UTC) }, Client: fake, Worker: fake,
		Authority: func(ctx context.Context, _ directRuntimeBinding, use func(context.Context, string) error) error {
			if fake.revoked {
				return errDirectRuntimeRejected
			}
			if err := use(ctx, "credential-must-not-be-journaled"); err != nil {
				return errDirectEndpointOperationUnknown
			}
			return nil
		},
		Open: func(context.Context, transport.DirectChannelMessageV2, []byte) ([]byte, error) {
			if fake.invalid {
				return nil, errors.New("invalid ciphertext")
			}
			return []byte("plaintext-must-not-be-journaled"), nil
		},
		Source: func(context.Context) (nativedirect.NativeDirectASKSource, error) { return fake.source, nil }}
	fake.coordinator = c
	return c, fake
}
func TestDirectReservationCoordinatorDuplicateConcurrent(t *testing.T) {
	c, f := reservationCoordinatorFixture(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := c.ReceiveOne(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if f.reserves != 1 {
		t.Fatalf("reserves = %d", f.reserves)
	}
	if f.runtime.admits+f.runtime.resumes+f.runtime.sends+f.runtime.seals != 0 {
		t.Fatal("native or reply path reached")
	}
	var raw []byte
	err := c.store.locked(context.Background(), func(conn *sql.Conn) error {
		return conn.QueryRowContext(context.Background(), "SELECT record FROM native_direct_reservation_v1").Scan(&raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"plaintext-must-not-be-journaled", "credential-must-not-be-journaled"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret retained")
		}
	}
}
func TestDirectReservationCoordinatorConcurrentInstances(t *testing.T) {
	c, f := reservationCoordinatorFixture(t)
	f.concurrent = true
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			peer := &directReservationCoordinator{store: &directReservationStore{registry: c.store.registry}, deps: c.deps}
			// Contention may defer an attempt; it must never mint a second identity.
			_, _, _ = peer.ReceiveOne(context.Background())
		}()
	}
	wg.Wait()
	if f.result == nil {
		t.Fatal("no reservation")
	}
	savedID := f.result.Source.AdmissionID
	key, _ := directReservationKey(f.result.Source)
	if err := c.Recover(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	record, err := c.store.load(context.Background(), key)
	if err != nil || record.Source.AdmissionID != savedID {
		t.Fatal("concurrent identity changed", err)
	}
	var count int
	if err = c.store.locked(context.Background(), func(conn *sql.Conn) error {
		return conn.QueryRowContext(context.Background(), "SELECT count(*) FROM native_direct_reservation_v1").Scan(&count)
	}); err != nil || count != 1 {
		t.Fatal("duplicate daemon journal admission", err)
	}
}

func TestDirectReservationCoordinatorLostResponseRecovery(t *testing.T) {
	c, f := reservationCoordinatorFixture(t)
	f.lost = true
	key, found, err := c.ReceiveOne(context.Background())
	if err == nil || !found || key == "" {
		t.Fatal("lost response not uncertain")
	}
	oldID := f.result.Source.AdmissionID
	// Fresh daemon journal object and a new live lease never replace saved source.
	c.store = &directReservationStore{registry: c.store.registry}
	f.source.EndpointLeaseID = "fresh-live-lease"
	f.lost = false
	if err = c.Recover(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if f.reserves != 1 || f.lookups != 1 || f.result.Source.AdmissionID != oldID {
		t.Fatal("recovery redispatched or changed admission")
	}
	f.unknown = true
	if err = c.Recover(context.Background(), key); !errors.Is(err, errDirectReservationRecovery) {
		t.Fatalf("restart unknown: %v", err)
	}
	record, err := c.store.load(context.Background(), key)
	if err != nil || record.Stage != "unknown" {
		t.Fatal("unknown not retained", err)
	}
	if f.reserves != 1 {
		t.Fatal("unknown reserved again")
	}
}
func TestDirectReservationCoordinatorAbsenceDeadlineAndFences(t *testing.T) {
	for _, action := range []string{"absence", "expired", "revoked", "replacement", "consent", "invalid ciphertext"} {
		t.Run(action, func(t *testing.T) {
			c, f := reservationCoordinatorFixture(t)
			if action == "invalid ciphertext" {
				f.invalid = true
				if _, _, err := c.ReceiveOne(context.Background()); err == nil || f.reserves != 0 {
					t.Fatal("invalid ciphertext reserved")
				}
				return
			}
			f.lost = true
			key, _, err := c.ReceiveOne(context.Background())
			if err == nil {
				t.Fatal("expected lost response")
			}
			f.lost = false
			f.absent = true
			switch action {
			case "expired":
				c.deps.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 30, 0, 0, time.UTC) }
			case "revoked":
				f.revoked = true
			case "replacement":
				f.source.NativePID++
			case "consent":
				c.deps.Binding.ConsentRevision++
			}
			err = c.Recover(context.Background(), key)
			if action == "absence" {
				if err != nil || f.reserves != 2 {
					t.Fatal("explicit absence did not retry saved record", err)
				}
			} else if err == nil || f.reserves != 1 {
				t.Fatal("fence permitted reserve", err)
			}
		})
	}
}
func TestDirectReservationCoordinatorCommitFailureNoIPC(t *testing.T) {
	c, f := reservationCoordinatorFixture(t)
	c.store.poisoned = true
	if _, _, err := c.ReceiveOne(context.Background()); err == nil || f.reserves != 0 {
		t.Fatal("failed journal dispatched")
	}
}
func TestDirectReservationCoordinatorRealAuthorityConstructor(t *testing.T) {
	f, consent, reader, _ := runtimeAuthorityFixture(t)
	c, err := newDirectTargetReservationCoordinatorWithReader(t.Context(), f.d, f.captured, f.s, f.target, consent, 1, reader)
	if err != nil {
		t.Fatal(err)
	}
	if c.deps.Worker != f.s.binding.proxy || c.deps.Binding.ConsentRevision != 1 || !strings.Contains(f.s.binding.leaseID, "-") {
		t.Fatal("constructor lost live source")
	}
	f.s.Remove()
	if _, _, err = c.ReceiveOne(t.Context()); err == nil {
		t.Fatal("revoked real authority admitted inbox")
	}
}
