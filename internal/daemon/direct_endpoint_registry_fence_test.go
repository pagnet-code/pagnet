//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func directEndpointRegistryFence(t *testing.T, d *Daemon, token *nativeWorkerPublicationToken, kind string) func(bool) error {
	t.Helper()
	record, err := d.nativeRegistry.Lookup(token.instanceID)
	if err != nil {
		t.Fatal(err)
	}
	if kind == "gc" {
		payload := transport.ForgetInstancePayload{CommandID: domain.NewID().String(), DeleteRequestID: domain.NewID().String(), InstanceID: token.instanceID, NativeOwnership: record.Ownership}
		return func(conflict bool) error {
			p := payload
			if conflict {
				p.DeleteRequestID = domain.NewID().String()
			}
			_, err := d.nativeRegistry.beginGC(record, p)
			return err
		}
	}
	boot := recoveryBoot("11111111-1111-4111-8111-111111111111")
	recovery := NativeWorkerRecovery{RecoveryID: domain.NewID().String(), InstanceID: token.instanceID, OriginalGeneration: record.Scope.Generation, LocalGeneration: record.Scope.Generation, Action: "replace", PrepareBoot: boot, FenceBoot: boot, Phase: "prepared"}
	if kind == "recovery-wildcard" {
		recovery.OriginalGeneration = ""
	}
	return func(conflict bool) error {
		r := recovery
		if conflict {
			r.Action = "delete"
		}
		_, err := d.nativeRegistry.PrepareRecovery(r)
		return err
	}
}

func TestDirectEndpointRegistryRecoveryProtocolRetryReassertsFence(t *testing.T) {
	d, _, payload, _, _ := recoveryProtocolFixture(t)
	if err := d.handleNativeWorkerRecoveryState(nil, payload, bootReader(payload.PrepareBoot)); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatalf("initial same-boot preparation: %v", err)
	}
	d.nativeRegistry.directInvalidations.register(&d.directSubscriptions)
	for range 2 {
		subscription := d.directSubscriptions.add(directEndpointBinding{
			metadata: DirectEndpointSubscriptionMetadata{Deadline: time.Now().Add(time.Minute)},
			subject:  nativeManagedSubject{InstanceID: domain.ID(payload.InstanceID), OwnershipGeneration: payload.OwnershipGeneration},
		})
		if subscription == nil {
			t.Fatal("synthetic subscription missing")
		}
		if err := d.handleNativeWorkerRecoveryState(nil, payload, bootReader(payload.PrepareBoot)); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
			t.Fatalf("same-boot replay: %v", err)
		}
		if subscription.Valid() {
			t.Fatal("protocol replay did not reassert registry invalidation")
		}
	}
}

func TestDirectEndpointRegistryFenceWaitsForAdmission(t *testing.T) {
	for _, kind := range []string{"gc", "recovery", "recovery-wildcard"} {
		t.Run(kind, func(t *testing.T) {
			d, token, _, admit := subscriptionFixture(t)
			fence := directEndpointRegistryFence(t, d, token, kind)
			entered := make(chan *DirectEndpointSubscription, 1)
			release := make(chan struct{})
			admitted := make(chan struct{})
			go func() {
				defer close(admitted)
				_, _ = admit(context.Background(), func(custody directEndpointCustodyUse) directEndpointCustodyUse {
					return func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
						return custody(verify, fence, func(material endpointMaterial) error {
							if err := use(material); err != nil {
								return err
							}
							d.directSubscriptions.mu.Lock()
							var candidate *DirectEndpointSubscription
							for s := range d.directSubscriptions.entries {
								candidate = s
							}
							d.directSubscriptions.mu.Unlock()
							entered <- candidate
							<-release
							return nil
						})
					}
				})
			}()
			var candidate *DirectEndpointSubscription
			select {
			case candidate = <-entered:
			case <-admitted:
				close(release)
				t.Fatal("admission failed before custody callback")
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("admission did not reach custody callback")
			}
			if candidate == nil {
				close(release)
				t.Fatal("candidate missing under custody fence")
			}
			completed := make(chan error, 1)
			started := make(chan struct{})
			go func() { close(started); completed <- fence(false) }()
			<-started
			select {
			case err := <-completed:
				close(release)
				<-admitted
				t.Fatalf("registry fence passed active admission custody: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			close(release)
			if err := <-completed; err != nil {
				t.Fatal(err)
			}
			<-admitted
			select {
			case <-candidate.Done():
			default:
				t.Fatal("registry fence left admitted subscription active")
			}
		})
	}
}

func TestDirectEndpointRegistryFencePrecedesAdmission(t *testing.T) {
	for _, kind := range []string{"gc", "recovery", "recovery-wildcard"} {
		t.Run(kind, func(t *testing.T) {
			d, token, _, admit := subscriptionFixture(t)
			if err := directEndpointRegistryFence(t, d, token, kind)(false); err != nil {
				t.Fatal(err)
			}
			if subscription, err := admit(context.Background(), nil); err == nil || subscription != nil {
				t.Fatal("admission crossed existing registry fence")
			}
		})
	}
}

func TestDirectEndpointRegistryFenceRetryAndFailureRevoke(t *testing.T) {
	for _, kind := range []string{"gc", "recovery"} {
		attempts := []string{"retry", "conflict", "persistence-failure"}
		if kind == "gc" {
			attempts = append(attempts, "postinsert-failure")
		}
		for _, attempt := range attempts {
			t.Run(kind+"/"+attempt, func(t *testing.T) {
				d, token, _, admit := subscriptionFixture(t)
				subscription, err := admit(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				binding := subscription.binding
				fence := directEndpointRegistryFence(t, d, token, kind)
				if attempt == "postinsert-failure" {
					if _, err := d.nativeRegistry.db.Exec(`CREATE TRIGGER corrupt_registry_fence AFTER INSERT ON native_worker_gc BEGIN UPDATE native_worker_gc SET payload='invalid' WHERE instance_id=NEW.instance_id; END`); err != nil {
						t.Fatal(err)
					}
				} else if attempt == "persistence-failure" {
					table := "native_worker_gc"
					if kind == "recovery" {
						table = "native_worker_recoveries"
					}
					if _, err := d.nativeRegistry.db.Exec("CREATE TRIGGER fail_registry_fence BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(FAIL, 'injected failure'); END"); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := fence(false); err != nil {
						t.Fatal(err)
					}
					if subscription.Valid() {
						t.Fatal("initial fence left subscription active")
					}
					// Registry registrations must survive selective invalidation so every
					// replay and failed attempt also invalidates matching owner entries.
					subscription = d.directSubscriptions.add(binding)
					if subscription == nil {
						t.Fatal("synthetic subscription missing")
					}
				}
				other := binding
				other.subject.OwnershipGeneration = domain.NewID().String()
				unmatched := d.directSubscriptions.add(other)
				if unmatched == nil {
					t.Fatal("unmatched subscription missing")
				}
				unrelatedBinding := other
				unrelatedBinding.subject.InstanceID = domain.NewID()
				unrelated := d.directSubscriptions.add(unrelatedBinding)
				if unrelated == nil {
					t.Fatal("unrelated instance subscription missing")
				}
				err = fence(attempt == "conflict")
				if (attempt == "retry") != (err == nil) {
					t.Fatalf("unexpected fence result: %v", err)
				}
				if !unrelated.Valid() {
					t.Fatal("registry fence revoked another instance")
				}
				if subscription.Valid() {
					t.Fatal("retry or failure left matching subscription active")
				}
				if kind == "gc" {
					if unmatched.Valid() {
						t.Fatal("instance-wide GC fence left replacement generation active")
					}
				} else if !unmatched.Valid() {
					t.Fatal("generation-specific recovery revoked another generation")
				}
			})
		}
	}
}

func TestDirectEndpointRegistryRecoveryWildcardRevokesAllGenerations(t *testing.T) {
	d, token, _, admit := subscriptionFixture(t)
	subscription, err := admit(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	other := subscription.binding
	other.subject.OwnershipGeneration = domain.NewID().String()
	anotherGeneration := d.directSubscriptions.add(other)
	other.subject.InstanceID = domain.NewID()
	anotherInstance := d.directSubscriptions.add(other)
	if anotherGeneration == nil || anotherInstance == nil {
		t.Fatal("synthetic subscriptions missing")
	}
	boot := recoveryBoot("11111111-1111-4111-8111-111111111111")
	recovery := NativeWorkerRecovery{RecoveryID: domain.NewID().String(), InstanceID: token.instanceID, LocalGeneration: token.subject.OwnershipGeneration, Action: "delete", PrepareBoot: boot, FenceBoot: boot, Phase: "prepared"}
	if _, err := d.nativeRegistry.PrepareRecovery(recovery); err != nil {
		t.Fatal(err)
	}
	if subscription.Valid() || anotherGeneration.Valid() {
		t.Fatal("legacy wildcard recovery left an instance generation active")
	}
	if !anotherInstance.Valid() {
		t.Fatal("legacy wildcard recovery revoked another instance")
	}
}
