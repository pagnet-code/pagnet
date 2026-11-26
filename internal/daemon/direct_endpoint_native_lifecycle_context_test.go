//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDirectEndpointLifecycleContextContention(t *testing.T) {
	for _, operation := range []string{"snapshot", "transition"} {
		for _, lock := range []string{"publication", "index", "owner", "canceled"} {
			t.Run(operation+"/"+lock, func(t *testing.T) {
				_, token, _, admit := subscriptionFixture(t)
				s, err := admit(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				p := token.proxy
				epoch, identity, observed, transition := p.directEndpointEpoch, p.directEndpointIdentity, p.directEndpointObserved, p.directEndpointTransition
				// A second owner must remain untouched even when another is busy.
				var other directEndpointSubscriptions
				second := other.add(directEndpointBinding{proxy: p, metadata: DirectEndpointSubscriptionMetadata{Deadline: time.Now().Add(time.Hour)}})
				defer other.close()
				p.directInvalidations.register(&other)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var release func()
				want := errDirectEndpointLocalBusy
				switch lock {
				case "publication":
					p.publicationMu.RLock()
					release = p.publicationMu.RUnlock
				case "index":
					p.directInvalidations.mu.Lock()
					release = p.directInvalidations.mu.Unlock
				case "owner":
					s.owner.mu.Lock()
					release = s.owner.mu.Unlock
				case "canceled":
					cancel()
					want = context.Canceled
				}
				if operation == "snapshot" {
					snapshot := subscriptionNativeSnapshot(token)
					snapshot.NativeStartIdentity = "replacement"
					_, err = p.observeDirectEndpointSnapshotContext(ctx, snapshot, epoch)
				} else {
					err = p.beginDirectEndpointTransitionContext(ctx)
				}
				if release != nil {
					release()
				}
				if !errors.Is(err, want) {
					t.Fatalf("error = %v, want %v", err, want)
				}
				if p.directEndpointEpoch != epoch || p.directEndpointIdentity != identity || p.directEndpointObserved != observed || p.directEndpointTransition != transition {
					t.Fatal("failed acquisition changed lifecycle state")
				}
				for _, subscription := range []*DirectEndpointSubscription{s, second} {
					select {
					case <-subscription.Done():
						t.Fatal("failed acquisition revoked subscription")
					default:
					}
				}
				// A successful retry also verifies every acquired lock was unwound.
				if err := p.beginDirectEndpointTransitionContext(context.Background()); err != nil {
					t.Fatalf("retry: %v", err)
				}
				if p.directEndpointEpoch != epoch+1 || !p.directEndpointTransition || p.directEndpointIdentity != identity || p.directEndpointObserved != observed {
					t.Fatal("transition did not preserve lifecycle semantics")
				}
				for _, subscription := range []*DirectEndpointSubscription{s, second} {
					select {
					case <-subscription.Done():
					default:
						t.Fatal("successful transition returned before revocation")
					}
				}
			})
		}
	}
}

func TestDirectEndpointObservationEpochContext(t *testing.T) {
	var p NativeWorkerProxy
	p.directEndpointEpoch = 7
	p.publicationMu.Lock()
	_, err := p.directEndpointObservationEpochContext(context.Background())
	p.publicationMu.Unlock()
	if err != errDirectEndpointLocalBusy {
		t.Fatalf("busy read: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.directEndpointObservationEpochContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read: %v", err)
	}
	if epoch, err := p.directEndpointObservationEpochContext(context.Background()); err != nil || epoch != 7 {
		t.Fatalf("epoch = %d, error = %v", epoch, err)
	}
}

func TestDirectEndpointSnapshotContextPreservesLifecycle(t *testing.T) {
	for _, kind := range []string{"unchanged", "changed", "inactive", "transition-unchanged", "transition-changed", "stale-unchanged", "stale-changed"} {
		t.Run(kind, func(t *testing.T) {
			_, token, _, admit := subscriptionFixture(t)
			s, err := admit(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			p := token.proxy
			var legacy NativeWorkerProxy
			legacy.directEndpointEpoch, legacy.directEndpointIdentity = p.directEndpointEpoch, p.directEndpointIdentity
			legacy.directEndpointObserved = p.directEndpointObserved
			observationEpoch := p.directEndpointEpoch
			snapshot := subscriptionNativeSnapshot(token)
			switch kind {
			case "changed", "transition-changed", "stale-changed":
				snapshot.NativeStartIdentity = "replacement"
			case "inactive":
				snapshot.PID = 0
			}
			switch kind {
			case "transition-unchanged", "transition-changed":
				// Keep the live subscription to isolate snapshot revocation.
				p.directEndpointTransition, legacy.directEndpointTransition = true, true
			case "stale-unchanged", "stale-changed":
				p.directEndpointEpoch++
				legacy.directEndpointEpoch++
				p.directEndpointTransition, legacy.directEndpointTransition = true, true
			}
			other := s.owner.add(directEndpointBinding{proxy: &legacy, metadata: DirectEndpointSubscriptionMetadata{Deadline: time.Now().Add(time.Hour)}})
			wantEpoch := legacy.observeDirectEndpointSnapshot(snapshot, observationEpoch)
			gotEpoch, err := p.observeDirectEndpointSnapshotContext(context.Background(), snapshot, observationEpoch)
			if err != nil || gotEpoch != wantEpoch {
				t.Fatalf("epoch = %d, error = %v; want %d", gotEpoch, err, wantEpoch)
			}
			if p.directEndpointEpoch != legacy.directEndpointEpoch || p.directEndpointIdentity != legacy.directEndpointIdentity || p.directEndpointObserved != legacy.directEndpointObserved || p.directEndpointTransition != legacy.directEndpointTransition {
				t.Fatal("context lifecycle differs from legacy lifecycle")
			}
			wantRevoked := kind == "changed" || kind == "inactive" || kind == "transition-changed" || kind == "stale-changed"
			select {
			case <-s.Done():
				if !wantRevoked {
					t.Fatal("unchanged snapshot revoked subscription")
				}
			default:
				if wantRevoked {
					t.Fatal("changed snapshot left subscription live")
				}
			}
			if !other.Valid() {
				t.Fatal("snapshot revoked another proxy's subscription")
			}
			if _, ok := p.directInvalidations.owners[s.owner]; !ok {
				t.Fatal("snapshot removed owner registration")
			}
		})
	}
}

func TestDirectEndpointAuthorityContext(t *testing.T) {
	p := &NativeWorkerProxy{directEndpointEpoch: 7, directEndpointObserved: true, directEndpointIdentity: directEndpointNativeIdentity{generation: "generation", session: "session", origin: "origin", active: true}}
	subject := nativeManagedSubject{NativeGeneration: "generation", NativeSessionID: "session", OriginID: "origin"}
	if epoch, valid, err := p.directEndpointAuthorityContext(context.Background(), subject); epoch != 7 || !valid || err != nil {
		t.Fatalf("exact authority: %d %v %v", epoch, valid, err)
	}
	p.publicationMu.Lock()
	epoch, valid, err := p.directEndpointAuthorityContext(context.Background(), subject)
	p.publicationMu.Unlock()
	if epoch != 0 || valid || err != errDirectEndpointLocalBusy {
		t.Fatalf("contended authority accepted: %d %v %v", epoch, valid, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, valid, err := p.directEndpointAuthorityContext(ctx, subject); valid || err != context.Canceled {
		t.Fatalf("canceled authority: %v %v", valid, err)
	}
	p.directEndpointTransition = true
	if epoch, valid, err := p.directEndpointAuthorityContext(context.Background(), subject); epoch != 7 || valid || err != nil {
		t.Fatalf("transition authority: %d %v %v", epoch, valid, err)
	}
}
