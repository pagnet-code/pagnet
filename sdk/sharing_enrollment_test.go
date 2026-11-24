package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Done is first consulted when the enrollment waits for the grant lock.
// This makes overlap deterministic without relying on scheduler timing.
type sharingEnrollmentWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *sharingEnrollmentWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestSharingEnrollmentOverlappingCallsRetainProof(t *testing.T) {
	for _, reconnect := range []bool{false, true} {
		name := "ready"
		if reconnect {
			name = "reconnect"
		}
		t.Run(name, func(t *testing.T) {
			f, issuer, _ := sharingMessageClients(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if reconnect {
				issuer.connGeneration.Add(1)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			var gateHeld atomic.Bool
			releaseFirst := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseFirst()
			var mu sync.Mutex
			var challenges atomic.Int64
			gate := "/status"
			if reconnect {
				gate = "/challenge"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, gate) && gateHeld.CompareAndSwap(false, true) {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
					}
				}
				mu.Lock()
				defer mu.Unlock()
				if strings.HasSuffix(r.URL.Path, "/challenge") {
					challenges.Add(1)
					// Model the server invalidating a consumed proof on reissue.
					f.pair.installed["issuer"] = false
				}
				if strings.Contains(r.URL.Path, "/messages") && !f.pair.installed["issuer"] {
					http.NotFound(w, r)
					return
				}
				f.serve(w, r)
			}))
			defer server.Close()
			issuer.rest.base = server.URL + "/api/v1"
			first := make(chan error, 1)
			go func() {
				result, err := issuer.EnrollSharingPair(ctx, "grant")
				if err == nil && result.Pending {
					err = errors.New("first enrollment pending")
				}
				first <- err
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			waiting := &sharingEnrollmentWaitContext{Context: ctx, waiting: make(chan struct{})}
			second := make(chan error, 1)
			go func() {
				result, err := issuer.EnrollSharingPair(waiting, "grant")
				if err == nil && result.Pending {
					err = errors.New("second enrollment pending")
				}
				second <- err
			}()
			select {
			case <-waiting.waiting:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			// Existing message admission must remain usable while a redundant
			// enrollment holds the grant lock and another enrollment waits.
			if !reconnect {
				prepared, err := issuer.PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart("retained proof")}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := issuer.SendPreparedSharingMessage(ctx, prepared); err != nil {
					t.Fatal(err)
				}
				if receipt, err := issuer.GetSharingMessageReceipt(ctx, prepared); err != nil || receipt.Status != "pending" {
					t.Fatalf("receipt: %v, %v", receipt, err)
				}
			}
			releaseFirst()
			for _, done := range []<-chan error{first, second} {
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if result, err := issuer.EnrollSharingPair(ctx, "grant"); err != nil || result.Pending {
					t.Fatalf("repeated enrollment: pending=%v err=%v", result.Pending, err)
				}
			}
			want := int64(0)
			if reconnect {
				want = 1
			}
			if got := challenges.Load(); got != want {
				t.Fatalf("challenges=%d want %d", got, want)
			}
		})
	}
}

func TestSharingEnrollmentWaitCancellation(t *testing.T) {
	var c Client
	unlock, err := c.lockSharingEnrollment(context.Background(), "grant")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	waiting := &sharingEnrollmentWaitContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := c.EnrollSharingPair(waiting, "grant")
		done <- err
	}()
	select {
	case <-waiting.waiting:
	case err := <-done:
		t.Fatalf("enrollment did not wait: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting enrollment: %v", err)
	}
	// Other grants can still progress while this grant remains locked.
	otherUnlock, err := c.lockSharingEnrollment(context.Background(), "other")
	if err != nil {
		t.Fatal(err)
	}
	otherUnlock()
}

func TestSharingEnrollmentReadyRejectsStaleBindings(t *testing.T) {
	for _, what := range []string{"grant", "generation", "epoch", "descriptor", "principal", "connection"} {
		t.Run(what, func(t *testing.T) {
			f, issuer, _ := sharingMessageClients(t)
			var challenges atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/challenge") {
					challenges.Add(1)
				}
				if strings.HasSuffix(r.URL.Path, "/status") {
					status := f.pair.status
					switch what {
					case "grant":
						status.GrantID = "other"
					case "generation":
						status.Generation++
					case "epoch":
						epoch := "other"
						status.ActivationEpoch = &epoch
					case "descriptor":
						status.Permissions = []string{"changed"}
					case "principal":
						issuer.principalID.Store("other")
					case "connection":
						issuer.connGeneration.Add(1)
					}
					_ = json.NewEncoder(w).Encode(status)
					return
				}
				f.serve(w, r)
			}))
			defer server.Close()
			issuer.rest.base = server.URL + "/api/v1"
			if _, err := issuer.EnrollSharingPair(context.Background(), "grant"); err == nil {
				t.Fatal("accepted stale " + what)
			}
			if challenges.Load() != 0 {
				t.Fatal("reissued challenge for stale binding")
			}
		})
	}
}
