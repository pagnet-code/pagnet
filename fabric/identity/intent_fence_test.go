package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNativeIntentFenceTakeoverWaitsForDurableACKThenRejectsStaleA(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a := f.controller(t, 0, "A")
	b := f.binding(t, a)
	caller, original, final := f.invocation(t)
	admission, e := f.a.Admit(ctx, f.owner, a, b, caller, original, final, "source-A", "attempt", "replay")
	if e != nil {
		t.Fatal(e)
	}
	intent := NativeIntentCommitment{CommandID: "actual-command", Sequence: 1, OperationDigest: sha256.Sum256([]byte("exact native bytes")), SelectorDigest: sha256.Sum256([]byte("native.prompt.v1")), SpecDigest: b.Worker.ProfileDigest}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, e := f.a.FenceNativeIntent(ctx, f.owner, a, b, admission, caller, original, final, intent, func(ctx context.Context) (NativeIntentReceipt, error) {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return NativeIntentReceipt{}, ctx.Err()
			}
			return NativeIntentReceipt{CommandID: intent.CommandID, Sequence: intent.Sequence, OperationDigest: intent.OperationDigest, OriginalAdmissionID: admission.ID, ControllerEpoch: a.Epoch(), OwnershipGeneration: b.Worker.OwnershipGeneration}, nil
		})
		done <- e
	}()
	<-entered
	takeover := make(chan Controller, 1)
	failed := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		next, e := f.a.AcquireController(ctx, f.owner, f.scope, a.Epoch(), "B", "controller-B")
		if e != nil {
			failed <- e
		} else {
			takeover <- next
		}
	}()
	<-started
	select {
	case <-takeover:
		t.Fatal("B committed while A's durable admission ACK fence was held")
	case e := <-failed:
		t.Fatal(e)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	var current Controller
	select {
	case current = <-takeover:
	case e = <-failed:
		t.Fatal(e)
	}
	called := false
	if _, e = f.a.FenceNativeIntent(ctx, f.owner, a, b, admission, caller, original, final, intent, func(context.Context) (NativeIntentReceipt, error) { called = true; return NativeIntentReceipt{}, nil }); e == nil || called {
		t.Fatal("stale A reached effect-admission callback", e)
	}
	// Original A remains the source under current B, not a regenerated admission.
	_, e = f.a.FenceNativeIntent(ctx, f.owner, current, b, admission, caller, original, final, intent, func(context.Context) (NativeIntentReceipt, error) {
		return NativeIntentReceipt{CommandID: intent.CommandID, Sequence: intent.Sequence, OperationDigest: intent.OperationDigest, OriginalAdmissionID: admission.ID, ControllerEpoch: current.Epoch(), OwnershipGeneration: b.Worker.OwnershipGeneration}, nil
	})
	if e != nil {
		t.Fatal("A source under B admission", e)
	}
}
func TestNativeIntentFenceCommittedLostACKRetainsExactEvidence(t *testing.T) {
	f := fixture(t)
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	caller, original, final := f.invocation(t)
	source, e := f.a.Admit(context.Background(), f.owner, c, b, caller, original, final, "source", "attempt", "replay")
	if e != nil {
		t.Fatal(e)
	}
	intent := NativeIntentCommitment{CommandID: "actual-command", Sequence: 1, OperationDigest: sha256.Sum256([]byte("exact native bytes")), SelectorDigest: sha256.Sum256([]byte("selector")), SpecDigest: b.Worker.ProfileDigest}
	expected := NativeIntentReceipt{CommandID: intent.CommandID, Sequence: intent.Sequence, OperationDigest: intent.OperationDigest, OriginalAdmissionID: source.ID, ControllerEpoch: c.Epoch(), OwnershipGeneration: b.Worker.OwnershipGeneration}
	var mu sync.Mutex
	durable := map[int64]NativeIntentReceipt{}
	fresh := 0
	appendIntent := func(context.Context) (NativeIntentReceipt, error) {
		mu.Lock()
		defer mu.Unlock()
		if old, exists := durable[intent.Sequence]; exists {
			return old, nil
		}
		durable[intent.Sequence] = expected
		fresh++
		return expected, errors.New("committed ACK lost")
	}
	got, e := f.a.FenceNativeIntent(context.Background(), f.owner, c, b, source, caller, original, final, intent, appendIntent)
	if e == nil || got != expected {
		t.Fatal("known durable evidence discarded", e)
	}
	got, e = f.a.FenceNativeIntent(context.Background(), f.owner, c, b, source, caller, original, final, intent, appendIntent)
	if e != nil || got != expected || fresh != 1 {
		t.Fatal("original sequence retry replayed effects", e)
	}
	bad := intent
	bad.SpecDigest = sha256.Sum256([]byte("different executable"))
	called := false
	if _, e = f.a.FenceNativeIntent(context.Background(), f.owner, c, b, source, caller, original, final, bad, func(context.Context) (NativeIntentReceipt, error) { called = true; return expected, nil }); e == nil || called {
		t.Fatal("wrong native spec accepted", e)
	}
}
