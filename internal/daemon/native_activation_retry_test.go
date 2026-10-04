//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeWorkerActivationRetriesOriginalIssuedTicketAfterTransientAuthorityFailure(t *testing.T) {
	for _, lostReply := range []bool{false, true} {
		name := "retryable_authority_failure"
		if lostReply {
			name = "committed_authority_reply_lost"
		}
		t.Run(name, func(t *testing.T) { testNativeActivationRetry(t, lostReply, false) })
	}
}

func TestNativeStopCancelsPendingOriginalActivationBeforeCompletion(t *testing.T) {
	testNativeActivationRetry(t, false, true)
}

func testNativeActivationRetry(t *testing.T, lostReply, stopPending bool) {
	var authorityMu sync.Mutex
	entered := make(chan struct{})
	release := make(chan struct{})
	firstCtx, cancelFirst := context.WithCancel(t.Context())
	defer cancelFirst()
	var committedOrigin *transport.NativeObservationOrigin
	var c *NativeObservationConnection
	var requests []transport.NativeOriginRegisterPayload
	var cloud *transport.NativeWorkerOwnership
	c, scope, spec := ownershipConnectionFixture(t, func(_ context.Context, typ string, raw any) error {
		switch typ {
		case transport.MsgNativeOwnershipRegister:
			p := raw.(transport.NativeOwnershipRegisterPayload)
			cloud = &transport.NativeWorkerOwnership{ID: domain.NewID().String(), InstanceID: p.InstanceID, OwnershipGeneration: p.OwnershipGeneration, Runtime: p.Runtime, Profile: p.Profile, ProfileFingerprint: p.ProfileFingerprint, OriginalAdmissionID: p.NativeAdmissionID, State: "active", LastDispatchSequence: 1}
			c.OwnershipDisposition(transport.NativeOwnershipRegisteredPayload{RequestID: p.RequestID, Ownership: cloud})
		case transport.MsgNativeOriginRegister:
			p := raw.(transport.NativeOriginRegisterPayload)
			authorityMu.Lock()
			requests = append(requests, p)
			attempt := len(requests)
			authorityMu.Unlock()
			if attempt == 1 {
				close(entered)
				<-release
				if lostReply {
					c.mu.Lock()
					a := *c.session
					c.mu.Unlock()
					committedOrigin = &transport.NativeObservationOrigin{ID: domain.NewID().String(), NativeAdmissionID: p.NativeAdmissionID, CommandID: p.CommandID, TenantID: a.TenantID, HostID: a.HostID, InstanceID: p.InstanceID, Runtime: p.Runtime, NativeGeneration: p.NativeGeneration, RunnerID: a.RunnerID, RunnerEpoch: a.RunnerEpoch, BootID: a.BootID, CreatedAt: time.Now().UTC()}
					cancelFirst()
					return nil
				}
				c.OriginRegistered(transport.NativeOriginRegisteredPayload{RequestID: p.RequestID, PublicError: "native_origin_unavailable", Retryable: true})
				return nil
			}
			c.mu.Lock()
			a := *c.session
			c.mu.Unlock()
			if committedOrigin != nil {
				c.OriginRegistered(transport.NativeOriginRegisteredPayload{RequestID: p.RequestID, Origin: committedOrigin})
				return nil
			}
			c.OriginRegistered(transport.NativeOriginRegisteredPayload{RequestID: p.RequestID, Origin: &transport.NativeObservationOrigin{ID: domain.NewID().String(), NativeAdmissionID: p.NativeAdmissionID, CommandID: p.CommandID, TenantID: a.TenantID, HostID: a.HostID, InstanceID: p.InstanceID, Runtime: p.Runtime, NativeGeneration: p.NativeGeneration, RunnerID: a.RunnerID, RunnerEpoch: a.RunnerEpoch, BootID: a.BootID, CreatedAt: time.Now().UTC()}})
		default:
			t.Errorf("unexpected RPC %s", typ)
		}
		return nil
	})
	spec.Workspace = t.TempDir()
	spec.NetworkTenantID = scope.TenantID
	o, e := c.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", "")
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(t.TempDir(), "owner")
	key := bytes.Repeat([]byte{41}, 32)
	if e = sessionworker.PrepareBootstrap(dir, sessionworker.Bootstrap{Protocol: sessionworker.Protocol, Scope: scope, Native: spec}, key); e != nil {
		t.Fatal(e)
	}
	journal, e := sessionworker.OpenJournal(dir, scope)
	if e != nil {
		t.Fatal(e)
	}
	defer journal.Close()
	owner, e := sessionworker.NewSessionOwner(t.Context(), journal, spec, key)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = sessionworker.ServeOwner(ctx, owner, key, "original-worker") }()
	var proxy *NativeWorkerProxy
	until := time.Now().Add(3 * time.Second)
	for {
		proxy, e = AttachNativeWorker(t.Context(), c, dir, scope, "controller")
		if e == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal(e)
		}
		time.Sleep(time.Millisecond)
	}
	defer proxy.Close()
	c.mu.Lock()
	a := *c.session
	c.mu.Unlock()
	proof := transport.NativeDispatchProof{OwnershipID: o.ID, OwnershipGeneration: scope.Generation, DispatchSequence: 1, SourceCommandID: domain.NewID().String(), SourceAdmissionID: a.NativeAdmissionID, SourceRunnerID: a.RunnerID, SourceRunnerEpoch: a.RunnerEpoch, SourceBootID: a.BootID}
	out, e := proxy.AcceptDispatch(t.Context(), *o, proof, "attach", sessionworker.Operation{InputKind: "user_input"})
	if e != nil {
		t.Fatal(e)
	}
	firstDone := make(chan error, 1)
	go func() {
		for {
			err := proxy.Reconcile(firstCtx)
			authorityMu.Lock()
			attempted := len(requests) > 0
			authorityMu.Unlock()
			if attempted || err != nil {
				firstDone <- err
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("original activation ticket was not issued")
	}
	// A competing terminal reconciliation must honor its own deadline instead
	// of blocking behind the pump's in-flight authority request.
	concurrentCtx, cancelConcurrent := context.WithTimeout(t.Context(), 20*time.Millisecond)
	concurrentErr := proxy.Reconcile(concurrentCtx)
	cancelConcurrent()
	close(release)
	if !errors.Is(concurrentErr, context.DeadlineExceeded) {
		t.Fatal("concurrent reconciliation escaped or ignored its deadline", concurrentErr)
	}
	e = <-firstDone
	expectedErr := ErrNativeOriginAdmissionDeferred
	if lostReply {
		expectedErr = context.Canceled
	}
	if !errors.Is(e, expectedErr) {
		t.Fatal("transient authority failure did not preserve retry", e)
	}
	if stopPending {
		stopProof := proof
		stopProof.DispatchSequence++
		stopProof.SourceCommandID = domain.NewID().String()
		stop, err := proxy.AcceptDispatch(t.Context(), *o, stopProof, "stop", sessionworker.Operation{})
		if err != nil {
			t.Fatal(err)
		}
		until = time.Now().Add(3 * time.Second)
		for {
			response, err := proxy.call(t.Context(), sessionworker.Request{Type: "outcome", Sequence: stop.Sequence})
			if err != nil {
				t.Fatal(err)
			}
			if response.Outcome.State == "completed" {
				break
			}
			if time.Now().After(until) {
				t.Fatal("stop did not finish cancellation")
			}
			time.Sleep(time.Millisecond)
		}
		response, err := proxy.call(t.Context(), sessionworker.Request{Type: "outcome", Sequence: out.Sequence})
		if err != nil || response.Outcome.State != "failed" {
			t.Fatal("completed stop left earlier native activation admitted", err, response.Outcome)
		}
		if err = proxy.Reconcile(t.Context()); err != nil {
			t.Fatal("stopped ticket remained pending", err)
		}
		if len(requests) != 1 {
			t.Fatal("completed stop authorized a late native startup", len(requests))
		}
		if snapshot, err := proxy.Snapshot(t.Context()); err != nil || snapshot.PID != 0 || snapshot.IdentityPending || snapshot.HasTerminal {
			t.Fatal("completed stop resurrected native endpoint", err, snapshot)
		}
		return
	}
	if e = proxy.Reconcile(t.Context()); e != nil {
		t.Fatal("original activation retry failed", e)
	}
	if len(requests) != 2 {
		t.Fatal("issued ticket was stranded after transient failure; authority calls", len(requests))
	}
	if requests[0].CommandID != requests[1].CommandID || requests[0].NativeAdmissionID != requests[1].NativeAdmissionID || requests[0].NativeGeneration != requests[1].NativeGeneration {
		t.Fatal("retry replaced original source or generation")
	}
	for {
		r, e := proxy.call(t.Context(), sessionworker.Request{Type: "outcome", Sequence: out.Sequence})
		if e != nil {
			t.Fatal(e)
		}
		if r.Outcome.State != "admitted" {
			if r.Outcome.State != "failed" {
				t.Fatal("fixture /bin/true unexpectedly materialized", r.Outcome.State)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatal("genuine pre-handshake runtime failure remained admitted after authorization")
		}
		time.Sleep(time.Millisecond)
	}
}
