//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeDispatchRetirementLostReplyReconcilesOriginalWorkerPrefix(t *testing.T) {
	var c *NativeObservationConnection
	var cloud transport.NativeWorkerOwnership
	drop, missingEcho := false, false
	var replayed []int64
	send := func(_ context.Context, typ string, raw any) error {
		var reply transport.NativeOwnershipRegisteredPayload
		switch typ {
		case transport.MsgNativeOwnershipRegister:
			p := raw.(transport.NativeOwnershipRegisterPayload)
			if cloud.ID == "" {
				cloud = transport.NativeWorkerOwnership{ID: domain.NewID().String(), InstanceID: p.InstanceID, OwnershipGeneration: p.OwnershipGeneration, Runtime: p.Runtime, ProfileFingerprint: p.ProfileFingerprint, OriginalAdmissionID: p.NativeAdmissionID, State: "active", LastDispatchSequence: 1}
			}
			reply.RequestID = p.RequestID
		case transport.MsgNativeOwnershipRetire:
			p := raw.(transport.NativeOwnershipRetirePayload)
			if p.UnstartedStop == nil || p.UnstartedStop.DispatchSequence != p.RetiredDispatchSequence {
				t.Error("retained original stop proof missing")
			}
			cloud.RetiredFloor = p.RetiredDispatchSequence
			replayed = append(replayed, p.RetiredDispatchSequence)
			reply.RequestID = p.RequestID
			if !missingEcho {
				reply.UnstartedStop = p.UnstartedStop
			}
			if drop {
				return nil
			}
		default:
			t.Errorf("unexpected RPC %s", typ)
		}
		copy := cloud
		reply.Ownership = &copy
		c.OwnershipDisposition(reply)
		return nil
	}
	c, scope, spec := ownershipConnectionFixture(t, send)
	spec.Workspace = t.TempDir()
	spec.NetworkTenantID = scope.TenantID
	o, e := c.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", "")
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(t.TempDir(), "owner")
	key := bytes.Repeat([]byte{37}, 32)
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
	attach := func(name string) *NativeWorkerProxy {
		t.Helper()
		until := time.Now().Add(3 * time.Second)
		for {
			proxy, e := AttachNativeWorker(t.Context(), c, dir, scope, name)
			if e == nil {
				return proxy
			}
			if time.Now().After(until) {
				t.Fatal(e)
			}
			time.Sleep(time.Millisecond)
		}
	}
	proxy := attach("first-controller")
	defer proxy.Close()
	stop := func(n int64) {
		t.Helper()
		proof := transport.NativeDispatchProof{OwnershipID: o.ID, OwnershipGeneration: scope.Generation, DispatchSequence: n, SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String(), SourceRunnerID: domain.NewID().String(), SourceRunnerEpoch: time.Now().UTC(), SourceBootID: "historical-boot"}
		out, e := proxy.AcceptDispatch(t.Context(), *o, proof, "stop", sessionworker.Operation{SourceCommandID: proof.SourceCommandID})
		if e != nil {
			t.Fatal(e)
		}
		until := time.Now().Add(3 * time.Second)
		for {
			r, e := proxy.call(t.Context(), sessionworker.Request{Type: "outcome", Sequence: out.Sequence})
			if e != nil {
				t.Fatal(e)
			}
			if r.Outcome.State == "completed" {
				break
			}
			if time.Now().After(until) {
				t.Fatal("actual original stop did not complete")
			}
			time.Sleep(time.Millisecond)
		}
	}
	stop(1)
	drop = true
	short, done := context.WithTimeout(t.Context(), 100*time.Millisecond)
	_, e = proxy.SettleDispatches(short, *o)
	done()
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("lost committed retirement reply authorized local prune", e)
	}
	if cloud.RetiredFloor != 1 {
		t.Fatal("simulated cloud commit absent")
	}
	_ = proxy.Close()
	c.mu.Lock()
	admission := *c.session
	c.mu.Unlock()
	c.Close()
	boot := domain.NewID().String()
	admission.BootID = boot
	admission.RunnerID = domain.NewID().String()
	admission.NativeAdmissionID = domain.NewID().String()
	admission.RunnerEpoch = time.Now().UTC()
	c = NewNativeObservationConnection(scope.ServerURL, scope.HostID, boot, send)
	defer c.Close()
	if e = c.Admit(admission); e != nil {
		t.Fatal(e)
	}
	drop = false
	o, e = c.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", "")
	if e != nil || o.RetiredFloor != 1 {
		t.Fatal(o, e)
	}
	proxy = attach("replacement-controller")
	defer proxy.Close()
	cloud.LastDispatchSequence = 2
	stop(2)
	missingEcho = true
	if _, e = proxy.SettleDispatches(t.Context(), *o); !errors.Is(e, ErrNativeOriginAdmissionDeferred) {
		t.Fatal("missing committed original stop echo authorized prune", e)
	}
	records, e := proxy.call(t.Context(), sessionworker.Request{Type: "dispatches"})
	if e != nil || len(records.Dispatches) != 2 {
		t.Fatal("lost echo erased retained original records", len(records.Dispatches), e)
	}
	missingEcho = false
	updated, e := proxy.SettleDispatches(t.Context(), *o)
	if e != nil || updated.RetiredFloor != 2 {
		t.Fatal("original prefix stranded later dispatch", updated, e)
	}
	records, e = proxy.call(t.Context(), sessionworker.Request{Type: "dispatches"})
	if e != nil || len(records.Dispatches) != 0 {
		t.Fatal("committed original prefix not pruned", e, len(records.Dispatches))
	}
	if len(replayed) < 4 || replayed[len(replayed)-2] != 1 || replayed[len(replayed)-1] != 2 {
		t.Fatal("cloud committed prefix was not replayed before newer ordinal", replayed)
	}
}
