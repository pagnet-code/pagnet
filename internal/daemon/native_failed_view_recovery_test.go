//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeFailedTerminalViewReconnectRetiresOriginalFailureBeforeStop(t *testing.T) {
	var c *NativeObservationConnection
	var cloud transport.NativeWorkerOwnership
	retireCalls := 0
	c, scope, spec := ownershipConnectionFixture(t, func(_ context.Context, typ string, raw any) error {
		switch typ {
		case transport.MsgNativeOwnershipRegister:
			p := raw.(transport.NativeOwnershipRegisterPayload)
			cloud = transport.NativeWorkerOwnership{ID: domain.NewID().String(), InstanceID: p.InstanceID, OwnershipGeneration: p.OwnershipGeneration, Runtime: p.Runtime, Profile: p.Profile, ProfileFingerprint: p.ProfileFingerprint, OriginalAdmissionID: p.NativeAdmissionID, State: "active", LastDispatchSequence: 2}
			copy := cloud
			c.OwnershipDisposition(transport.NativeOwnershipRegisteredPayload{RequestID: p.RequestID, Ownership: &copy})
		case transport.MsgNativeOwnershipRetire:
			p := raw.(transport.NativeOwnershipRetirePayload)
			retireCalls++
			if p.RetiredDispatchSequence != 2 || p.UnstartedStop == nil || p.UnstartedStop.DispatchSequence != 2 {
				t.Error("missing exact original completed stop proof")
			}
			cloud.RetiredFloor = p.RetiredDispatchSequence
			copy := cloud
			c.OwnershipDisposition(transport.NativeOwnershipRegisteredPayload{RequestID: p.RequestID, Ownership: &copy, UnstartedStop: p.UnstartedStop})
		default:
			t.Errorf("unexpected RPC %s", typ)
		}
		return nil
	})
	spec.Workspace = t.TempDir()
	spec.NetworkTenantID = scope.TenantID
	ownership, err := c.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "owner")
	key := bytes.Repeat([]byte{53}, 32)
	if err = sessionworker.PrepareBootstrap(dir, sessionworker.Bootstrap{Protocol: sessionworker.Protocol, Scope: scope, Native: spec}, key); err != nil {
		t.Fatal(err)
	}
	journal, err := sessionworker.OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	owner, err := sessionworker.NewSessionOwner(t.Context(), journal, spec, key)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = sessionworker.ServeOwner(ctx, owner, key, "original-worker") }()
	attach := func(name string) *NativeWorkerProxy {
		t.Helper()
		until := time.Now().Add(3 * time.Second)
		for {
			proxy, err := AttachNativeWorker(t.Context(), c, dir, scope, name)
			if err == nil {
				return proxy
			}
			if time.Now().After(until) {
				t.Fatal(err)
			}
			time.Sleep(time.Millisecond)
		}
	}
	proxy := attach("first-controller")
	defer proxy.Close()
	c.mu.Lock()
	admission := *c.session
	c.mu.Unlock()
	proof := func(n int64) transport.NativeDispatchProof {
		return transport.NativeDispatchProof{OwnershipID: ownership.ID, OwnershipGeneration: scope.Generation, DispatchSequence: n, SourceCommandID: domain.NewID().String(), SourceAdmissionID: admission.NativeAdmissionID, SourceRunnerID: admission.RunnerID, SourceRunnerEpoch: admission.RunnerEpoch, SourceBootID: admission.BootID}
	}
	viewProof := proof(1)
	view, err := proxy.AcceptDispatch(t.Context(), *ownership, viewProof, "attach", sessionworker.Operation{})
	if err != nil {
		t.Fatal(err)
	}
	// No origin authority response is supplied: this real operation remains
	// admitted until the subsequent original Stop cancels and joins its startup.
	updated, err := proxy.SettleDispatches(t.Context(), *ownership)
	if err != nil || updated.RetiredFloor != 0 || retireCalls != 0 {
		t.Fatal("admitted view was confirmed or retired", updated, err)
	}
	stopProof := proof(2)
	stop, err := proxy.AcceptDispatch(t.Context(), *ownership, stopProof, "stop", sessionworker.Operation{})
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(3 * time.Second)
	for {
		out, err := proxy.call(t.Context(), sessionworker.Request{Type: "outcome", Sequence: stop.Sequence})
		if err != nil {
			t.Fatal(err)
		}
		if out.Outcome.State == "completed" {
			break
		}
		if time.Now().After(until) {
			t.Fatal("actual original Stop did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	original, err := proxy.call(t.Context(), sessionworker.Request{Type: "outcome", Sequence: view.Sequence})
	if err != nil || original.Outcome == nil || original.Outcome.State != "failed" {
		t.Fatal("original activation failure was not durable", original.Outcome, err)
	}
	records, err := proxy.call(t.Context(), sessionworker.Request{Type: "dispatches"})
	if err != nil || len(records.Dispatches) != 2 || records.Dispatches[0].State != "view_pending" {
		t.Fatal("fixture did not retain skipped final view confirmation", records.Dispatches, err)
	}
	if !transport.SameNativeDispatchProof(records.Dispatches[0].Proof, viewProof) {
		t.Fatal("original view proof changed")
	}
	_ = proxy.Close()
	proxy = attach("replacement-controller")
	defer proxy.Close()
	updated, err = proxy.SettleDispatches(t.Context(), *ownership)
	if err != nil || updated.RetiredFloor != 2 || retireCalls != 1 {
		t.Fatal("original failed view stranded genuine completed Stop", updated, err)
	}
	records, err = proxy.call(t.Context(), sessionworker.Request{Type: "dispatches"})
	if err != nil || len(records.Dispatches) != 0 {
		t.Fatal("committed original dispatches were not pruned", records.Dispatches, err)
	}
}
