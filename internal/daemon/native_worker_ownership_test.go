package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func ownershipConnectionFixture(t *testing.T, send func(context.Context, string, any) error) (*NativeObservationConnection, sessionworker.Scope, sessionworker.NativeSpec) {
	t.Helper()
	scope := sessionworker.Scope{ServerURL: "https://example.test", TenantID: domain.NewID().String(), AccountID: domain.NewID().String(), HostID: domain.NewID().String(), InstanceID: domain.NewID().String(), Generation: domain.NewID().String()}
	spec := sessionworker.NativeSpec{Runtime: domain.RuntimeFakePersistent, Kind: "worker", NetworkID: domain.NewID().String(), TenantID: scope.TenantID, Workspace: "/tmp/private", Binary: "/bin/true", MCPExecutable: "/bin/true"}
	c := NewNativeObservationConnection(scope.ServerURL, scope.HostID, "boot", send)
	p := transport.HostSessionPayload{TenantID: scope.TenantID, AccountID: scope.AccountID, OwnershipScope: "personal", HostID: scope.HostID, BootID: "boot", NativeAdmissionID: domain.NewID().String(), RunnerID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol, transport.NativeWorkerOwnershipProtocol}}
	if err := c.Admit(p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, scope, spec
}

func TestNativeOwnershipRPCPinsWorkerProfileAndCommittedRetirement(t *testing.T) {
	var c *NativeObservationConnection
	var original *transport.NativeWorkerOwnership
	var mutation string
	c, scope, spec := ownershipConnectionFixture(t, func(_ context.Context, typ string, payload any) error {
		var reply transport.NativeOwnershipRegisteredPayload
		switch typ {
		case transport.MsgNativeOwnershipRegister:
			p := payload.(transport.NativeOwnershipRegisterPayload)
			reply.RequestID = p.RequestID
			o := transport.NativeWorkerOwnership{ID: domain.NewID().String(), InstanceID: p.InstanceID, OwnershipGeneration: p.OwnershipGeneration, Runtime: p.Runtime, Profile: p.Profile, ProfileFingerprint: p.ProfileFingerprint, OriginalAdmissionID: p.NativeAdmissionID, State: "active", LastDispatchSequence: 2}
			original = &o
			reply.Ownership = &o
		case transport.MsgNativeOwnershipRetire:
			p := payload.(transport.NativeOwnershipRetirePayload)
			o := *original
			o.RetiredFloor = p.RetiredDispatchSequence
			if p.Retire {
				o.State = "retired"
			}
			if mutation == "source" {
				o.OriginalAdmissionID = domain.NewID().String()
			}
			reply.RequestID = p.RequestID
			reply.Ownership = &o
		default:
			t.Error("unsupported ownership request", typ)
		}
		if mutation == "profile" {
			reply.Ownership.ProfileFingerprint = "wrong"
		}
		if mutation == "scope" {
			reply.Ownership.OwnershipGeneration = "wrong"
		}
		if mutation == "rollback" {
			reply.Ownership = nil
			reply.PublicError = "retirement commit failed"
			reply.Retryable = true
		}
		c.OwnershipDisposition(reply)
		return nil
	})
	o, err := c.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.RetireNativeWorkerOwnership(t.Context(), scope, spec, "", *o, 1, nil, false, nil); err != nil {
		t.Fatal(err)
	}
	mutation = "rollback"
	if _, err = c.RetireNativeWorkerOwnership(t.Context(), scope, spec, "", *o, 1, nil, false, nil); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatal("rollback authorized prune", err)
	}
	mutation = "source"
	if _, err = c.RetireNativeWorkerOwnership(t.Context(), scope, spec, "", *o, 1, nil, false, nil); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatal("changed original source authorized prune", err)
	}
	for _, change := range []string{"scope", "profile"} {
		mutation = change
		if _, err = c.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", ""); !errors.Is(err, ErrNativeObservationConflict) {
			t.Fatal("foreign worker registered", change, err)
		}
	}
}

func TestNativeOwnershipDisconnectAndPendingCapacity(t *testing.T) {
	requests := make(chan struct{}, 1)
	c, scope, spec := ownershipConnectionFixture(t, func(context.Context, string, any) error { requests <- struct{}{}; return nil })
	errs := make(chan error, 1)
	go func() { _, err := c.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", ""); errs <- err }()
	<-requests
	c.Close()
	select {
	case err := <-errs:
		if !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("disconnected registration stayed blocked")
	}
	c, scope, spec = ownershipConnectionFixture(t, func(context.Context, string, any) error { t.Error("overcapacity ownership sent"); return nil })
	c.mu.Lock()
	c.pendingOwnership = make(map[string]chan transport.NativeOwnershipRegisteredPayload)
	for range 64 {
		c.pendingOwnership[domain.NewID().String()] = make(chan transport.NativeOwnershipRegisteredPayload, 1)
	}
	c.mu.Unlock()
	if _, err := c.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", ""); !errors.Is(err, ErrNativeObservationCapacity) {
		t.Fatal("ownership escaped shared pending limit", err)
	}
}

func TestNativeUnstartedStopRetirementRequiresExactCommittedEcho(t *testing.T) {
	var c *NativeObservationConnection
	var owner *transport.NativeWorkerOwnership
	mutation := ""
	c, scope, spec := ownershipConnectionFixture(t, func(_ context.Context, typ string, raw any) error {
		reply := transport.NativeOwnershipRegisteredPayload{}
		if typ == transport.MsgNativeOwnershipRegister {
			p := raw.(transport.NativeOwnershipRegisterPayload)
			owner = &transport.NativeWorkerOwnership{ID: domain.NewID().String(), InstanceID: p.InstanceID, OwnershipGeneration: p.OwnershipGeneration, Runtime: p.Runtime, Profile: p.Profile, ProfileFingerprint: p.ProfileFingerprint, OriginalAdmissionID: p.NativeAdmissionID, State: "active", LastDispatchSequence: 1}
			reply.RequestID = p.RequestID
			reply.Ownership = owner
		} else {
			p := raw.(transport.NativeOwnershipRetirePayload)
			o := *owner
			o.RetiredFloor = p.RetiredDispatchSequence
			reply.RequestID = p.RequestID
			reply.Ownership = &o
			if mutation != "missing" {
				copy := *p.UnstartedStop
				reply.UnstartedStop = &copy
			}
			if mutation == "foreign" {
				reply.UnstartedStop.SourceCommandID = domain.NewID().String()
			}
			if mutation == "rollback" {
				reply.Ownership = nil
				reply.PublicError = "unavailable"
				reply.Retryable = true
			}
		}
		c.OwnershipDisposition(reply)
		return nil
	})
	o, e := c.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", "")
	if e != nil {
		t.Fatal(e)
	}
	// Historical source is intentionally distinct from the current RPC connection.
	proof := transport.NativeDispatchProof{OwnershipID: o.ID, OwnershipGeneration: scope.Generation, DispatchSequence: 1, SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String(), SourceRunnerID: domain.NewID().String(), SourceRunnerEpoch: time.Now().UTC().Add(-time.Hour), SourceBootID: "original-boot"}
	for _, m := range []string{"missing", "foreign", "rollback", ""} {
		mutation = m
		_, e = c.RetireNativeWorkerOwnership(t.Context(), scope, spec, "", *o, 1, nil, false, &proof)
		if m == "" && e != nil {
			t.Fatal(e)
		}
		if m != "" && !errors.Is(e, ErrNativeOriginAdmissionDeferred) {
			t.Fatal("uncommitted or changed stop proof authorized prune", m, e)
		}
	}
}
