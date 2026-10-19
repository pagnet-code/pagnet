//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
	"testing"
)

func TestNativeGCOriginalTupleAndRemoteCommitBeforeRegistryReclaim(t *testing.T) {
	registry, scope, spec := nativeRegistryFixture(t)
	record, err := registry.Reserve(scope, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ownership := transport.NativeWorkerOwnership{ID: domain.NewID().String(), InstanceID: scope.InstanceID, OwnershipGeneration: scope.Generation, Runtime: string(spec.Runtime), ProfileFingerprint: record.ProfileFingerprint, OriginalAdmissionID: domain.NewID().String(), State: "active"}
	if err = registry.BindOwnership(record, ownership); err != nil {
		t.Fatal(err)
	}
	record, err = registry.Lookup(scope.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	p := transport.ForgetInstancePayload{CommandID: domain.NewID().String(), DeleteRequestID: domain.NewID().String(), InstanceID: scope.InstanceID, NativeOwnership: &ownership}
	gc, err := registry.beginGC(record, p)
	if err != nil {
		t.Fatal(err)
	}
	confirmation := transport.NativeInstanceForgottenPayload{CommandID: p.CommandID, DeleteRequestID: p.DeleteRequestID, InstanceID: p.InstanceID, OwnershipID: ownership.ID, OwnershipGeneration: scope.Generation, Disposition: "forgotten"}
	if err = registry.confirmGC(context.Background(), confirmation); err == nil {
		t.Fatal("uncollected journal reclaimed")
	}
	foreign := p
	foreign.DeleteRequestID = domain.NewID().String()
	if _, err = registry.beginGC(record, foreign); err == nil {
		t.Fatal("deletion authority replaced")
	}
	gc, err = registry.advanceGC(p.InstanceID, gc, "retiring", &ownership)
	if err != nil {
		t.Fatal(err)
	}
	retired := ownership
	retired.State = "retired"
	gc, err = registry.advanceGC(p.InstanceID, gc, "backend_retired", &retired)
	if err != nil {
		t.Fatal(err)
	}
	retry := p
	retry.NativeOwnership = &retired
	resumed, retryErr := registry.beginGC(record, retry)
	if retryErr != nil || resumed.Phase != "backend_retired" {
		t.Fatal("exact retired delivery cannot resume original deletion", retryErr)
	}
	badRetired := retired
	badRetired.RetiredFloor++
	retry.NativeOwnership = &badRetired
	if _, err := registry.beginGC(record, retry); err == nil {
		t.Fatal("refreshed delivery replaced committed retirement proof")
	}
	retry.NativeOwnership = &retired
	retry.DeleteRequestID = domain.NewID().String()
	if _, err := registry.beginGC(record, retry); err == nil {
		t.Fatal("foreign job reused retired collection authority")
	}
	gc, err = registry.advanceGC(p.InstanceID, gc, "collecting", nil)
	if err != nil {
		t.Fatal(err)
	}
	gc, err = registry.advanceGC(p.InstanceID, gc, "collected", nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := confirmation
	bad.OwnershipGeneration = "foreign"
	if err = registry.confirmGC(context.Background(), bad); err == nil {
		t.Fatal("foreign confirmation removed private authority")
	}
	if !registry.Owns(p.InstanceID) {
		t.Fatal("lost ACK discarded registry authority")
	}
	if err = registry.confirmGC(context.Background(), confirmation); err != nil {
		t.Fatal(err)
	}
	if registry.Owns(p.InstanceID) {
		t.Fatal("completed deletion leaks lifetime registry row")
	}
	if _, err = registry.lookupGC(p.InstanceID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("completed deletion leaks marker", err)
	}
}

func TestNativeGCRetirementLostReplyRecovery(t *testing.T) {
	registry, scope, spec := nativeRegistryFixture(t)
	record, err := registry.Reserve(scope, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ownership := transport.NativeWorkerOwnership{ID: domain.NewID().String(), InstanceID: scope.InstanceID, OwnershipGeneration: scope.Generation, Runtime: string(spec.Runtime), ProfileFingerprint: record.ProfileFingerprint, OriginalAdmissionID: domain.NewID().String(), State: "active"}
	if err := registry.BindOwnership(record, ownership); err != nil {
		t.Fatal(err)
	}
	record, err = registry.Lookup(scope.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	p := transport.ForgetInstancePayload{CommandID: domain.NewID().String(), DeleteRequestID: domain.NewID().String(), InstanceID: scope.InstanceID, NativeOwnership: &ownership}
	gc, err := registry.beginGC(record, p)
	if err != nil {
		t.Fatal(err)
	}
	settled := ownership
	settled.LastDispatchSequence, settled.RetiredFloor = 3, 3
	proof := &transport.NativeOwnershipDeletionProof{DeleteRequestID: p.DeleteRequestID, StopProof: transport.NativeDispatchProof{OwnershipID: ownership.ID, OwnershipGeneration: scope.Generation, DispatchSequence: 3}, StoppedDigest: "original-stop"}
	retired := settled
	retired.State, retired.DeletionProof = "retired", proof
	retry := p
	retry.NativeOwnership = &retired
	if _, err := registry.beginGC(record, retry); err == nil {
		t.Fatal("waiting job accepted retirement without preparing worker checks")
	}
	if _, err := registry.advanceGC(p.InstanceID, gc, "backend_retired", &retired); err == nil {
		t.Fatal("waiting job skipped retirement preparation")
	}
	if _, err := registry.advanceGC(p.InstanceID, gc, "retiring", &settled, proof); err != nil {
		t.Fatal(err)
	}
	activeRetry, err := registry.beginGC(record, p)
	if err != nil || activeRetry.Phase != "retiring" || activeRetry.Ownership.RetiredFloor != 3 {
		t.Fatal("stale active delivery replaced prepared retirement", err)
	}
	// The backend commits, but its response never reaches the daemon. Reload
	// solely from the durable marker and a refreshed authenticated delivery.
	gc, err = registry.beginGC(record, retry)
	if err != nil || gc.Phase != "retiring" || gc.Ownership.RetiredFloor != 3 || gc.DeletionProof == nil {
		t.Fatalf("prepared retirement not recovered: %+v, %v", gc, err)
	}
	for _, mutate := range []func(*transport.NativeWorkerOwnership){
		func(o *transport.NativeWorkerOwnership) { o.LastDispatchSequence++; o.RetiredFloor++ },
		func(o *transport.NativeWorkerOwnership) { o.OriginalAdmissionID = "foreign" },
		func(o *transport.NativeWorkerOwnership) { o.DeletionProof = nil },
		func(o *transport.NativeWorkerOwnership) {
			copy := *o.DeletionProof
			copy.StoppedDigest = "foreign"
			o.DeletionProof = &copy
		},
		func(o *transport.NativeWorkerOwnership) {
			copy := *o.DeletionProof
			copy.DeleteRequestID = "foreign"
			o.DeletionProof = &copy
		},
	} {
		bad := retired
		mutate(&bad)
		retry.NativeOwnership = &bad
		if _, err := registry.beginGC(record, retry); err == nil {
			t.Fatal("refreshed retirement replaced prepared authority")
		}
		if _, err := registry.advanceGC(p.InstanceID, gc, "backend_retired", &bad); err == nil {
			t.Fatal("retirement response replaced prepared authority")
		}
	}
	retry.NativeOwnership = &retired
	gc, err = registry.advanceGC(p.InstanceID, gc, "backend_retired", retry.NativeOwnership)
	if err != nil || gc.Phase != "backend_retired" {
		t.Fatal("authoritative retired ownership could not finish lost response", err)
	}
}
