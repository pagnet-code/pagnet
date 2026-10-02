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
	retired := ownership
	retired.State = "retired"
	gc, err = registry.advanceGC(p.InstanceID, gc, "backend_retired", &retired)
	if err != nil {
		t.Fatal(err)
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
