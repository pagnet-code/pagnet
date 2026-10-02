//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func TestOwnershipRetirementFencesAllLaterIntentsAcrossReopen(t *testing.T) {
	j, dir := testJournal(t)
	a := lease(t, j)
	ownership := dispatchOwnership(t, j, a)
	retired := ownership
	retired.State = "retired"
	for _, field := range []string{"active", "ownership", "admission", "generation", "profile", "floor"} {
		bad := retired
		switch field {
		case "active":
			bad.State = "active"
		case "ownership":
			bad.ID = domain.NewID().String()
		case "admission":
			bad.OriginalAdmissionID = domain.NewID().String()
		case "generation":
			bad.OwnershipGeneration = "foreign"
		case "profile":
			bad.Profile = "foreign"
		case "floor":
			bad.RetiredFloor = 1
			bad.LastDispatchSequence = 1
		}
		if err := j.CommitOwnershipRetirement(t.Context(), a, bad); err == nil {
			t.Fatal("foreign/unproven retirement admitted", field)
		}
	}
	b := lease(t, j)
	if err := j.CommitOwnershipRetirement(t.Context(), a, retired); !errors.Is(err, ErrFenced) {
		t.Fatal("stale controller retired worker", err)
	}
	if err := j.CommitOwnershipRetirement(t.Context(), b, retired); err != nil {
		t.Fatal(err)
	}
	if err := j.CommitOwnershipRetirement(t.Context(), b, retired); err != nil {
		t.Fatal("lost retirement response cannot replay", err)
	}
	if _, effect, err := j.Admit(t.Context(), b, 1, "late-resize", "resize", json.RawMessage(`{}`)); !errors.Is(err, ErrRetired) || effect {
		t.Fatal("retired worker accepts local intent", err, effect)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	b = lease(t, j)
	if _, effect, err := j.Admit(t.Context(), b, 1, "late-after-reopen", "resize", json.RawMessage(`{}`)); !errors.Is(err, ErrRetired) || effect {
		t.Fatal("reopen resurrected worker", err, effect)
	}
}

func TestOwnershipRetirementRefusesUnsettledLocalEffect(t *testing.T) {
	j, _ := testJournal(t)
	defer j.Close()
	a := lease(t, j)
	if _, _, err := j.Admit(t.Context(), a, 1, "local-effect", "resize", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	ownership := dispatchOwnership(t, j, a)
	ownership.State = "retired"
	if err := j.CommitOwnershipRetirement(t.Context(), a, ownership); !errors.Is(err, ErrConflict) {
		t.Fatal("unsettled local effect discarded", err)
	}
}

func TestAuthenticatedRetirementClosesOwnedListenerAfterResponse(t *testing.T) {
	j, dir := testJournal(t)
	defer j.Close()
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: t.TempDir(), NetworkID: domain.NewID().String(), NetworkTenantID: j.scope.TenantID, TenantID: j.scope.TenantID, Kind: "worker"}
	key := bytes.Repeat([]byte{7}, 32)
	owner, err := NewSessionOwner(t.Context(), j, spec, key)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	original := transport.NativeWorkerOwnership{ID: domain.NewID().String(), InstanceID: j.scope.InstanceID, OwnershipGeneration: j.scope.Generation, Runtime: string(spec.Runtime), OriginalAdmissionID: domain.NewID().String(), State: "active", ProfileFingerprint: NativeProfileFingerprint(spec)}
	if err = j.BindDispatchOwnership(t.Context(), lease(t, j), original, original.Runtime, original.ProfileFingerprint); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeOwner(ctx, owner, key, "retirement-fixture") }()
	var controller *Controller
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		controller, err = DialOwnerController(ctx, dir, j.scope, key, "current-controller")
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	retired := original
	retired.State = "retired"
	response, err := controller.Call(ctx, Request{Type: "worker_retire", Ownership: &retired})
	if err != nil || response.Error != "" {
		t.Fatal("retirement response lost before worker exit", response.Error, err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("retired original worker listener remains open")
	}
	if _, err = DialOwnerController(ctx, dir, j.scope, key, "later-controller"); err == nil {
		t.Fatal("retired original owner accepts new controller")
	}
}
