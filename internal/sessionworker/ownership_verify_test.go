//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/internal/proc"
	"os"
	"reflect"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func verificationSnapshot(t *testing.T, j *Journal, ownership transport.NativeWorkerOwnership) NativeSnapshot {
	t.Helper()
	origin, err := json.Marshal(transport.NativeObservationOrigin{ID: "origin", TenantID: j.scope.TenantID, HostID: j.scope.HostID, InstanceID: j.scope.InstanceID, NativeGeneration: "native-generation", Runtime: ownership.Runtime, NativeSessionID: "native-session"})
	if err != nil {
		t.Fatal(err)
	}
	start, err := proc.StartIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return NativeSnapshot{Scope: j.scope, PID: os.Getpid(), NativeStartIdentity: start, ActualRuntime: domain.RuntimeName(ownership.Runtime), ProfileFingerprint: ownership.ProfileFingerprint, NativeGeneration: "native-generation", NativeSessionID: "native-session", Origin: origin}
}

func TestOwnershipVerifyExactFreshSnapshot(t *testing.T) {
	j, _ := testJournal(t)
	current := lease(t, j)
	ownership := dispatchOwnership(t, j, current)
	snapshot := verificationSnapshot(t, j, ownership)
	// Server progress is mutable metadata, not immutable ownership identity.
	ownership.LastDispatchSequence, ownership.RetiredFloor = 19, 12
	calls := 0
	result, err := j.verifyOwnershipSnapshot(t.Context(), current, NativeOwnershipVerifyRequest{Ownership: ownership}, func() NativeSnapshot {
		calls++
		return snapshot
	})
	if err != nil || result == nil || calls != 1 || !reflect.DeepEqual(result.Snapshot, snapshot) {
		t.Fatal("fresh exact physical snapshot unavailable", result, calls, err)
	}
}

func TestOwnershipVerifyRejectsWrongOwnershipBeforeCollection(t *testing.T) {
	for _, field := range []string{"id", "instance", "generation", "runtime", "profile", "fingerprint", "admission", "state", "deletion"} {
		t.Run(field, func(t *testing.T) {
			j, _ := testJournal(t)
			current := lease(t, j)
			ownership := dispatchOwnership(t, j, current)
			switch field {
			case "id":
				ownership.ID = domain.NewID().String()
			case "instance":
				ownership.InstanceID = "another"
			case "generation":
				ownership.OwnershipGeneration = "another"
			case "runtime":
				ownership.Runtime = "another"
			case "profile":
				ownership.Profile = "another"
			case "fingerprint":
				ownership.ProfileFingerprint = "another"
			case "admission":
				ownership.OriginalAdmissionID = domain.NewID().String()
			case "state":
				ownership.State = "retired"
			case "deletion":
				ownership.DeletionProof = &transport.NativeOwnershipDeletionProof{}
			}
			result, err := j.verifyOwnershipSnapshot(t.Context(), current, NativeOwnershipVerifyRequest{Ownership: ownership}, func() NativeSnapshot { t.Fatal("wrong ownership reached physical collection"); return NativeSnapshot{} })
			if !errors.Is(err, ErrConflict) || result != nil {
				t.Fatal(result, err)
			}
		})
	}
}

func TestOwnershipVerifyFencesChangesDuringCollection(t *testing.T) {
	for _, change := range []string{"controller", "retirement", "ownership"} {
		t.Run(change, func(t *testing.T) {
			j, _ := testJournal(t)
			current := lease(t, j)
			ownership := dispatchOwnership(t, j, current)
			want := ErrConflict
			if change == "controller" {
				want = ErrFenced
			}
			result, err := j.verifyOwnershipSnapshot(t.Context(), current, NativeOwnershipVerifyRequest{Ownership: ownership}, func() NativeSnapshot {
				switch change {
				case "controller":
					lease(t, j)
				case "retirement":
					retired := ownership
					retired.State = "retired"
					if err := j.CommitOwnershipRetirement(t.Context(), current, retired); err != nil {
						t.Fatal(err)
					}
				case "ownership":
					if _, err := j.db.Exec(`UPDATE worker_dispatch_meta SET ownership='{}'`); err != nil {
						t.Fatal(err)
					}
				}
				return verificationSnapshot(t, j, ownership)
			})
			if !errors.Is(err, want) || result != nil {
				t.Fatal(result, err)
			}
		})
	}
}

func TestOwnershipVerifyRejectsRetiredAndStaleLeaseBeforeCollection(t *testing.T) {
	for _, retired := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale_lease", true: "retired"}[retired], func(t *testing.T) {
			j, _ := testJournal(t)
			current := lease(t, j)
			ownership := dispatchOwnership(t, j, current)
			want := ErrFenced
			if retired {
				proof := ownership
				proof.State = "retired"
				if err := j.CommitOwnershipRetirement(t.Context(), current, proof); err != nil {
					t.Fatal(err)
				}
				want = ErrConflict
			} else {
				lease(t, j)
			}
			result, err := j.verifyOwnershipSnapshot(t.Context(), current, NativeOwnershipVerifyRequest{Ownership: ownership}, func() NativeSnapshot { t.Fatal("fenced read reached physical collection"); return NativeSnapshot{} })
			if !errors.Is(err, want) || result != nil {
				t.Fatal(result, err)
			}
		})
	}
}

func TestOwnershipVerifyRejectsIncompleteOrMismatchedPhysicalIdentity(t *testing.T) {
	for _, field := range []string{"pending", "pid", "start", "reused_pid", "scope", "runtime", "profile", "generation", "session", "origin", "origin_generation", "origin_session"} {
		t.Run(field, func(t *testing.T) {
			j, _ := testJournal(t)
			current := lease(t, j)
			ownership := dispatchOwnership(t, j, current)
			snapshot := verificationSnapshot(t, j, ownership)
			switch field {
			case "pending":
				snapshot.IdentityPending = true
			case "pid":
				snapshot.PID = 0
			case "start":
				snapshot.NativeStartIdentity = ""
			case "reused_pid":
				snapshot.NativeStartIdentity = "previous-process-at-same-pid"
			case "scope":
				snapshot.Scope.Generation = "another"
			case "runtime":
				snapshot.ActualRuntime = "another"
			case "profile":
				snapshot.ProfileFingerprint = "another"
			case "generation":
				snapshot.NativeGeneration = ""
			case "session":
				snapshot.NativeSessionID = ""
			case "origin":
				snapshot.Origin = nil
			case "origin_generation":
				snapshot.NativeGeneration = "another"
			case "origin_session":
				snapshot.NativeSessionID = "another"
			}
			result, err := j.verifyOwnershipSnapshot(t.Context(), current, NativeOwnershipVerifyRequest{Ownership: ownership}, func() NativeSnapshot { return snapshot })
			if !errors.Is(err, ErrNativeBusy) || result != nil {
				t.Fatal(result, err)
			}
		})
	}
}

func TestOwnershipVerifyRequiresExistingBinding(t *testing.T) {
	j, _ := testJournal(t)
	current := lease(t, j)
	result, err := j.verifyOwnershipSnapshot(t.Context(), current, NativeOwnershipVerifyRequest{Ownership: transport.NativeWorkerOwnership{State: "active"}}, func() NativeSnapshot {
		t.Fatal("unbound worker reached physical collection")
		return NativeSnapshot{}
	})
	if !errors.Is(err, ErrConflict) || result != nil {
		t.Fatal(result, err)
	}
	var count int
	if err := j.db.QueryRow(`SELECT count(*) FROM worker_dispatch_meta`).Scan(&count); err != nil || count != 0 {
		t.Fatal("verification bound ownership", count, err)
	}
}

func TestOwnershipVerifyOwnerRequestRequiresTypedInputAndRetriesPendingIdentity(t *testing.T) {
	j, _ := testJournal(t)
	current := lease(t, j)
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: t.TempDir(), TenantID: j.scope.TenantID, NetworkTenantID: j.scope.TenantID, NetworkID: domain.NewID().String(), Kind: "worker"}
	owner, err := NewSessionOwner(t.Context(), j, spec, bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	ownership := transport.NativeWorkerOwnership{ID: domain.NewID().String(), InstanceID: j.scope.InstanceID, OwnershipGeneration: j.scope.Generation, Runtime: string(spec.Runtime), OriginalAdmissionID: domain.NewID().String(), State: "active", ProfileFingerprint: NativeProfileFingerprint(spec)}
	if err := j.BindDispatchOwnership(t.Context(), current, ownership, ownership.Runtime, ownership.ProfileFingerprint); err != nil {
		t.Fatal(err)
	}
	// No physical identity exists. Verification may neither launch one nor
	// accept the generic ownership field used by mutation RPCs.
	response := owner.controllerRequest(t.Context(), current, Request{Type: "ownership_verify", Ownership: &ownership})
	if response.Error != ErrConflict.Error() || response.OwnershipVerify != nil || response.Retryable {
		t.Fatal(response)
	}
	response = owner.controllerRequest(t.Context(), current, Request{Type: "ownership_verify", OwnershipVerify: &NativeOwnershipVerifyRequest{Ownership: ownership}})
	if response.Error != ErrNativeBusy.Error() || response.OwnershipVerify != nil || !response.Retryable {
		t.Fatal(response)
	}
}
