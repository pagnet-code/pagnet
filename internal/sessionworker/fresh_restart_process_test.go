//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

func TestOwnedExplicitRestartStartsFreshWithoutReplayingOldNativeWork(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "binary", "native")
	if err = os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	testBinary(t, root, binary, "./cmd/pagnet-fake-runtime", "")
	scope := testScope()
	scope.InstanceID = uuid.NewString()
	j, err := OpenJournal(filepath.Join(t.TempDir(), "worker"), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: binary, MCPExecutable: binary, Workspace: t.TempDir(), TenantID: scope.TenantID, NetworkTenantID: scope.TenantID, NetworkID: uuid.NewString(), Kind: "worker"}
	owner, err := NewSessionOwner(context.Background(), j, spec, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	owner.generation = "original-native-generation"
	owner.origin = json.RawMessage(`{"id":"` + uuid.NewString() + `","nativeGeneration":"original-native-generation"}`)
	owner.sess.Env, err = owner.launchEnvironment("original-fixture-nonce")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Only initial fixture authority is installed here. Replacement activation
	// must traverse the real owned driver's original-command authority request.
	owner.manager.RegisterDriver(owner.driver)
	if _, err = owner.manager.EnsureActive(ctx, owner.sess, make(chan session.SessionEvent, 64)); err != nil {
		t.Fatal(err)
	}
	owner.manager.RegisterDriver(&ownedDriver{Driver: owner.driver, owner: owner})
	original := owner.Snapshot()
	if original.NativeSessionID == "" || original.PID <= 0 {
		t.Fatal("no actual original native endpoint")
	}
	if err = owner.manager.Stop(scope.InstanceID); err != nil {
		t.Fatal(err)
	}
	// The actual terminal-stop path can retain this unmaterialised inactive ID;
	// ordinary resume must not silently manufacture a replacement conversation.
	owner.sess.State = session.StateInactive
	if _, err = owner.manager.EnsureActive(ctx, owner.sess, nil); err != session.ErrNotMaterialised {
		t.Fatalf("ordinary resume unexpectedly accepted: %v", err)
	}
	before, err := j.PendingObservations(ctx, 32)
	if err != nil {
		t.Fatal(err)
	}
	admitted := Admission{NativeAdmissionID: uuid.NewString(), Scope: scope, TenantID: scope.TenantID, NetworkID: spec.NetworkID, Kind: spec.Kind, RunnerID: uuid.NewString(), RunnerEpoch: time.Now().UTC(), BootID: uuid.NewString()}
	current := lease(t, j)
	owner.relay.bindLease(current)
	if err = owner.relay.admit(current, admitted); err != nil {
		t.Fatal(err)
	}
	operation := Operation{SourceCommandID: uuid.NewString(), SourceAdmissionID: admitted.NativeAdmissionID, InputKind: "wake"}
	raw, _ := json.Marshal(operation)
	outcome, execute, err := j.admit(ctx, current, 1, "explicit-original-restart", "restart", raw, func() (*Admission, error) { copy := admitted; return &copy, nil })
	if err != nil || !execute {
		t.Fatalf("restart admission: %v", err)
	}
	owner.Execute(outcome, raw)
	var request *ActivationRequest
	for request == nil && ctx.Err() == nil {
		request, err = owner.relay.pollActivation(current)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	if request == nil {
		t.Fatal("restart never requested fresh original authority", ctx.Err())
	}
	if request.SourceCommandID != operation.SourceCommandID || request.NativeGeneration == original.NativeGeneration {
		t.Fatal("restart reused old generation/command authority")
	}
	newOrigin, _ := json.Marshal(map[string]any{"id": uuid.NewString(), "commandId": operation.SourceCommandID, "tenantId": scope.TenantID, "hostId": scope.HostID, "instanceId": scope.InstanceID, "runtime": spec.Runtime, "nativeGeneration": request.NativeGeneration, "nativeAdmissionId": admitted.NativeAdmissionID, "runnerId": admitted.RunnerID, "runnerEpoch": admitted.RunnerEpoch, "bootId": admitted.BootID, "createdAt": time.Now().UTC()})
	if err = owner.relay.completeActivation(current, ActivationOrigin{ID: request.ID, NativeGeneration: request.NativeGeneration, Origin: newOrigin}); err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil {
		outcome, err = j.Outcome(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.State != "admitted" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if outcome.State != "completed" {
		t.Fatalf("restart did not complete: %s %s", outcome.State, string(outcome.Result))
	}
	after := owner.Snapshot()
	if after.NativeSessionID == original.NativeSessionID || after.NativeGeneration == original.NativeGeneration || after.PID == original.PID || after.PID <= 0 {
		t.Fatal("restart did not establish a genuine new endpoint/session/generation")
	}
	rows, err := j.PendingObservations(ctx, 32)
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range before {
		found := false
		for _, row := range rows {
			if row.ID == old.ID {
				found = true
				if row.SourceDigest != old.SourceDigest || !bytes.Equal(row.Origin, old.Origin) {
					t.Fatal("restart rewrote original source history")
				}
			}
		}
		if !found {
			t.Fatal("restart erased original unacknowledged capture")
		}
	}
	for _, row := range rows {
		if row.Event.Type == session.EventTurnStarted {
			t.Fatal("restart replayed an old prompt or synthesised a native turn")
		}
	}
	replay, run, err := j.admit(ctx, current, 1, "explicit-original-restart", "restart", raw, func() (*Admission, error) { t.Fatal("replay consulted replacement source"); return nil, nil })
	if err != nil || run || replay.State != "completed" {
		t.Fatal("original restart replay executed twice")
	}
}
