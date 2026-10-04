//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/session"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func TestNativeOwnerImportsStoredSessionOnlyBeforeFirstOperation(t *testing.T) {
	j, _ := testJournal(t)
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: t.TempDir(), NetworkID: "network", NetworkTenantID: j.scope.TenantID, TenantID: j.scope.TenantID, Kind: "worker", InitialNativeSessionID: "original-host-native-session"}
	owner, err := NewSessionOwner(context.Background(), j, spec, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := owner.manager.NativeID(j.scope.InstanceID); id != spec.InitialNativeSessionID || !owner.sess.Materialised || owner.supervisor.EndpointPID(j.scope.InstanceID) != nil {
		t.Fatal("stored session not imported without executing a process")
	}
	owner.Close()
	// The permanent admission counter survives retirement and journal pruning.
	// An old bootstrap must not replace a later deliberate fresh conversation.
	if _, err := j.db.Exec(`UPDATE worker_meta SET next_sequence=3,retired=2 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	owner, err = NewSessionOwner(context.Background(), j, spec, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if id, _ := owner.manager.NativeID(j.scope.InstanceID); id != "" {
		t.Fatal("bootstrap resurrected original conversation after earlier worker operations")
	}
}

func TestNativeOwnerStoredSessionRequiresGenuineResume(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "bin", "native")
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	testBinary(t, root, binary, "./cmd/pagnet-fake-runtime", "")
	j, _ := testJournal(t)
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: binary, MCPExecutable: binary, Workspace: t.TempDir(), NetworkID: uuid.NewString(), NetworkTenantID: j.scope.TenantID, TenantID: j.scope.TenantID, Kind: "worker", InitialNativeSessionID: uuid.NewString()}
	owner, err := NewSessionOwner(context.Background(), j, spec, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	owner.generation = "original-generation"
	owner.origin = json.RawMessage(`{"id":"` + uuid.NewString() + `","nativeGeneration":"original-generation"}`)
	owner.sess.Env, err = owner.launchEnvironment("fixture-nonce")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err = owner.driver.Activate(ctx, owner.sess, make(chan session.SessionEvent, 64)); !errors.Is(err, session.ErrSessionLost) {
		t.Fatalf("missing native history did not fail honestly: %v", err)
	}
	// Preserve the observed original resume failure through durable outcome
	// recovery; a controller must not misclassify it as a headless runtime.
	activationErr := err
	if _, _, err = j.Admit(ctx, lease(t, j), 1, "original-resume-attach", "attach", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	owner.finish(1, nil, activationErr)
	outcome, err := j.Outcome(ctx, 1)
	var failure NativeOperationFailure
	if err != nil || outcome.State != "failed" || json.Unmarshal(outcome.Result, &failure) != nil || failure.Code != "native_session_lost" || failure.Error != "native operation failed" {
		t.Fatal("original resume failure classification lost", outcome, err)
	}
	if bytes.Contains(outcome.Result, []byte(spec.InitialNativeSessionID)) {
		t.Fatal("public failure leaked original native session identity")
	}
	if owner.driver.Live(j.scope.InstanceID) {
		t.Fatal("failed resume silently left a fresh runtime running")
	}
	if id, _ := owner.manager.NativeID(j.scope.InstanceID); id != spec.InitialNativeSessionID {
		t.Fatal("failed resume silently switched to a new conversation")
	}
}
