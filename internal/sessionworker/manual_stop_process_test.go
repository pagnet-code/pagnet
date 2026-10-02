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

func TestOwnedManualStopInterruptsBusyOriginalProcessWithoutCompletingPrompt(t *testing.T) {
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
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: binary, MCPExecutable: binary, Workspace: t.TempDir(), TenantID: scope.TenantID, NetworkTenantID: scope.TenantID, NetworkID: uuid.NewString(), Kind: "worker", Env: []string{"PAGNET_FAKE_INTERACTION=question"}}
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	owner.manager.RegisterDriver(owner.driver)
	if _, err = owner.manager.EnsureActive(ctx, owner.sess, make(chan session.SessionEvent, 64)); err != nil {
		t.Fatal(err)
	}
	owner.manager.RegisterDriver(&ownedDriver{Driver: owner.driver, owner: owner})
	original := owner.Snapshot()
	current := lease(t, j)
	ownership := dispatchOwnership(t, j, current)
	promptProof := dispatchProof(ownership, 1)
	operation := Operation{SourceCommandID: promptProof.SourceCommandID, SourceAdmissionID: promptProof.SourceAdmissionID, InputKind: "ask", Input: "original accepted prompt"}
	raw, _ := json.Marshal(operation)
	source := Admission{Scope: scope, NativeAdmissionID: promptProof.SourceAdmissionID, RunnerID: promptProof.SourceRunnerID, RunnerEpoch: promptProof.SourceRunnerEpoch, BootID: promptProof.SourceBootID}
	prompt, run, err := j.admitDispatch(ctx, current, 0, promptProof.SourceCommandID, "prompt", raw, func() (*Admission, error) { copy := source; return &copy, nil }, &promptProof)
	if err != nil || !run {
		t.Fatal("original prompt admission failed", err)
	}
	owner.Execute(prompt, raw)
	var pending NativeObservation
	for ctx.Err() == nil {
		rows, e := j.PendingObservations(ctx, 32)
		if e != nil {
			t.Fatal(e)
		}
		for _, row := range rows {
			if row.Event.Type == session.EventInteractionStarted {
				pending = row
			}
		}
		if pending.ID != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pending.ID == "" {
		t.Fatal("actual native process never blocked on permission", ctx.Err())
	}
	// A local view operation occupies operation 2 but has no backend ordinal.
	local, run, err := j.Admit(ctx, current, 2, "local-resize", "resize", json.RawMessage(`{}`))
	if err != nil || !run {
		t.Fatal(err)
	}
	if err = j.Settle(ctx, local.Sequence, "completed", nil); err != nil {
		t.Fatal(err)
	}
	stopProof := dispatchProof(ownership, 2)
	stopOp := Operation{SourceCommandID: stopProof.SourceCommandID, SourceAdmissionID: stopProof.SourceAdmissionID}
	stopRaw, _ := json.Marshal(stopOp)
	stopSource := source
	stopSource.NativeAdmissionID = stopProof.SourceAdmissionID
	stopSource.RunnerID = stopProof.SourceRunnerID
	stopSource.RunnerEpoch = stopProof.SourceRunnerEpoch
	stopSource.BootID = stopProof.SourceBootID
	stop, run, err := j.admitDispatch(ctx, current, 0, stopProof.SourceCommandID, "stop", stopRaw, func() (*Admission, error) { copy := stopSource; return &copy, nil }, &stopProof)
	if err != nil || !run || stop.Sequence != 3 {
		t.Fatal("stop did not map distinct local operation", stop.Sequence, err)
	}
	owner.Execute(stop, stopRaw)
	for ctx.Err() == nil {
		stop, err = j.Outcome(ctx, 3)
		if err != nil {
			t.Fatal(err)
		}
		if stop.State != "admitted" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if stop.State != "completed" || owner.driver.Live(scope.InstanceID) {
		t.Fatal("explicit stop refused busy native process", stop.State)
	}
	rows, err := j.PendingObservations(ctx, 32)
	if err != nil {
		t.Fatal(err)
	}
	retained, stopped := false, false
	for _, row := range rows {
		if row.ID == pending.ID {
			retained = true
			if row.SourceDigest != pending.SourceDigest {
				t.Fatal("stop rewrote original private permission")
			}
		}
		if row.Event.Type == session.EventSessionStopped && row.NativeGeneration == original.NativeGeneration && row.NativeSessionID == original.NativeSessionID {
			stopped = true
		}
		if row.Event.Type == session.EventTurnCompleted {
			t.Fatal("stop invented vendor completion")
		}
	}
	if !retained || !stopped {
		t.Fatal("stop discarded original permission or lacked genuine original EOF")
	}
	records, err := j.DispatchRecords(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		if record.Proof.DispatchSequence == 2 {
			found = true
			if record.OperationSequence != 3 || record.State != "completed" {
				t.Fatal("stop mapping adopted dispatch as operation")
			}
		}
	}
	if !found {
		t.Fatal("stop mapping missing")
	}
}
