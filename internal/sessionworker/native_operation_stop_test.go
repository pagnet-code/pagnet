//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func TestStopJoinsEarlierQueuedActivationBeforeDurableCompletion(t *testing.T) {
	j, _ := testJournal(t)
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: t.TempDir(), TenantID: j.scope.TenantID, NetworkTenantID: j.scope.TenantID, NetworkID: domain.NewID().String(), Kind: "worker"}
	owner, err := NewSessionOwner(t.Context(), j, spec, bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	current := lease(t, j)
	owner.relay.bindLease(current)
	a := Admission{Scope: j.scope, TenantID: j.scope.TenantID, NetworkID: spec.NetworkID, Kind: "worker", RunnerID: domain.NewID().String(), NativeAdmissionID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), BootID: "original-boot"}
	if err = owner.relay.admit(current, a); err != nil {
		t.Fatal(err)
	}
	admit := func(sequence int64, kind string) Outcome {
		t.Helper()
		command := domain.NewID().String()
		raw, _ := json.Marshal(Operation{SourceCommandID: command, SourceAdmissionID: a.NativeAdmissionID, InputKind: "user_input"})
		out, run, err := j.admit(t.Context(), current, sequence, command, kind, raw, func() (*Admission, error) { copy := a; return &copy, nil })
		if err != nil || !run {
			t.Fatal("original admission", err)
		}
		owner.Execute(out, raw)
		return out
	}
	// A prior operation owns the prompt fence. The earlier attach is durably
	// accepted but cannot reach native authority or launch until this releases.
	owner.prompt.Lock()
	locked := true
	defer func() {
		if locked {
			owner.prompt.Unlock()
		}
	}()
	attach := admit(1, "attach")
	stop := admit(2, "stop")
	deadline := time.Now().Add(3 * time.Second)
	for {
		out, err := j.Outcome(t.Context(), stop.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		if out.State == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stop did not join queued original activation", out.State)
		}
		time.Sleep(time.Millisecond)
	}
	prior, err := j.Outcome(t.Context(), attach.Sequence)
	if err != nil || prior.State != "failed" {
		t.Fatal("stop completed before exact prior cancellation settled", prior, err)
	}
	owner.prompt.Unlock()
	locked = false
	if ticket, err := owner.relay.pollActivation(current); err != nil || ticket != nil {
		t.Fatal("stopped earlier operation requested fresh native authority", ticket, err)
	}
	if snap := owner.Snapshot(); snap.PID != 0 || snap.IdentityPending || snap.HasTerminal {
		t.Fatal("queued activation resurrected original endpoint", snap)
	}
}

func TestStopReapsGenuineAcceptedPromptWithoutErasingUncertainty(t *testing.T) {
	testStopAcceptedPrompt(t, false)
}
func TestFailedStopDoesNotWaitOnUnkillableAcceptedPrompt(t *testing.T) {
	testStopAcceptedPrompt(t, true)
}

type refusedNativeStopDriver struct{ session.Driver }

func (refusedNativeStopDriver) Stop(string) error { return errors.New("fixture original stop refused") }

func testStopAcceptedPrompt(t *testing.T, refuseStop bool, invocation ...bool) {
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
	scope.TenantID, scope.AccountID, scope.HostID, scope.InstanceID, scope.Generation = domain.NewID().String(), domain.NewID().String(), domain.NewID().String(), domain.NewID().String(), domain.NewID().String()
	j, err := OpenJournal(filepath.Join(t.TempDir(), "worker"), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: binary, MCPExecutable: binary, Workspace: t.TempDir(), TenantID: j.scope.TenantID, NetworkTenantID: j.scope.TenantID, NetworkID: domain.NewID().String(), Kind: "worker", Env: []string{"PAGNET_FAKE_INTERACTION=permission"}}

	var invocationSource *transport.NativeInvocationSource
	if len(invocation) > 0 && invocation[0] {
		spec.NetworkStateDir = t.TempDir()
		ring := hostcrypto.NewKeyring(spec.NetworkID)
		epoch, err := ring.Activate(time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if err = hostcrypto.SaveKeyring(spec.NetworkStateDir, ring); err != nil {
			t.Fatal(err)
		}
		invocationSource = &transport.NativeInvocationSource{InvocationID: "original-stop-invocation", InputAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: spec.TenantID, NetworkID: spec.NetworkID, ObjectType: e2ee.ObjectTypeInvocationInput, ObjectID: "original-stop-invocation", KeyEpochID: epoch.ID}}
	}
	owner, err := NewSessionOwner(t.Context(), j, spec, bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	current := lease(t, j)
	owner.relay.bindLease(current)
	a := Admission{Scope: j.scope, TenantID: j.scope.TenantID, NetworkID: spec.NetworkID, Kind: "worker", RunnerID: domain.NewID().String(), NativeAdmissionID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), BootID: "original-boot"}
	if err = owner.relay.admit(current, a); err != nil {
		t.Fatal(err)
	}
	admit := func(sequence int64, kind string) Outcome {
		t.Helper()
		command := domain.NewID().String()
		op := Operation{SourceCommandID: command, SourceAdmissionID: a.NativeAdmissionID, InputKind: "user_input", Input: "test original accepted prompt"}
		if kind == "prompt" && invocationSource != nil {
			op.InputKind = "invocation"
			op.SourceInvocation = invocationSource
		}
		raw, _ := json.Marshal(op)
		out, run, err := j.admit(t.Context(), current, sequence, command, kind, raw, func() (*Admission, error) { copy := a; return &copy, nil })
		if err != nil || !run {
			t.Fatal("original admission", err)
		}
		owner.Execute(out, raw)
		return out
	}
	prompt := admit(1, "prompt")
	deadline := time.Now().Add(5 * time.Second)
	var ticket *ActivationRequest
	for ticket == nil {
		ticket, err = owner.relay.pollActivation(current)
		if err != nil || time.Now().After(deadline) {
			t.Fatal("original activation authority", err)
		}
		time.Sleep(time.Millisecond)
	}
	origin, _ := json.Marshal(map[string]any{"id": domain.NewID().String(), "commandId": ticket.SourceCommandID, "tenantId": j.scope.TenantID, "hostId": j.scope.HostID, "instanceId": j.scope.InstanceID, "runtime": spec.Runtime, "nativeGeneration": ticket.NativeGeneration, "nativeAdmissionId": a.NativeAdmissionID, "runnerId": a.RunnerID, "runnerEpoch": a.RunnerEpoch, "bootId": a.BootID, "createdAt": time.Now().UTC()})
	if err = owner.relay.completeActivation(current, ActivationOrigin{ID: ticket.ID, NativeGeneration: ticket.NativeGeneration, Origin: origin}); err != nil {
		t.Fatal(err)
	}
	for {
		rows, err := j.PendingObservations(t.Context(), 32)
		if err != nil {
			t.Fatal(err)
		}
		accepted := false
		for _, row := range rows {
			if row.Event.Type == session.EventTurnStarted {
				accepted = true
			}
		}
		if accepted {
			break
		}
		if time.Now().After(deadline) {
			out, _ := j.Outcome(t.Context(), prompt.Sequence)
			t.Fatal("runtime never accepted the genuine prompt", out, owner.Snapshot())
		}
		time.Sleep(time.Millisecond)
	}
	original := owner.Snapshot()
	if original.PID <= 0 || original.NativeSessionID == "" {
		t.Fatal("accepted prompt lacks genuine original endpoint", original)
	}
	if refuseStop {
		owner.manager.RegisterDriver(&ownedDriver{owner: owner, Driver: refusedNativeStopDriver{Driver: owner.driver}})
	}
	stop := admit(2, "stop")
	for {
		out, err := j.Outcome(t.Context(), stop.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		if out.State == "completed" || (refuseStop && out.State == "failed") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stop deadlocked on the accepted prompt", out.State)
		}
		time.Sleep(time.Millisecond)
	}
	if refuseStop {
		out, err := j.Outcome(t.Context(), prompt.Sequence)
		if err != nil || out.State != "admitted" || !owner.driver.Live(j.scope.InstanceID) {
			t.Fatal("failed stop altered genuine live turn", out, err)
		}
		rows, err := j.PendingObservations(t.Context(), 32)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.Event.Type == session.EventSessionStopped {
				t.Fatal("failed stop fabricated stopped evidence")
			}
		}
		// Independently stop the original process for fixture cleanup. Only this
		// genuine EOF may establish the interrupted outcome and stopped evidence.
		if err = owner.supervisor.StopEndpoint(j.scope.InstanceID); err != nil {
			t.Fatal(err)
		}
		for {
			out, err = j.Outcome(t.Context(), prompt.Sequence)
			if err != nil {
				t.Fatal(err)
			}
			if out.State != "admitted" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("genuine fixture cleanup did not settle")
			}
			time.Sleep(time.Millisecond)
		}
		owner.nativeObserverWG.Wait()
	}
	interrupted, err := j.Outcome(t.Context(), prompt.Sequence)
	if err != nil || interrupted.State != "uncertain" {
		t.Fatal("stop erased genuinely accepted effects", interrupted, err)
	}
	if owner.supervisor.EndpointPID(j.scope.InstanceID) != nil {
		t.Fatal("stop completed before original process reap")
	}
	observations, err := j.PendingObservations(t.Context(), 32)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, observation := range observations {
		if observation.Event.Type == session.EventSessionStopped && observation.NativeSessionID == original.NativeSessionID && observation.NativeGeneration == original.NativeGeneration {
			found = true
		}
	}
	if !found {
		t.Fatal("stop lacks original runtime reader's genuine stopped evidence")
	}
}
