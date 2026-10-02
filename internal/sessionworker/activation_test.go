//go:build linux || darwin

package sessionworker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func TestActivationAuthorityBeforeNativeGenerationAndReconnection(t *testing.T) {
	j, _ := testJournal(t)
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, TenantID: "tenant", NetworkID: "network", Kind: "worker"}
	o := &SessionOwner{journal: j, spec: spec, relay: newRelayBroker(j.scope, spec)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type answer struct {
		origin json.RawMessage
		err    error
	}
	for _, generation := range []string{"first-attempt", "proven-unaccepted-retry"} {
		done := make(chan answer, 1)
		go func() {
			origin, err := o.awaitActivationOrigin(ctx, "same-source-command", generation)
			done <- answer{origin, err}
		}()
		o.relay.bindLease(1)
		admission := Admission{NativeAdmissionID: "native-admission-original", Scope: j.scope, TenantID: spec.TenantID, NetworkID: spec.NetworkID, Kind: spec.Kind, RunnerID: "runner-one", RunnerEpoch: time.Now().UTC(), BootID: "boot-one"}
		if generation == "proven-unaccepted-retry" {
			o.relay.bindLease(3)
			admission.RunnerID = "runner-three"
		}
		lease := o.relay.lease
		if err := o.relay.admit(lease, admission); err != nil {
			t.Fatal(err)
		}
		var request *ActivationRequest
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			request, _ = o.relay.pollActivation(lease)
			if request != nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if request == nil || request.NativeGeneration != generation || request.SourceCommandID != "same-source-command" {
			t.Fatalf("wrong actual activation request: %+v", request)
		}
		raw, _ := json.Marshal(map[string]any{"id": "origin-" + generation, "commandId": request.SourceCommandID, "tenantId": spec.TenantID, "hostId": j.scope.HostID, "instanceId": j.scope.InstanceID, "runtime": spec.Runtime, "nativeGeneration": generation, "nativeAdmissionId": admission.NativeAdmissionID, "runnerId": admission.RunnerID, "runnerEpoch": admission.RunnerEpoch, "bootId": admission.BootID, "createdAt": time.Now().UTC()})
		result := ActivationOrigin{ID: request.ID, NativeGeneration: generation, Origin: raw}
		wrong := result
		wrong.NativeGeneration = "another-generation"
		if err := o.relay.completeActivation(lease, wrong); err == nil {
			t.Fatal("wrong native generation authorized")
		}
		select {
		case <-done:
			t.Fatal("activation passed before authority reply")
		default:
		}
		// A disconnected controller cannot complete its old attempt. Fresh admission
		// reissues this still-unlaunched attempt with the same native generation.
		o.relay.disconnect(lease)
		if err := o.relay.completeActivation(lease, result); err == nil {
			t.Fatal("disconnected controller authorized activation")
		}
		o.relay.bindLease(lease + 1)
		admission.RunnerID += "-replacement"
		admission.NativeAdmissionID = "native-admission-current"
		if err := o.relay.admit(lease+1, admission); err != nil {
			t.Fatal(err)
		}
		request, err := o.relay.pollActivation(lease + 1)
		if err != nil || request == nil || request.NativeGeneration != generation {
			t.Fatalf("prelaunch request lost on reconnect: %+v %v", request, err)
		}
		if err := o.relay.completeActivation(lease, result); err == nil {
			t.Fatal("old lease authorized native launch")
		}
		// The source admission is immutable even when B retrieves an origin that
		// A already committed before losing its reply. Only the control lease renews.
		if request.Admission.RunnerID != resultRunner(raw) || request.CurrentAdmission.RunnerID != admission.RunnerID {
			t.Fatal("reconnect rewrote activation source admission")
		}
		var updated map[string]any
		_ = json.Unmarshal(raw, &updated)
		updated["runnerId"] = admission.RunnerID
		forged := result
		forged.Origin, _ = json.Marshal(updated)
		if err := o.relay.completeActivation(lease+1, forged); err == nil {
			t.Fatal("current transport rewrote original origin")
		}
		if err := o.relay.completeActivation(lease+1, result); err != nil {
			t.Fatal(err)
		}
		select {
		case actual := <-done:
			if actual.err != nil || string(actual.origin) != string(result.Origin) {
				t.Fatalf("wrong accepted immutable origin: %+v", actual)
			}
		case <-time.After(time.Second):
			t.Fatal("authorized activation did not continue")
		}
		if err := o.relay.completeActivation(lease+1, result); err == nil {
			t.Fatal("authority reply consumed twice")
		}
	}
}

func resultRunner(raw json.RawMessage) string {
	var origin struct {
		RunnerID string `json:"runnerId"`
	}
	_ = json.Unmarshal(raw, &origin)
	return origin.RunnerID
}

func TestSameControllerFreshTransportReissuesUnlaunchedGate(t *testing.T) {
	scope := testScope()
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, TenantID: scope.TenantID, NetworkID: "network", Kind: "worker"}
	broker := newRelayBroker(scope, spec)
	broker.bindLease(1)
	original := Admission{NativeAdmissionID: "original-server-admission", Scope: scope, TenantID: scope.TenantID, NetworkID: "network", Kind: "worker", RunnerID: "runner", RunnerEpoch: time.Now().UTC(), BootID: "boot"}
	if err := broker.admit(1, original); err != nil {
		t.Fatal(err)
	}
	broker.activation = &activationTicket{request: ActivationRequest{ID: "exact-request", Scope: scope, SourceCommandID: "original-command", NativeGeneration: "original-generation", ActualRuntime: spec.Runtime}, done: make(chan activationReply, 1)}
	first, err := broker.pollActivation(1)
	if err != nil || first == nil {
		t.Fatal("first authority gate unavailable")
	}
	replacement := original
	replacement.NativeAdmissionID = "replacement-server-admission"
	replacement.RunnerEpoch = original.RunnerEpoch.Add(time.Second)
	if err := broker.admit(1, replacement); err != nil {
		t.Fatal(err)
	}
	again, err := broker.pollActivation(1)
	if err != nil || again == nil || again.ID != first.ID || again.NativeGeneration != first.NativeGeneration || again.Admission != original || again.CurrentAdmission != replacement {
		t.Fatalf("fresh transport lost or rewrote original attempt: %+v %v", again, err)
	}
}
