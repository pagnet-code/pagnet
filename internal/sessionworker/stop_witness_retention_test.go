//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func TestStopWitnessLatestActivationSurvivesRestartsAndDelayedACK(t *testing.T) {
	j, dir := testJournal(t)
	l := lease(t, j)
	owned := dispatchOwnership(t, j, l)
	var delayed NativeObservation
	var delayedReceipt transport.NativeObservationReceiptPayload
	var latestProof transport.NativeDispatchProof
	for n := int64(1); n <= 8; n++ {
		proof := dispatchProof(owned, n)
		admission := &Admission{Scope: j.scope, NativeAdmissionID: proof.SourceAdmissionID, RunnerID: proof.SourceRunnerID, RunnerEpoch: proof.SourceRunnerEpoch, BootID: proof.SourceBootID}
		out, run, err := j.admitDispatch(t.Context(), l, 0, proof.SourceCommandID, "activate", json.RawMessage(`{}`), func() (*Admission, error) { return admission, nil }, &proof)
		if err != nil || !run {
			t.Fatal(out, run, err)
		}
		generation := fmt.Sprintf("activation-%d", n)
		origin := transport.NativeObservationOrigin{ID: domain.NewID().String(), TenantID: j.scope.TenantID, HostID: j.scope.HostID, InstanceID: j.scope.InstanceID, Runtime: owned.Runtime, NativeGeneration: generation, CommandID: proof.SourceCommandID, NativeAdmissionID: proof.SourceAdmissionID, RunnerID: proof.SourceRunnerID, RunnerEpoch: proof.SourceRunnerEpoch, BootID: proof.SourceBootID, CreatedAt: time.Now().UTC()}
		raw, _ := json.Marshal(origin)
		if n == 1 {
			bad := origin
			bad.BootID = "foreign"
			invalid, _ := json.Marshal(bad)
			if _, err = j.registerNativeSourceActivation(t.Context(), generation, invalid, true); err == nil {
				t.Fatal("foreign boot bound activation")
			}
		}
		p, err := j.registerNativeSourceActivation(t.Context(), generation, raw, true)
		if err != nil {
			t.Fatal(err)
		}
		o := NativeObservation{ID: domain.NewID().String(), NativeGeneration: generation, NativeSessionID: "session-" + generation, Origin: raw, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventSessionStopped, SessionID: "session-" + generation}}
		o.SourceDigest, _ = observationDigest(o)
		if err = j.journalCapturedObservation(t.Context(), p, o, nil); err != nil {
			t.Fatal(err)
		}
		pending, err := j.PendingObservations(t.Context(), 32)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range pending {
			if candidate.ID == o.ID {
				o = candidate
			}
		}
		wire, err := NativeBackendObservation(o)
		if err != nil {
			t.Fatal(err)
		}
		receipt := transport.NativeObservationReceiptPayload{ObservationID: o.ID, OriginID: wire.OriginID, Digest: wire.Digest, Disposition: "committed"}
		if n == 8 {
			// A retry of the same dispatch can authenticate another generation. Both
			// generations remain protected until a strictly newer activation is bound.
			var tie transport.NativeObservationOrigin
			if err := json.Unmarshal(raw, &tie); err != nil {
				t.Fatal(err)
			}
			tie.ID = domain.NewID().String()
			tie.NativeGeneration = "activation-tie"
			raw, _ := json.Marshal(tie)
			tieProducer, err := j.registerNativeSourceActivation(t.Context(), tie.NativeGeneration, raw, true)
			if err != nil {
				t.Fatal(err)
			}
			if err = j.retireNativeSource(t.Context(), tieProducer); err != nil {
				t.Fatal(err)
			}
		}
		if err = j.Settle(t.Context(), out.Sequence, "completed", nil); err != nil {
			t.Fatal(err)
		}
		if err = j.Acknowledge(t.Context(), l, out.Sequence); err != nil {
			t.Fatal(err)
		}
		if err = j.retireNativeSource(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			delayed, delayedReceipt = o, receipt
		} else if err = j.acknowledgeObservation(t.Context(), l, o.ID, o.SourceDigest, &receipt, nil); err != nil {
			t.Fatal(err)
		}
		expected := 2
		if n == 8 {
			expected = 3
		}
		if n > 1 && sourceCount(t, j, "worker_source_registration") != expected {
			t.Fatal("settled activations accumulated")
		}
		latestProof = proof
		if err = j.Close(); err != nil {
			t.Fatal(err)
		}
		j, err = OpenJournal(dir, testScope())
		if err != nil {
			t.Fatal(err)
		}
		l = lease(t, j)
	}
	defer j.Close()
	if err := j.acknowledgeObservation(t.Context(), l, delayed.ID, delayed.SourceDigest, &delayedReceipt, nil); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, j, "worker_source_registration") != 2 || sourceCount(t, j, "worker_stopped_receipts") != 1 {
		t.Fatal("delayed old ACK displaced latest stop witness")
	}
	var retained []byte
	if err := j.db.QueryRow(`SELECT activation_proof FROM worker_source_registration LIMIT 1`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	var proof transport.NativeDispatchProof
	if json.Unmarshal(retained, &proof) != nil || !transport.SameNativeDispatchProof(proof, latestProof) {
		t.Fatal("latest dispatch binding changed")
	}

}

type activationProofCheckingDriver struct {
	session.Driver
	check func() error
}

func (d *activationProofCheckingDriver) Live(string) bool { return false }
func (d *activationProofCheckingDriver) Activate(context.Context, *session.RuntimeSession, chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
	return nil, d.check()
}

func TestOwnedActivationBindsDispatchBeforeDriverExecution(t *testing.T) {
	j, _ := testJournal(t)
	defer j.Close()
	l := lease(t, j)
	owned := dispatchOwnership(t, j, l)
	proof := dispatchProof(owned, 1)
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: t.TempDir(), TenantID: j.scope.TenantID, NetworkTenantID: j.scope.TenantID, NetworkID: domain.NewID().String(), Kind: "worker"}
	admission := &Admission{Scope: j.scope, TenantID: spec.TenantID, NetworkID: spec.NetworkID, Kind: spec.Kind, NativeAdmissionID: proof.SourceAdmissionID, RunnerID: proof.SourceRunnerID, RunnerEpoch: proof.SourceRunnerEpoch, BootID: proof.SourceBootID}
	out, _, err := j.admitDispatch(t.Context(), l, 0, proof.SourceCommandID, "activate", json.RawMessage(`{}`), func() (*Admission, error) { return admission, nil }, &proof)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewSessionOwner(t.Context(), j, spec, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	owner.candidateCommandID = proof.SourceCommandID
	owner.candidateAdmission = admission
	owner.candidateTurnSource.Sequence = out.Sequence
	owner.relay.bindLease(l)
	if err = owner.relay.admit(l, *admission); err != nil {
		t.Fatal(err)
	}
	checked := false
	sentinel := errors.New("driver did not execute")
	driver := &ownedDriver{owner: owner, Driver: &activationProofCheckingDriver{check: func() error {
		var raw []byte
		if err := j.db.QueryRow(`SELECT activation_proof FROM worker_source_registration WHERE quiesced=0`).Scan(&raw); err != nil {
			return err
		}
		var bound transport.NativeDispatchProof
		if json.Unmarshal(raw, &bound) != nil || !transport.SameNativeDispatchProof(bound, proof) {
			return ErrConflict
		}
		checked = true
		return sentinel
	}}}
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go func() { _, err := driver.Activate(ctx, owner.sess, make(chan session.SessionEvent, 8)); done <- err }()
	var request *ActivationRequest
	for request == nil && ctx.Err() == nil {
		request, err = owner.relay.pollActivation(l)
		if err != nil {
			t.Fatal(err)
		}
		if request == nil {
			time.Sleep(time.Millisecond)
		}
	}
	if request == nil {
		t.Fatal("activation request missing")
	}
	origin := transport.NativeObservationOrigin{ID: domain.NewID().String(), TenantID: j.scope.TenantID, HostID: j.scope.HostID, InstanceID: j.scope.InstanceID, Runtime: owned.Runtime, NativeGeneration: request.NativeGeneration, CommandID: proof.SourceCommandID, NativeAdmissionID: proof.SourceAdmissionID, RunnerID: proof.SourceRunnerID, RunnerEpoch: proof.SourceRunnerEpoch, BootID: proof.SourceBootID, CreatedAt: time.Now().UTC()}
	raw, _ := json.Marshal(origin)
	if err = owner.relay.completeActivation(l, ActivationOrigin{ID: request.ID, NativeGeneration: request.NativeGeneration, Origin: raw}); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, sentinel) || !checked {
		t.Fatal("driver ran before original activation proof was durable", err)
	}
	// A failed activation before observer attachment has no genuine stop. Keep
	// its original activation proof; a proven unstarted outcome is a separate
	// contract and cannot be inferred from the driver's error.
	var quiesced bool
	var retained []byte
	if err = j.db.QueryRow(`SELECT quiesced,activation_proof FROM worker_source_registration`).Scan(&quiesced, &retained); err != nil {
		t.Fatal(err)
	}
	var bound transport.NativeDispatchProof
	if !quiesced || json.Unmarshal(retained, &bound) != nil || !transport.SameNativeDispatchProof(bound, proof) {
		t.Fatal("failed pre-observer activation lost proof")
	}
	if err = j.Settle(t.Context(), out.Sequence, "failed", nil); err != nil {
		t.Fatal(err)
	}
	if err = j.Acknowledge(t.Context(), l, out.Sequence); err != nil {
		t.Fatal(err)
	}
	if err = j.RetireDispatches(t.Context(), l, 1); err != nil {
		t.Fatal(err)
	}
	owned.State, owned.LastDispatchSequence, owned.RetiredFloor = "retired", 1, 1
	if err = j.CommitOwnershipRetirement(t.Context(), l, owned); !errors.Is(err, ErrConflict) {
		t.Fatal("failed activation retired without stopped proof", err)
	}
	if sourceCount(t, j, "worker_source_registration") != 1 {
		t.Fatal("rejected retirement lost failed activation evidence")
	}
}
