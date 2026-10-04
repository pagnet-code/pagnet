//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/session"
)

func TestLocalDurableIntentOriginalACKAcrossTakeoverAndRestart(t *testing.T) {
	f := newLocalAuthorityFixture(t)
	ctx := context.Background()
	binder := nativeauthority.JSONPromptBinder{ProfileDigest: f.binding.Worker.ProfileDigest}
	controller, e := nativeauthority.NewLocalController(f.authority, f.owner, f.binding, binder)
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().UTC().Add(time.Hour)
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "original-invoke", Operation: fabric.OperationInvoke, Principal: f.owner.PrincipalView(), Source: f.owner.PrincipalView().Ref, Target: &f.binding.Scope.Endpoint, ExpectedRevision: f.binding.Scope.DescriptorRevision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"original"}`), Context: fabric.EnvelopeContext{Origin: f.owner.PrincipalView().Ref, Deadline: &deadline}}
	original, _ := json.Marshal(env)
	caller, e := fabric.NewAuthenticatedContext(f.owner.PrincipalView(), f.authority.Identity().Namespace, original)
	if e != nil {
		t.Fatal(e)
	}
	env.Payload = json.RawMessage(`{"input":"finalized native input"}`)
	final, _ := json.Marshal(env)
	source, e := f.authority.Admit(ctx, f.owner, f.controller, f.binding, caller, original, final, "original-source-A", "attempt", "replay")
	if e != nil {
		t.Fatal(e)
	}
	origin, e := f.authority.RegisterOrigin(ctx, f.owner, f.controller, f.binding, source, caller, original, final, "original-origin", "unit-test-native-generation")
	if e != nil {
		t.Fatal(e)
	}
	if e = nativeauthority.ValidateOriginalOrigin(f.scope, source, origin, "unit-test-native-generation"); e != nil {
		t.Fatal(e)
	}
	wrongOrigin := origin
	wrongOrigin.NativeGeneration = "different-generation"
	if nativeauthority.ValidateOriginalOrigin(f.scope, source, wrongOrigin, "different-generation") == nil {
		t.Fatal("unsigned native origin change accepted")
	}
	dir := filepath.Join(t.TempDir(), "worker")
	j, e := OpenAuthorityJournal(dir, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { j.Close() }()
	originBytes, _ := json.Marshal(origin)
	observation := NativeObservation{ID: "private-source", NativeGeneration: origin.NativeGeneration, NativeSessionID: "unit-native-session", Origin: originBytes, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventTurnCompleted, SessionID: "unit-native-session"}}
	private := NativeSourceCapture{Format: NativeSourceCaptureFormat, Event: session.SessionEvent{Type: session.EventInteractionResolved, SessionID: "unit-native-session", Interaction: &session.InteractionEvent{Answer: "private original answer"}}}
	key := bytes.Repeat([]byte{7}, 32)
	ref, ciphertext, e := j.sealNativeCapture(key, observation, private)
	if e != nil {
		t.Fatal(e)
	}
	observation.Capture = ref
	opened, e := OpenAuthorityNativeCapture(key, f.scope, dir, observation, ciphertext)
	if e != nil {
		t.Fatal(e)
	}
	var decoded NativeSourceCapture
	if e = json.Unmarshal(opened, &decoded); e != nil || decoded.Event.Interaction.Answer != private.Event.Interaction.Answer {
		t.Fatal("local source altered", e)
	}
	clear(opened)
	if bytes.Contains(ciphertext, []byte(private.Event.Interaction.Answer)) {
		t.Fatal("private answer persisted plaintext")
	}
	if _, e = OpenNativeCapture(key, Scope{}, dir, observation, ciphertext); e == nil {
		t.Fatal("local capture accepted zero Cloud authority")
	}
	if _, e = OpenAuthorityNativeCapture(key, f.scope, filepath.Join(dir, "different-state"), observation, ciphertext); e == nil {
		t.Fatal("local capture allowed state-directory transplant")
	}
	changed := observation
	changed.NativeGeneration = "wrong-generation"
	if _, e = OpenAuthorityNativeCapture(key, f.scope, dir, changed, ciphertext); e == nil {
		t.Fatal("local capture allowed generation transplant")
	}
	lease, e := j.AdvanceLease(ctx)
	if e != nil {
		t.Fatal(e)
	}
	freshCount := 0
	var accepted nativeauthority.VerifiedIntent
	appendIntent := func(ctx context.Context, i nativeauthority.VerifiedIntent) (fabricidentity.NativeIntentReceipt, error) {
		accepted = i
		_, r, fresh, e := j.AdmitLocal(ctx, lease, binder, i)
		if fresh {
			freshCount++
		}
		return r, e
	}
	ackA, e := controller.AdmitIntent(ctx, f.controller, source, caller, original, final, appendIntent)
	if e != nil || freshCount != 1 || ackA.ControllerEpoch != f.controller.Epoch() {
		t.Fatal("genuine local admission", e)
	}
	retainedSource, e := j.localIntentSource(ctx, j.db, accepted.Commitment.Sequence)
	if e != nil {
		t.Fatal(e)
	}
	request := LocalActivationRequest{Authority: f.scope, OriginalSource: *retainedSource, NativeGeneration: origin.NativeGeneration}
	if e = j.retainLocalActivation(ctx, key, request, origin); e != nil {
		t.Fatal("activation proof before paid launch", e)
	}
	tx, e := j.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	activation, e := j.localActivationEvidenceTx(ctx, tx, key, origin.NativeGeneration)
	tx.Rollback()
	if e != nil || !sameLocalJSON(activation.Origin, origin) || !sameLocalJSON(activation.Admission, source) {
		t.Fatal("signed activation evidence changed", e)
	}
	if e = j.retainLocalActivation(ctx, key, request, origin); e != nil {
		t.Fatal("exact origin retry", e)
	}
	// Wire mutations cannot redirect or alter the operation behind signed source.
	bad := accepted
	bad.Operation.Payload = json.RawMessage(`{"input":"tampered","inputKind":"local-native"}`)
	if _, _, _, e = j.AdmitLocal(ctx, lease, binder, bad); !errors.Is(e, ErrFenced) {
		t.Fatal("unsigned executable bytes admitted", e)
	}
	B, e := f.authority.AcquireController(ctx, f.owner, f.binding.Scope, f.controller.Epoch(), "B", "controller-B")
	if e != nil {
		t.Fatal(e)
	}
	lease, e = j.AdvanceLease(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ackB, e := controller.AdmitIntent(ctx, B, source, caller, original, final, appendIntent)
	if e != nil || ackB != ackA || freshCount != 1 {
		t.Fatal("historical ACK rewritten or native replay requested", e)
	}
	if _, _, _, e = j.AdmitLocal(ctx, lease, binder, accepted); e != nil {
		t.Fatal(e)
	}
	stale := accepted
	stale.CurrentController = f.controller
	if _, _, _, e = j.AdmitLocal(ctx, lease, binder, stale); !errors.Is(e, ErrFenced) {
		t.Fatal("journal accepted stale controller after B", e)
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	j, e = OpenAuthorityJournal(dir, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	lease, e = j.AdvanceLease(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ack, e := controller.AdmitIntent(ctx, B, source, caller, original, final, appendIntent)
	if e != nil || ack != ackA || freshCount != 1 {
		t.Fatal("restart replayed ambiguous native effect", e)
	}
	out, e := j.Outcome(ctx, 1)
	if e != nil || out.State != "uncertain" || out.LocalSource.Admission.ID != source.ID || out.LocalSource.Receipt != ackA || out.SourceAdmission != nil {
		t.Fatal("restart forged completion or cloud source", e)
	}
	if e = j.Settle(ctx, 1, "completed", json.RawMessage(`{}`)); !errors.Is(e, ErrConflict) {
		t.Fatal("ambiguous restart fabricated completion", e)
	}
	if e = j.Acknowledge(ctx, lease, 1); e != nil {
		t.Fatal(e)
	}
	var left int
	if e = j.db.QueryRow(`SELECT COUNT(*) FROM worker_local_intent`).Scan(&left); e != nil || left != 0 {
		t.Fatal("retired source not reclaimed", e)
	}
	if _, _, _, e = j.AdmitLocal(ctx, lease, binder, accepted); !errors.Is(e, ErrRetired) {
		t.Fatal("retired source resurrected", e)
	}
	// A partial restored source table must not silently become a new history.
	orphan, _ := json.Marshal(out.LocalSource)
	if _, e = j.db.Exec(`INSERT INTO worker_local_intent(sequence,admission_id,source) VALUES(?,?,?)`, 1, out.LocalSource.Admission.ID, orphan); e != nil {
		t.Fatal(e)
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	if reopened, e := OpenAuthorityJournal(dir, f.scope); e == nil {
		reopened.Close()
		t.Fatal("partial source history silently repaired")
	}
}

func TestLocalPrivateIntentMaximumEscapedEnvelopeFitsActualFrame(t *testing.T) {
	f := newLocalAuthorityFixture(t)
	ctx := context.Background()
	binder := nativeauthority.JSONPromptBinder{ProfileDigest: f.binding.Worker.ProfileDigest}
	controller, e := nativeauthority.NewLocalController(f.authority, f.owner, f.binding, binder)
	if e != nil {
		t.Fatal(e)
	}
	input := strings.Repeat("\x01", 128<<10)
	payload, _ := json.Marshal(struct {
		Input string `json:"input"`
	}{input})
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "maximum-escaped-input", Operation: fabric.OperationInvoke, Principal: f.owner.PrincipalView(), Source: f.owner.PrincipalView().Ref, Target: &f.binding.Scope.Endpoint, ExpectedRevision: f.binding.Scope.DescriptorRevision, CreatedAt: time.Now().UTC(), Payload: payload, Context: fabric.EnvelopeContext{Origin: f.owner.PrincipalView().Ref}}
	original, _ := json.Marshal(env)
	caller, e := fabric.NewAuthenticatedContext(f.owner.PrincipalView(), f.authority.Identity().Namespace, original)
	if e != nil {
		t.Fatal(e)
	}
	source, e := f.authority.Admit(ctx, f.owner, f.controller, f.binding, caller, original, original, "maximum-source", "attempt", "replay")
	if e != nil {
		t.Fatal(e)
	}
	j, e := OpenAuthorityJournal(filepath.Join(t.TempDir(), "worker"), f.scope)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	lease, e := j.AdvanceLease(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = controller.AdmitIntent(ctx, f.controller, source, caller, original, original, func(ctx context.Context, i nativeauthority.VerifiedIntent) (fabricidentity.NativeIntentReceipt, error) {
		r := i.Request()
		var encoded bytes.Buffer
		if e := writeFrame(&encoded, LocalRequest{Type: "intent", Intent: &r}); e != nil {
			t.Fatal("authentic maximum escaped envelope exceeds private wire", e)
		}
		var read LocalRequest
		if e := readFrame(&encoded, &read); e != nil {
			t.Fatal(e)
		}
		verified, e := read.Intent.Verify(j.authority, binder)
		if e != nil || !bytes.Equal(verified.Operation.Payload, i.Operation.Payload) {
			t.Fatal("private frame re-derived different executable input", e)
		}
		_, receipt, fresh, e := j.AdmitLocal(ctx, lease, binder, verified)
		if e != nil || !fresh {
			t.Fatal("maximum prompt not durably admitted", e)
		}
		return receipt, e
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestLocalSignedSparseReservationGapCannotResurrect(t *testing.T) {
	f := newLocalAuthorityFixture(t)
	ctx := context.Background()
	binder := nativeauthority.JSONPromptBinder{ProfileDigest: f.binding.Worker.ProfileDigest}
	controller, e := nativeauthority.NewLocalController(f.authority, f.owner, f.binding, binder)
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(t.TempDir(), "worker")
	j, e := OpenAuthorityJournal(dir, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { j.Close() }()
	lease, e := j.AdvanceLease(ctx)
	if e != nil {
		t.Fatal(e)
	}
	reserve := func(id string) nativeauthority.VerifiedIntent {
		t.Helper()
		deadline := time.Now().UTC().Add(time.Hour)
		env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: id, Operation: fabric.OperationInvoke, Principal: f.owner.PrincipalView(), Source: f.owner.PrincipalView().Ref, Target: &f.binding.Scope.Endpoint, ExpectedRevision: f.binding.Scope.DescriptorRevision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"exact native input"}`), Context: fabric.EnvelopeContext{Origin: f.owner.PrincipalView().Ref, Deadline: &deadline}}
		raw, _ := json.Marshal(env)
		caller, e := fabric.NewAuthenticatedContext(f.owner.PrincipalView(), f.authority.Identity().Namespace, raw)
		if e != nil {
			t.Fatal(e)
		}
		source, e := f.authority.Admit(ctx, f.owner, f.controller, f.binding, caller, raw, raw, id+"-source", "attempt", "replay")
		if e != nil {
			t.Fatal(e)
		}
		var captured nativeauthority.VerifiedIntent
		_, e = controller.AdmitIntent(ctx, f.controller, source, caller, raw, raw, func(_ context.Context, i nativeauthority.VerifiedIntent) (fabricidentity.NativeIntentReceipt, error) {
			captured = i
			return fabricidentity.NativeIntentReceipt{}, context.Canceled
		})
		if e == nil || captured.Commitment.CommandID == "" {
			t.Fatal("reservation without native ACK", e)
		}
		return captured
	}
	abandoned := reserve("abandoned")
	accepted := reserve("accepted")
	if abandoned.Commitment.Sequence != 1 || accepted.Commitment.Sequence != 2 {
		t.Fatal("reservation ordinals")
	}
	forged := accepted
	forged.Commitment.Sequence = 3
	if _, _, _, e = j.AdmitLocal(ctx, lease, binder, forged); !errors.Is(e, ErrFenced) {
		t.Fatal("unsigned sparse advance", e)
	}
	out, ack, fresh, e := j.AdmitLocal(ctx, lease, binder, accepted)
	if e != nil || !fresh || out.Sequence != 2 {
		t.Fatal("genuine gap acceptance", e)
	}
	if _, _, _, e = j.AdmitLocal(ctx, lease, binder, abandoned); !errors.Is(e, ErrRetired) {
		t.Fatal("older unaccepted reservation resurrected", e)
	}
	_, retry, newEffect, e := j.AdmitLocal(ctx, lease, binder, accepted)
	if e != nil || newEffect || retry != ack {
		t.Fatal("exact ambiguous ACK readback", e)
	}
	if e = j.requestLocalCancellation(ctx, lease, binder, accepted); e != nil {
		t.Fatal("durable exact source cancellation", e)
	}
	if yes, e := j.localCancellationRequested(2); e != nil || !yes {
		t.Fatal("cancel marker missing", e)
	}
	if e = j.requestLocalCancellation(ctx, lease, binder, forged); !errors.Is(e, ErrFenced) {
		t.Fatal("forged cancellation accepted", e)
	}
	if e = j.Settle(ctx, 2, "completed", json.RawMessage(`{"fixture":true}`)); e != nil {
		t.Fatal(e)
	}
	if e = j.Acknowledge(ctx, lease, 2); e != nil {
		t.Fatal("sparse accepted-prefix retirement", e)
	}
	j.Close()
	j, e = OpenAuthorityJournal(dir, f.scope)
	if e != nil {
		t.Fatal("sparse restart", e)
	}
	lease, e = j.AdvanceLease(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = j.AdmitLocal(ctx, lease, binder, accepted); !errors.Is(e, ErrRetired) {
		t.Fatal("retired signed mapping resurrected", e)
	}
}
