package sessionworker

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

func accountPersistenceFixture(t *testing.T) (transport.NativeAccountMessageSource, e2ee.AAD) {
	t.Helper()
	source := accountMessageContractSource(t, "account_message_source_reply_html_v1.json")
	raw, err := os.ReadFile("../../transport/testdata/account_message_source_reply_html_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ ReplyAADCanonical string }
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var aad e2ee.AAD
	if err = json.Unmarshal([]byte(fixture.ReplyAADCanonical), &aad); err != nil {
		t.Fatal(err)
	}
	return source, aad
}

func TestAccountPersistenceEnclosingRecords(t *testing.T) {
	source, aad := accountPersistenceFixture(t)
	proof := transport.NativeDispatchProof{AccountMessageSource: &source}
	turn := NativeTurnSource{InputKind: "account_message", SourceAccountMessage: &source}
	op := Operation{SourceAccountMessage: &source, InputKind: "account_message", Input: "quoted \"雪 <>&"}
	payload, err := MarshalNativeJSON(op)
	if err != nil {
		t.Fatal(err)
	}
	observation := NativeObservation{TurnSource: &turn}
	stopped := stoppedReceipt{Observation: observation}
	cancellation := DispatchCancellationPreparation{Proposal: transport.NativeDispatchCancellationProposal{Proof: proof}}
	fragment := transport.NativeContentFragment{AAD: aad}
	ref := transport.NativeContentReference{ManifestAAD: aad}
	records := []any{
		op,
		turn,
		observation,
		NativeObservation{OutputContent: &ref},
		NativeObservation{PlanContent: &ref},
		NativeObservation{OriginalNativePayloadContent: &ref},
		NativeObservation{Resolution: &NativeResolution{DetailAAD: aad}},
		NativeObservation{Inspection: &Inspection{DetailAAD: aad}},
		resourceSettlement{Observation: observation, Proof: proof},
		stopped,
		ownerStopSettlement{Stopped: stopped, Turn: turn, Proof: proof},
		cancellation,
		Request{Type: "dispatch", Payload: payload, NativeDispatch: &proof},
		Request{Type: "intent", Payload: payload},
		Request{CancelProposal: &cancellation.Proposal},
		Request{CancelReceipt: &transport.NativeDispatchCancelledPayload{Proof: &proof}},
		Response{Dispatches: []NativeDispatchRecord{{Proof: proof}}},
		Response{Observations: []NativeObservation{observation}},
		Response{Cancellation: &cancellation},
		Response{ContentFragment: &fragment},
		Response{Snapshot: &NativeSnapshot{Pending: []Inspection{{DetailContent: &ref}}}},
	}
	records = append(records,
		BridgeCall{TurnSource: &turn},
		CloudInvocationSourceResult{Source: &turn},
		NativeSourceDisposition{Observation: observation},
		NativeSourceDispositionPage{Sources: []NativeSourceDisposition{{Observation: observation}}},
		InvocationStreamState{Terminal: &observation},
		InvocationStreamProjection{AAD: aad},
		InvocationStreamRange{Source: turn, Terminal: &observation},
		invocationStreamCheckpoint{Source: turn, Terminal: &observation},
		LocalResponse{Observations: []NativeObservation{observation}},
		Response{Bridge: &BridgeCall{TurnSource: &turn}},
		Response{SourceDispositions: &NativeSourceDispositionPage{Sources: []NativeSourceDisposition{{Observation: observation}}}},
	)
	for index, record := range records {
		t.Run(reflect.TypeOf(record).Name()+string(rune('A'+index)), func(t *testing.T) {
			raw, err := MarshalNativeJSON(record)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(raw, []byte("<>&")) || bytes.Contains(raw, []byte(`\u003c`)) {
				t.Fatal("canonical contract escaped")
			}
			target := reflect.New(reflect.TypeOf(record)).Interface()
			if err = json.Unmarshal(raw, target); err != nil {
				t.Fatal("cannot recover", err)
			}
			again, err := MarshalNativeJSON(target)
			if err != nil || !bytes.Equal(raw, again) {
				t.Fatal("recovery changed bytes", err)
			}
		})
	}
	var frame bytes.Buffer
	if err = writeFrame(&frame, Response{Observations: []NativeObservation{observation}, ContentFragment: &fragment}); err != nil {
		t.Fatal(err)
	}
	var recovered Response
	if err = readFrame(&frame, &recovered); err != nil {
		t.Fatal("IPC lost canonical account source", err)
	}
	// The canonical serializer grants no account execution authority.
	if _, err = prepareDispatchOperation(Request{Kind: "prompt", Payload: payload, NativeDispatch: &proof}); err == nil {
		t.Fatal("account execution enabled")
	}
}

func TestAccountPersistenceLegacyBytes(t *testing.T) {
	for _, source := range []NativeTurnSource{{}, {SourceTask: &transport.NativeTaskSource{TaskID: "<>&"}}, {SourceInvocation: &transport.NativeInvocationSource{InvocationID: "<>&"}}} {
		op := Operation{Input: "quoted \"雪 <>&", SourceTask: source.SourceTask, SourceInvocation: source.SourceInvocation}
		observation := NativeObservation{TurnSource: &source, Origin: json.RawMessage(`{"id":"<>&"}`)}
		payload, _ := json.Marshal(op)
		for _, record := range []any{source, op, observation, stoppedReceipt{Observation: observation}, resourceSettlement{Observation: observation}, ownerStopSettlement{Turn: source}, Request{Type: "dispatch", Payload: payload}, Response{Observations: []NativeObservation{observation}}} {
			expected, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := MarshalNativeJSON(record)
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatal("legacy bytes changed", reflect.TypeOf(record), err)
			}
		}
	}
}

func TestAccountPersistenceRejectsInvalidAndEscapedSource(t *testing.T) {
	source, _ := accountPersistenceFixture(t)
	// An outer encoder must not repair previously noncanonical wire bytes.
	escaped, _ := json.Marshal(Operation{SourceAccountMessage: &source})
	if _, err := MarshalNativeJSON(Request{Type: "dispatch", Payload: escaped}); err == nil {
		t.Fatal("escaped source repaired")
	}
	source.BindingDigest = "invalid"
	if _, err := observationDigest(NativeObservation{TurnSource: &NativeTurnSource{SourceAccountMessage: &source}}); err == nil {
		t.Fatal("invalid source digested")
	}
}

func TestAccountContentPersistenceReopen(t *testing.T) {
	_, aad := accountPersistenceFixture(t)
	transfer, err := nativecontent.Build([]byte("quoted \"雪 <>&"), [32]byte{1}, aad, *aad.NativeContent, "text/plain; charset=utf-8")
	if err != nil {
		t.Fatal(err)
	}
	ref := transfer.Reference
	observation := NativeObservation{ID: ref.ObservationID, NativeGeneration: ref.NativeGeneration, NativeSessionID: ref.NativeSessionID, Origin: json.RawMessage(`{"id":"` + ref.OriginID + `"}`), ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventIdle, SessionID: ref.NativeSessionID}, OutputContent: &ref}
	observation.SourceDigest, err = observationDigest(observation)
	if err != nil {
		t.Fatal(err)
	}
	j, dir := testJournal(t)
	if err = j.JournalObservation(t.Context(), observation); err != nil {
		t.Fatal(err)
	}
	// Reply execution remains inactive. Import retained encrypted fragments as
	// recovery fixtures without creating a native account admission or turn.
	for _, fragment := range transfer.Fragments {
		raw, err := MarshalNativeJSON(fragment)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = j.db.Exec(`INSERT INTO worker_content_fragments(observation_id,content_id,ordinal,payload,size) VALUES(?,?,?,?,?)`, observation.ID, fragment.ContentID, fragment.Ordinal, raw, len(raw)); err != nil {
			t.Fatal(err)
		}
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal("canonical account content cannot reopen", err)
	}
	defer j.Close()
	observations, err := j.PendingObservations(t.Context(), 32)
	if err != nil || len(observations) != 1 {
		t.Fatal(err, len(observations))
	}
	digest, err := observationDigest(observations[0])
	if err != nil || digest != observation.SourceDigest {
		t.Fatal("digest changed on reopen", err)
	}
	fragment, err := j.ReadContentFragment(t.Context(), lease(t, j), observation.ID, observation.SourceDigest, ref.ContentID, 0)
	if err != nil || !reflect.DeepEqual(*fragment, transfer.Fragments[0]) {
		t.Fatal("fragment changed on reopen", err)
	}
}

func TestAccountSourcePersistenceReopen(t *testing.T) {
	source, _ := accountPersistenceFixture(t)
	observation := NativeObservation{ID: "retained-account-observation", NativeGeneration: "generation", Origin: json.RawMessage(`{"id":"origin"}`), ObservedAt: time.Now().UTC(), TurnSource: &NativeTurnSource{InputKind: "account_message", SourceAccountMessage: &source}}
	var err error
	observation.SourceDigest, err = observationDigest(observation)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalNativeJSON(observation)
	if err != nil {
		t.Fatal(err)
	}
	j, dir := testJournal(t)
	// A retained recovery fixture must not bind or execute an account turn.
	if _, err = j.db.Exec(`INSERT INTO worker_observations(id,digest,payload,size) VALUES(?,?,?,?)`, observation.ID, observation.SourceDigest, raw, len(raw)); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	pending, err := j.PendingObservations(t.Context(), 1)
	if err != nil || len(pending) != 1 {
		t.Fatal("retained account source lost", err)
	}
	digest, err := observationDigest(pending[0])
	if err != nil || digest != observation.SourceDigest {
		t.Fatal("source digest changed on reopen", err)
	}
	if !bytes.Equal(pending[0].TurnSource.SourceAccountMessage.CanonicalJSON(), source.CanonicalJSON()) {
		t.Fatal("retained source bytes changed")
	}
}

func TestAccountDispatchProofPersistenceRemainsInert(t *testing.T) {
	j, _, _, proposal := cancellationFixture(t)
	defer j.Close()
	source, _ := accountPersistenceFixture(t)
	proof := proposal.Proof
	proof.AccountMessageSource = &source
	tx, err := j.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, _, err = j.prepareDispatchTx(t.Context(), tx, 1, 0, proof.SourceCommandID, proof); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err = tx.QueryRow(`SELECT proof FROM worker_dispatches WHERE dispatch_sequence=1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var recovered transport.NativeDispatchProof
	if err = json.Unmarshal(raw, &recovered); err != nil {
		t.Fatal("dispatch proof cannot recover", err)
	}
	if !transport.SameNativeDispatchProof(proof, recovered) {
		t.Fatal("dispatch proof source changed")
	}
	// Roll back the metadata fixture; no account operation is admitted.
}
