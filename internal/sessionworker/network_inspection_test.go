package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNetworkNativeInspectionAndAnswerKeepOriginalScopeEpochAndProof(t *testing.T) {
	scope := testScope()
	scope.InstanceID = uuid.NewString()
	j, err := OpenJournal(filepath.Join(t.TempDir(), "worker"), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	state := t.TempDir()
	network := uuid.NewString()
	ring := crypto.NewKeyring(network)
	epoch, err := ring.Activate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = crypto.SaveKeyring(state, ring); err != nil {
		t.Fatal(err)
	}
	origin := json.RawMessage(`{"id":"` + uuid.NewString() + `"}`)
	owner := &SessionOwner{ctx: context.Background(), journal: j, spec: NativeSpec{NetworkStateDir: state, NetworkID: network, NetworkTenantID: j.scope.TenantID}, driver: agentruntime.NewPersistentFake("unused"), generation: "original-A", origin: origin, pending: map[string]*nativeApproval{}}
	event := session.SessionEvent{Type: session.EventInteractionStarted, SessionID: "original-session", Interaction: &session.InteractionEvent{NativeInteractionID: "choice", Kind: "permission", Summary: "private permission summary", NativePayload: json.RawMessage(`{"private":"actual native request"}`), Options: []domain.RuntimeInteractionOption{{ID: "allow", Kind: "allow_once"}}}}
	obs := NativeObservation{ID: uuid.NewString(), NativeGeneration: owner.generation, NativeSessionID: event.SessionID, Origin: origin, ObservedAt: time.Now().UTC(), Event: event}
	owner.prepareInspection(event, owner.generation, obs)
	record := owner.pending["choice"]
	if record == nil || record.inspection == nil {
		t.Fatal("network permission lost original inspection")
	}
	aad := record.inspection.DetailAAD
	if aad.ProtectedContext != nil || aad.NetworkID != network || aad.TenantID != j.scope.TenantID || aad.KeyEpochID != epoch.ID {
		t.Fatal("network inspection invented owner context/epoch")
	}
	key, _ := epoch.KeyArray()
	plain, err := e2ee.Decrypt(record.inspection.DetailEnvelope, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	var detail transport.OwnerInteractionDetail
	if json.Unmarshal(plain, &detail) != nil || detail.Summary != event.Interaction.Summary || !bytes.Contains(plain, []byte("actual native request")) {
		t.Fatal("network original inspection changed private detail")
	}
	proof, err := e2ee.ApprovalProof(record.secret, aad, j.scope.InstanceID, event.SessionID, "choice", "allow")
	if err != nil || len(proof) != 32 {
		t.Fatal(err)
	}
	if _, err = ring.Rotate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err = crypto.SaveKeyring(state, ring); err != nil {
		t.Fatal(err)
	}
	owner.prepareInspection(event, owner.generation, obs)
	if owner.pending["choice"] != record {
		t.Fatal("rotation rewrote inspected native capability")
	}
	resolved := session.SessionEvent{Type: session.EventInteractionResolved, SessionID: event.SessionID, Interaction: &session.InteractionEvent{NativeInteractionID: "choice", Resolved: true, Answer: string(bytes.Repeat([]byte("original private answer"), 5000))}}
	obs.Event = resolved
	answer, transfer := owner.encryptOriginalResolution(resolved, record.inspection, obs)
	if answer == nil || transfer == nil || answer.DetailAAD.KeyEpochID != epoch.ID {
		t.Fatal("large network answer followed fresh epoch")
	}
	opened, _, err := nativecontent.Open(transfer.Reference, transfer.Fragments, key)
	if err != nil || string(opened) != resolved.Interaction.Answer {
		t.Fatal("original network answer changed", err)
	}
	foreign := aad
	foreign.NetworkID = uuid.NewString()
	if err = owner.withInspectionEpoch(context.Background(), foreign, func(crypto.KeyEpoch) error { t.Fatal("foreign native scope reached effect"); return nil }); err == nil {
		t.Fatal("foreign network admitted")
	}
	if err = ring.Revoke(epoch.ID); err != nil {
		t.Fatal(err)
	}
	if err = crypto.SaveKeyring(state, ring); err != nil {
		t.Fatal(err)
	}
	if owner.encryptResolution(session.SessionEvent{Interaction: &session.InteractionEvent{Resolved: true, Answer: "answer"}}, record.inspection, time.Now()) != nil {
		t.Fatal("revoked original inspection encrypted answer")
	}
	if err = owner.withInspectionEpoch(context.Background(), aad, func(crypto.KeyEpoch) error { t.Fatal("revoked native scope reached effect"); return nil }); err == nil {
		t.Fatal("revoked network admitted")
	}
}
