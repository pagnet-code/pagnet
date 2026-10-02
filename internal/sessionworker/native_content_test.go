package sessionworker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
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

func TestLargeOriginalInspectionKeepsExactSecretProofAndCiphertext(t *testing.T) {
	scope := testScope()
	scope.InstanceID = uuid.NewString()
	scope.TenantID = uuid.NewString()
	journalDir := filepath.Join(t.TempDir(), "worker")
	j, err := OpenJournal(journalDir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	protected := e2ee.ProtectedContext{Kind: e2ee.OwnerContextKind, ID: uuid.NewString(), TenantID: scope.TenantID, OwnerUserID: uuid.NewString(), HostID: uuid.NewString()}
	epoch := crypto.KeyEpoch{ID: uuid.NewString(), State: crypto.EpochActive, Key: bytes.Repeat([]byte{7}, 32), CreatedAt: time.Now().UTC()}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	if err = crypto.SaveContextKeyring(dir, &crypto.ContextKeyring{Context: protected, Epochs: []crypto.KeyEpoch{epoch}}); err != nil {
		t.Fatal(err)
	}
	origin := json.RawMessage(`{"id":"` + uuid.NewString() + `"}`)
	owner := &SessionOwner{ctx: context.Background(), journal: j, spec: NativeSpec{ProtectedContext: &protected, ContextStateDir: dir, TenantID: scope.TenantID}, driver: agentruntime.NewPersistentFake("unused"), generation: "native-generation", origin: origin, pending: map[string]*nativeApproval{}}
	original := json.RawMessage(`{"request":"` + string(bytes.Repeat([]byte("<&>"), 350000)) + `"}`)
	event := session.SessionEvent{Type: session.EventInteractionStarted, SessionID: "native-session", Interaction: &session.InteractionEvent{NativeInteractionID: "choice", Kind: "permission", Summary: "Original request", NativePayload: original, Options: []domain.RuntimeInteractionOption{{ID: "proceed", Kind: "allow_once"}}}}
	obs := NativeObservation{ID: uuid.NewString(), NativeGeneration: owner.generation, NativeSessionID: event.SessionID, Origin: origin, ObservedAt: time.Now().UTC(), Event: event}
	owner.prepareInspection(event, owner.generation, obs)
	record := owner.pending["choice"]
	if record == nil || record.inspection == nil || record.transfer == nil {
		t.Fatal("valid large inspection lost its original proof")
	}
	transfer := *record.transfer
	key, _ := epoch.KeyArray()
	plain, _, err := nativecontent.Open(transfer.Reference, transfer.Fragments, key)
	if err != nil {
		t.Fatal(err)
	}
	var detail transport.OwnerInteractionDetail
	if err = json.Unmarshal(plain, &detail); err != nil {
		t.Fatal(err)
	}
	secret, err := base64.StdEncoding.DecodeString(detail.Inspection.Secret)
	if err != nil || !bytes.Equal(secret, record.secret) {
		t.Fatal("large manifest replaced original inspection secret")
	}
	raw, _ := canonicalNativeJSON(detail.NativePayload)
	if !bytes.Equal(raw, original) {
		t.Fatal("large inspection truncated vendor request")
	}
	proof, err := e2ee.ApprovalProof(secret, record.inspection.DetailAAD, scope.InstanceID, event.SessionID, "choice", "proceed")
	if err != nil || len(proof) != 32 {
		t.Fatal("whole manifest cannot produce original native approval proof", err)
	}
	owner.prepareInspection(event, owner.generation, obs)
	if owner.pending["choice"] != record || owner.pending["choice"].transfer.Reference.CiphertextDigest != transfer.Reference.CiphertextDigest {
		t.Fatal("retry regenerated ciphertext or inspection secret")
	}
	obs.Inspection = record.inspection
	obs.InteractionID = record.inspection.InteractionID
	obs.Event.Interaction = nil
	obs.SourceDigest, err = observationDigest(obs)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.JournalCapturedObservation(context.Background(), obs, nil, transfer); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(journalDir, scope)
	if err != nil {
		t.Fatal("complete original transfer did not survive reopen", err)
	}
	defer j.Close()
	a := lease(t, j)
	first, err := j.ReadContentFragment(context.Background(), a, obs.ID, obs.SourceDigest, transfer.Reference.ContentID, 0)
	if err != nil || first.Envelope.Ciphertext != transfer.Fragments[0].Envelope.Ciphertext {
		t.Fatal("stored transfer changed ciphertext", err)
	}
	b := lease(t, j)
	if _, err = j.ReadContentFragment(context.Background(), a, obs.ID, obs.SourceDigest, transfer.Reference.ContentID, 0); err != ErrFenced {
		t.Fatal("old controller drained private content", err)
	}
	if err = j.AcknowledgeObservation(context.Background(), b, obs.ID, obs.SourceDigest); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_content_fragments`).Scan(&count); err != nil || count != 0 {
		t.Fatal("acknowledged source ciphertext was not reclaimed")
	}
}
