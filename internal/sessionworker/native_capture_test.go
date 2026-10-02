package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func TestPrivateOriginalResolutionCaptureSurvivesControllerAndReopen(t *testing.T) {
	j, dir := testJournal(t)
	ctx := context.Background()
	key := bytes.Repeat([]byte{42}, 32)
	manager := session.NewManager()
	manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	owner := &SessionOwner{ctx: ctx, journal: j, captureKey: key, manager: manager, generation: "native-generation", origin: json.RawMessage(`{"id":"server-origin"}`), pending: map[string]*nativeApproval{}}
	answer := string(bytes.Repeat([]byte("private-answer<&>"), 70000))
	original := session.SessionEvent{Type: session.EventInteractionResolved, SessionID: "native-session", TurnID: "original-turn", Interaction: &session.InteractionEvent{NativeInteractionID: "choice", Kind: "question", Answer: answer, Summary: "private question", NativePayload: json.RawMessage(`{"private":"native-source"}`), Resolved: true}}
	if err := owner.nativeEventObserver(j.scope.InstanceID)(original); err != nil {
		t.Fatal(err)
	}
	firstLease := lease(t, j)
	pending, err := j.PendingObservationsForLease(ctx, firstLease, 32)
	if err != nil || len(pending) != 1 {
		t.Fatalf("missing original source: %v", err)
	}
	observation := pending[0]
	if observation.Event.Interaction.Answer != "" || len(observation.Event.Interaction.NativePayload) > 0 && string(observation.Event.Interaction.NativePayload) != "null" || observation.Capture == nil {
		t.Fatalf("private content exposed in projection or capture missing: payloadLen=%d answerLen=%d capture=%v", len(observation.Event.Interaction.NativePayload), len(observation.Event.Interaction.Answer), observation.Capture)
	}
	var stored []byte
	if err = j.db.QueryRow(`SELECT payload FROM worker_observations`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("private-answer")) || bytes.Contains(stored, []byte("private question")) {
		t.Fatal("plaintext original retained in metadata journal")
	}
	scope := j.scope
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	secondLease := lease(t, j)
	if _, err = j.ReadCaptureChunk(ctx, firstLease, observation.ID, observation.SourceDigest, 0); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale lease read private content: %v", err)
	}
	var encrypted []byte
	for offset := 0; offset < observation.Capture.CiphertextBytes; offset += captureChunkBytes {
		chunk, err := j.ReadCaptureChunk(ctx, secondLease, observation.ID, observation.SourceDigest, offset)
		if err != nil {
			t.Fatal(err)
		}
		if len(chunk.Data) > captureChunkBytes {
			t.Fatal("unbounded private capture frame")
		}
		encrypted = append(encrypted, chunk.Data...)
	}
	plain, err := OpenNativeCapture(key, scope, dir, observation, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	var recovered session.SessionEvent
	if err = json.Unmarshal(plain, &recovered); err != nil {
		t.Fatal(err)
	}
	if recovered.Interaction.Answer != answer || recovered.Interaction.Summary != original.Interaction.Summary || !bytes.Equal(recovered.Interaction.NativePayload, original.Interaction.NativePayload) {
		t.Fatal("original resolved native content changed")
	}
	// Timestamp, state-directory and actual activation are all authenticated.
	for _, change := range []func(*NativeObservation){func(o *NativeObservation) { o.NativeGeneration = "replacement" }, func(o *NativeObservation) { o.ObservedAt = o.ObservedAt.Add(time.Second) }, func(o *NativeObservation) { o.Origin = json.RawMessage(`{"id":"other-origin"}`) }} {
		altered := observation
		change(&altered)
		if _, err = OpenNativeCapture(key, scope, dir, altered, encrypted); err == nil {
			t.Fatal("capture accepted different immutable source")
		}
	}
	if _, err = OpenNativeCapture(key, scope, dir+"-other", observation, encrypted); err == nil {
		t.Fatal("capture accepted another state directory")
	}
	if _, err = j.ReadCaptureChunk(ctx, secondLease, observation.ID, observation.SourceDigest, 1); err == nil {
		t.Fatal("unaligned capture cursor accepted")
	}
	if err = j.AcknowledgeObservation(ctx, secondLease, observation.ID, observation.SourceDigest); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_source_captures`).Scan(&count); err != nil || count != 0 {
		t.Fatal("acknowledged private pending capture retained")
	}
}

func TestPrivateCaptureAndMetadataCommitAtomically(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	key := bytes.Repeat([]byte{1}, 32)
	observation := NativeObservation{ID: "capture", NativeGeneration: "native", Origin: json.RawMessage(`{"id":"source"}`), ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventIdle}}
	ref, encrypted, err := sealNativeCapture(key, j.scope, j.dir, observation, observation.Event)
	if err != nil {
		t.Fatal(err)
	}
	observation.Capture = ref
	observation.SourceDigest, _ = observationDigest(observation)
	// Simulate failing ciphertext insertion after metadata INSERT.
	if _, err = j.db.Exec(`CREATE TRIGGER reject_capture BEFORE INSERT ON worker_source_captures BEGIN SELECT RAISE(ABORT,'capture unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err = j.JournalCapturedObservation(ctx, observation, encrypted); err == nil {
		t.Fatal("capture failure acknowledged")
	}
	pending, err := j.PendingObservations(ctx, 32)
	if err != nil || len(pending) != 0 {
		t.Fatal("metadata committed without original encrypted source")
	}
	if _, err = j.db.Exec(`DROP TRIGGER reject_capture`); err != nil {
		t.Fatal(err)
	}
	if err = j.JournalCapturedObservation(ctx, observation, encrypted); err != nil {
		t.Fatal(err)
	}
	if err = j.JournalCapturedObservation(ctx, observation, encrypted); err != nil {
		t.Fatal(err)
	}
	encrypted[0] ^= 1
	if err = j.JournalCapturedObservation(ctx, observation, encrypted); !errors.Is(err, ErrConflict) {
		t.Fatal("different ciphertext accepted on retry")
	}
}

func TestResolutionUsesOriginalExistingInspectionEpoch(t *testing.T) {
	j, _ := testJournal(t)
	protected := e2ee.ProtectedContext{Kind: e2ee.OwnerContextKind, ID: uuid.NewString(), TenantID: uuid.NewString(), OwnerUserID: uuid.NewString(), HostID: uuid.NewString()}
	old := crypto.KeyEpoch{ID: uuid.NewString(), State: crypto.EpochActive, Key: bytes.Repeat([]byte{7}, 32), CreatedAt: time.Now().UTC()}
	newer := crypto.KeyEpoch{ID: uuid.NewString(), State: crypto.EpochActive, Key: bytes.Repeat([]byte{8}, 32), CreatedAt: time.Now().UTC().Add(time.Second)}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := crypto.SaveContextKeyring(dir, &crypto.ContextKeyring{Context: protected, Epochs: []crypto.KeyEpoch{old, newer}}); err != nil {
		t.Fatal(err)
	}
	owner := &SessionOwner{ctx: context.Background(), journal: j, spec: NativeSpec{ProtectedContext: &protected, ContextStateDir: dir}}
	inspection := &Inspection{InteractionID: uuid.NewString(), DetailAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: protected.TenantID, ObjectType: e2ee.ObjectTypeRuntimeInteraction, ObjectID: uuid.NewString(), Sender: j.scope.InstanceID, Recipient: protected.OwnerUserID, KeyEpochID: old.ID, ProtectedContext: &protected}}
	event := session.SessionEvent{Type: session.EventInteractionResolved, Interaction: &session.InteractionEvent{Resolved: true, Answer: "complete original answer"}}
	resolution := owner.encryptResolution(event, inspection, time.Now().UTC())
	if resolution == nil || resolution.DetailAAD.KeyEpochID != old.ID {
		t.Fatal("resolution changed original accepted content authority")
	}
	key, _ := old.KeyArray()
	plain, err := e2ee.Decrypt(resolution.DetailEnvelope, key, resolution.DetailAAD)
	if err != nil || string(plain) != event.Interaction.Answer {
		t.Fatal("resolution is not the original plain answer")
	}
	clear(plain)
	// Removing authority must not manufacture an epoch or publish under another.
	if err = crypto.SaveContextKeyring(dir, &crypto.ContextKeyring{Context: protected, Epochs: []crypto.KeyEpoch{newer}}); err != nil {
		t.Fatal(err)
	}
	if owner.encryptResolution(event, inspection, time.Now().UTC()) != nil {
		t.Fatal("resolution ignored unavailable original epoch")
	}
	ring, err := crypto.LoadContextKeyring(dir, protected)
	if err != nil || len(ring.Epochs) != 1 || ring.Epochs[0].ID != newer.ID {
		t.Fatal("resolution changed stored content keys")
	}
}
