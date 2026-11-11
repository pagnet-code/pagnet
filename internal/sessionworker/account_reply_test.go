//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

func accountReplySpec(t *testing.T, op Operation) NativeSpec {
	t.Helper()
	d := op.SourceAccountMessage.Descriptor
	state := t.TempDir()
	key := make([]byte, 32)
	key[0] = 1
	ring := &hostcrypto.Keyring{NetworkID: d.NetworkID, Epochs: []hostcrypto.KeyEpoch{{ID: d.EpochID, State: hostcrypto.EpochActive, CreatedAt: time.Now().UTC(), Key: key}}}
	if err := hostcrypto.SaveKeyring(state, ring); err != nil {
		t.Fatal(err)
	}
	return NativeSpec{AccountMessageExecutionEnabled: true, Runtime: domain.RuntimeQwenCode, Kind: "worker", NetworkID: d.NetworkID, NetworkTenantID: d.TenantID, NetworkStateDir: state}
}

func accountReplyOwner(t *testing.T) (*SessionOwner, string, NativeTurnSource, transport.NativeDispatchProof, int64) {
	t.Helper()
	scope := testScope()
	scope.InstanceID = uuid.NewString()
	dir := filepath.Join(t.TempDir(), "worker")
	j, err := OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	l := lease(t, j)
	op, p, current := accountInputFixture(t, j, l)
	out, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", accountInputPayload(t, op), func() (*Admission, error) { return current, nil }, &p)
	if err != nil || !run {
		t.Fatal(run, err)
	}
	source := NativeTurnSource{Sequence: out.Sequence, LogicalTurnID: logicalWorkerTurn(out.Sequence), NativeGeneration: "account-generation", NativeSessionID: "account-session", SourceCommandID: p.SourceCommandID, SourceAdmissionID: p.SourceAdmissionID, InputKind: "account_message", SourceAccountMessage: p.AccountMessageSource}
	if err = j.BindNativeTurn(t.Context(), source); err != nil {
		t.Fatal(err)
	}
	owner := &SessionOwner{ctx: t.Context(), journal: j, captureKey: bytes.Repeat([]byte{3}, 32), manager: session.NewManager(), generation: source.NativeGeneration, origin: json.RawMessage(`{"id":"` + uuid.NewString() + `"}`), spec: accountReplySpec(t, op), pending: map[string]*nativeApproval{}}
	owner.manager.Session(j.scope.InstanceID, domain.RuntimeQwenCode, "workspace")
	owner.pinOriginalTaskContent(source)
	return owner, dir, source, p, l
}

func TestAccountReplyOriginalEpochRotationAndRestart(t *testing.T) {
	owner, dir, source, p, l := accountReplyOwner(t)
	j := owner.journal
	ring, err := hostcrypto.LoadKeyring(owner.spec.NetworkStateDir, owner.spec.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ring.Rotate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(owner.spec.NetworkStateDir, ring); err != nil {
		t.Fatal(err)
	}
	final := &session.FinalOutput{Version: 1, TextBlocks: []string{"  private <&> answer\n", "", "€\tend  "}}
	event := session.SessionEvent{Type: session.EventTurnCompleted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID, FinalOutput: final}
	if err = owner.nativeEventObserver(j.scope.InstanceID)(event); err != nil {
		t.Fatal(err)
	}
	pending, err := j.PendingObservationsForLease(t.Context(), l, 32)
	if err != nil || len(pending) != 1 {
		t.Fatal(len(pending), err)
	}
	o := pending[0]
	if o.OutputContent == nil || o.OutputContent.Purpose != e2ee.ObjectTypeBrowserAccountReply || o.Event.FinalOutput != nil || o.Event.Output != "" {
		t.Fatal("missing encrypted reply or exposed plaintext")
	}
	if o.OutputContent.ManifestAAD.KeyEpochID != source.SourceAccountMessage.Descriptor.EpochID || source.SourceAccountMessage.ValidateReplyAAD(o.OutputContent.ManifestAAD, p) != nil {
		t.Fatal("original reply authority lost")
	}
	if NativeSourceType(o) != "" {
		t.Fatal("account source eligible for generic delivery")
	}
	if err = j.AcknowledgeObservation(t.Context(), l, o.ID, o.SourceDigest); !errors.Is(err, ErrFenced) {
		t.Fatal("generic ACK retired account reply", err)
	}
	if _, ok := owner.originalTaskContentPin(&source); ok {
		t.Fatal("durable terminal retained key pin")
	}
	before, _ := MarshalNativeJSON(o)
	if bytes.Contains(before, []byte("private <&>")) {
		t.Fatal("plaintext projection")
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
	l = lease(t, j)
	pending, err = j.PendingObservationsForLease(t.Context(), l, 32)
	if err != nil || len(pending) != 1 {
		t.Fatal(err)
	}
	after, _ := MarshalNativeJSON(pending[0])
	if !bytes.Equal(before, after) {
		t.Fatal("restart changed captured ciphertext or identity")
	}
	var fragments []transport.NativeContentFragment
	for i := 0; i < o.OutputContent.FragmentCount; i++ {
		f, err := j.ReadContentFragment(t.Context(), l, o.ID, o.SourceDigest, o.OutputContent.ContentID, i)
		if err != nil {
			t.Fatal(err)
		}
		fragments = append(fragments, *f)
	}
	plain, mime, err := nativecontent.Open(*o.OutputContent, fragments, [32]byte{1})
	if err != nil || mime != "application/json" {
		t.Fatal(mime, err)
	}
	expected, _ := canonicalNativeJSON(final)
	if !bytes.Equal(plain, expected) {
		t.Fatal("answer order or whitespace changed")
	}
	var decoded session.FinalOutput
	if json.Unmarshal(plain, &decoded) != nil || !reflect.DeepEqual(decoded, *final) {
		t.Fatal("final answer changed")
	}
	var count int
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_account_inputs`).Scan(&count); err != nil || count != 1 {
		t.Fatal("original ciphertext lost", count, err)
	}

	for name, mutate := range map[string]func(*NativeObservation, *transport.NativeDispatchProof){
		"generation":   func(o *NativeObservation, _ *transport.NativeDispatchProof) { o.NativeGeneration = "other" },
		"session":      func(o *NativeObservation, _ *transport.NativeDispatchProof) { o.NativeSessionID = "other" },
		"logical turn": func(o *NativeObservation, _ *transport.NativeDispatchProof) { o.Event.TurnID = "pagnet-worker-turn-2" },
		"ownership":    func(_ *NativeObservation, p *transport.NativeDispatchProof) { p.OwnershipID = "other" },
		"dispatch":     func(_ *NativeObservation, p *transport.NativeDispatchProof) { p.DispatchSequence++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed, changedProof := o, p
			mutate(&changed, &changedProof)
			if validateAccountReply(changed, *o.OutputContent, changedProof) == nil {
				t.Fatal("transplanted reply authority accepted")
			}
		})
	}
	// An observation identity or dispatch transplant cannot attach the reply.
	tx, err := j.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	changed := o
	changed.ID = uuid.NewString()
	if err = insertOriginalTransfer(t.Context(), tx, changed, nativecontent.Transfer{Reference: *o.OutputContent, Fragments: fragments}); err == nil {
		t.Fatal("identity transplant accepted")
	}
	changed = o
	copySource := *source.SourceAccountMessage
	copySource.Descriptor.ConnectionID = "other"
	copyTurn := source
	copyTurn.SourceAccountMessage = &copySource
	changed.TurnSource = &copyTurn
	if _, err = accountReplyProof(t.Context(), tx, *changed.TurnSource); err == nil {
		t.Fatal("original input transplant accepted")
	}
}

func TestAccountReplyRequiresAuthenticFinalAndOriginalEpoch(t *testing.T) {
	for _, name := range []string{"missing", "failed", "version", "session", "turn", "revoked", "missing epoch"} {
		t.Run(name, func(t *testing.T) {
			owner, _, source, _, _ := accountReplyOwner(t)
			defer owner.journal.Close()
			event := session.SessionEvent{Type: session.EventTurnCompleted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID, Output: "must not become reply", FinalOutput: &session.FinalOutput{Version: 1, TextBlocks: []string{"answer"}}}
			switch name {
			case "missing":
				event.FinalOutput = nil
			case "failed":
				event.Type = session.EventTurnFailed
			case "version":
				event.FinalOutput.Version = 2
			case "session":
				event.SessionID = "other"
			case "turn":
				event.TurnID = "other"
			case "missing epoch":
				owner.spec.NetworkStateDir = t.TempDir()
			case "revoked":
				ring, err := hostcrypto.LoadKeyring(owner.spec.NetworkStateDir, owner.spec.NetworkID)
				if err != nil {
					t.Fatal(err)
				}
				if name == "revoked" {
					ring.Epochs[0].State = hostcrypto.EpochRevoked
				} else {
					ring.Epochs = nil
				}
				if err = hostcrypto.SaveKeyring(owner.spec.NetworkStateDir, ring); err != nil {
					t.Fatal(err)
				}
			}
			o := NativeObservation{ID: uuid.NewString(), TurnSource: &source, NativeGeneration: source.NativeGeneration, NativeSessionID: source.NativeSessionID, Origin: owner.origin, ObservedAt: time.Now().UTC()}
			if got := owner.captureOriginalTaskContent(event, &o); got != nil || o.OutputContent != nil {
				t.Fatal("unauthentic final or epoch produced reply")
			}
		})
	}
}

func TestAccountReplyCapturesFinalAfterNativeDeltas(t *testing.T) {
	owner, _, source, _, l := accountReplyOwner(t)
	defer owner.journal.Close()
	registration := owner.nativeEventRegistration(owner.journal.scope.InstanceID)
	defer registration.Retire()
	observe := registration.Observe
	for _, event := range []session.SessionEvent{
		{Type: session.EventTurnOutput, NativeOutput: true, Output: "intermediate native transcript"},
		{Type: session.EventTurnCompleted, FinalOutput: &session.FinalOutput{Version: 1, TextBlocks: []string{"original final"}}},
	} {
		event.SessionID = source.NativeSessionID
		event.TurnID = source.LogicalTurnID
		if err := observe(event); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := owner.journal.PendingObservationsForLease(t.Context(), l, 32)
	if err != nil {
		t.Fatal(err)
	}
	replies := 0
	for _, o := range pending {
		if NativeSourceType(o) != "" {
			t.Fatal("native account event eligible for generic delivery")
		}
		if o.OutputContent != nil {
			if o.OutputContent.Purpose != e2ee.ObjectTypeBrowserAccountReply || o.Event.Type != session.EventTurnCompleted {
				t.Fatal("transcript delta became reply")
			}
			replies++
		}
	}
	if replies != 1 {
		t.Fatal("missing unique final reply", replies)
	}
}
