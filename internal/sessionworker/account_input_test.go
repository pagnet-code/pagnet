//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/accountmessage"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func accountInputFixture(t *testing.T, j *Journal, l int64) (Operation, transport.NativeDispatchProof, *Admission) {
	t.Helper()
	raw, err := os.ReadFile("../accountmessage/testdata/account_message_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Descriptor accountmessage.Descriptor `json:"descriptor"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	p := dispatchProof(dispatchOwnership(t, j, l), 1)
	d := fixture.Descriptor
	d.TenantID, d.OwnerUserID, d.HostID, d.TargetInstanceID = j.scope.TenantID, j.scope.AccountID, j.scope.HostID, j.scope.InstanceID
	d.RunnerID, d.RunnerConnectedAt = p.SourceRunnerID, p.SourceRunnerEpoch.UTC().Format(time.RFC3339Nano)
	d.CreatedAt, d.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), time.Now().Add(30*time.Second).UTC().Format(time.RFC3339Nano)
	envelope, err := e2ee.Encrypt([]byte("account input test"), [32]byte{1}, d.AAD(d.BindingDigest()))
	if err != nil {
		t.Fatal(err)
	}
	sealed := accountmessage.Sealed{V: 1, MessageID: d.MessageID, BindingDigest: d.BindingDigest(), Descriptor: d, Envelope: envelope}
	sealed.SealedDigest = sealed.Digest()
	// Convert through JSON to keep the frozen public descriptor representation.
	var source transport.NativeAccountMessageSource
	sourceRaw, err := transport.MarshalNativeAccountJSON(struct {
		V             int                       `json:"v"`
		MessageID     string                    `json:"messageId"`
		BindingDigest string                    `json:"bindingDigest"`
		SealedDigest  string                    `json:"sealedDigest"`
		Descriptor    accountmessage.Descriptor `json:"descriptor"`
		InputAAD      e2ee.AAD                  `json:"inputAAD"`
	}{1, d.MessageID, sealed.BindingDigest, sealed.SealedDigest, d, d.AAD(sealed.BindingDigest)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(sourceRaw, &source); err != nil {
		t.Fatal(err)
	}
	p.AccountMessageSource = &source
	op := Operation{InputKind: "account_message", SourceAccountMessage: &source, SealedAccountMessage: &envelope}
	current := &Admission{Scope: j.scope, Kind: "worker", NetworkID: d.NetworkID, NativeAdmissionID: p.SourceAdmissionID, RunnerID: p.SourceRunnerID, RunnerEpoch: p.SourceRunnerEpoch, BootID: p.SourceBootID}
	return op, p, current
}

func accountInputPayload(t *testing.T, op Operation) json.RawMessage {
	t.Helper()
	raw, err := MarshalNativeJSON(op)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAccountInputAdmissionImmutableDuplicateAndRecovery(t *testing.T) {
	j, dir := testJournal(t)
	l := lease(t, j)
	op, p, current := accountInputFixture(t, j, l)
	payload := accountInputPayload(t, op)
	out, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", payload, func() (*Admission, error) { return current, nil }, &p)
	if err != nil || !run {
		t.Fatal("admission", run, err)
	}
	op.SourceCommandID, op.SourceAdmissionID = p.SourceCommandID, p.SourceAdmissionID
	if err = j.verifyAccountInputForExecution(t.Context(), out.Sequence, out.CommandID, op); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE worker_account_inputs SET command_id='changed'`, `DELETE FROM worker_account_inputs`} {
		if _, err = j.db.Exec(q); err == nil {
			t.Fatal("mutable account input")
		}
	}
	if _, run, err = j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", payload, func() (*Admission, error) { t.Fatal("duplicate requested admission"); return nil, nil }, &p); err != nil || run {
		t.Fatal("duplicate", run, err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	l = lease(t, j)
	out, run, err = j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", payload, nil, &p)
	if err != nil || run || out.State != "uncertain" {
		t.Fatal("recovery", out.State, run, err)
	}
}

func TestAccountInputAdmissionRollsBack(t *testing.T) {
	for _, mutation := range []string{"missing", "runner", "epoch", "boot", "admission", "scope", "sealed", "generic", "intent"} {
		t.Run(mutation, func(t *testing.T) {
			j, _ := testJournal(t)
			l := lease(t, j)
			op, p, current := accountInputFixture(t, j, l)
			switch mutation {
			case "missing":
				current = nil
			case "runner":
				current.RunnerID = "stale"
			case "epoch":
				current.RunnerEpoch = current.RunnerEpoch.Add(time.Second)
			case "boot":
				current.BootID = "stale"
			case "admission":
				current.NativeAdmissionID = "stale"
			case "scope":
				current.Scope.AccountID = "stale"
			case "intent":
				if _, err := j.db.Exec(`CREATE TRIGGER reject_test_intent BEFORE INSERT ON worker_intent BEGIN SELECT RAISE(ABORT,'test rollback'); END`); err != nil {
					t.Fatal(err)
				}
			case "sealed":
				envelope := *op.SealedAccountMessage
				envelope.Ciphertext += "AAAA"
				op.SealedAccountMessage = &envelope
			}
			var proof *transport.NativeDispatchProof = &p
			sequence := int64(0)
			if mutation == "generic" {
				proof = nil
				sequence = 1
			}
			_, run, err := j.admitDispatch(t.Context(), l, sequence, p.SourceCommandID, "prompt", accountInputPayload(t, op), func() (*Admission, error) { return current, nil }, proof)
			// Pre-admission errors are generic failures, not durable worker
			// rejection receipts. No accepted outcome or partial journal survives.
			if err == nil || run {
				t.Fatal("accepted invalid account input")
			}
			for _, table := range []string{"worker_account_inputs", "worker_dispatches", "worker_intent"} {
				var n int
				if err := j.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
					t.Fatal("partial admission", table, n, err)
				}
			}
		})
	}
}

func TestAccountInputNativeSourceRoundTripAndReopen(t *testing.T) {
	j, dir := testJournal(t)
	l := lease(t, j)
	op, p, current := accountInputFixture(t, j, l)
	out, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", accountInputPayload(t, op), func() (*Admission, error) { return current, nil }, &p)
	if err != nil || !run {
		t.Fatal("admit", run, err)
	}
	source := NativeTurnSource{Sequence: out.Sequence, LogicalTurnID: logicalWorkerTurn(out.Sequence), NativeGeneration: "account-generation", NativeSessionID: "account-session", SourceCommandID: p.SourceCommandID, SourceAdmissionID: p.SourceAdmissionID, InputKind: "account_message", SourceAccountMessage: op.SourceAccountMessage}
	for i := 0; i < 2; i++ {
		if err := j.BindNativeTurn(t.Context(), source); err != nil {
			t.Fatal("bind", i, err)
		}
	}
	check := func(j *Journal) {
		t.Helper()
		tx, err := j.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := readNativeTurn(t.Context(), tx, source.NativeGeneration, source.LogicalTurnID)
		_ = tx.Rollback()
		if err != nil || stored.SourceAccountMessage == nil || !bytes.Equal(stored.SourceAccountMessage.CanonicalJSON(), source.SourceAccountMessage.CanonicalJSON()) || stored.SourceCommandID != source.SourceCommandID || stored.SourceAdmissionID != source.SourceAdmissionID {
			t.Fatal("read lost account source", err)
		}
		event, unavailable, err := j.NativeEventSource(t.Context(), source.NativeGeneration, session.SessionEvent{Type: session.EventTurnCompleted, TurnID: source.LogicalTurnID, SessionID: source.NativeSessionID})
		if err != nil || unavailable || event == nil || event.SourceAccountMessage == nil || !bytes.Equal(event.SourceAccountMessage.CanonicalJSON(), source.SourceAccountMessage.CanonicalJSON()) {
			t.Fatal("event lost account source", unavailable, err)
		}
	}
	check(j)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	check(j)
	var state string
	if err := j.db.QueryRow(`SELECT state FROM worker_intent WHERE sequence=?`, out.Sequence).Scan(&state); err != nil || state != "uncertain" {
		t.Fatal("recovery state", state, err)
	}
}

func TestAccountInputRetirementBoundsRetention(t *testing.T) {
	j, _ := testJournal(t)
	l := lease(t, j)
	op, p, current := accountInputFixture(t, j, l)
	payload := accountInputPayload(t, op)
	for n := int64(1); n <= maxCommands+1; n++ {
		p.DispatchSequence, p.SourceCommandID = n, domain.NewID().String()
		out, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", payload, func() (*Admission, error) { return current, nil }, &p)
		if err != nil || !run {
			t.Fatal("admit", n, run, err)
		}
		if err := j.Settle(t.Context(), out.Sequence, "completed", nil); err != nil {
			t.Fatal(n, err)
		}
		if err := j.Acknowledge(t.Context(), l, out.Sequence); err != nil {
			t.Fatal(n, err)
		}
		if err := j.RetireDispatches(t.Context(), l, n); err != nil {
			t.Fatal("retire", n, err)
		}
		var retained int
		if err := j.db.QueryRow(`SELECT COUNT(*) FROM worker_account_inputs`).Scan(&retained); err != nil || retained != 0 {
			t.Fatal("retained retired input", n, retained, err)
		}
		if _, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", payload, nil, &p); !errors.Is(err, ErrRetired) || run {
			t.Fatal("retired replay", n, run, err)
		}
	}
}

func TestAccountInputRetainsUncertainAndUnresolvedTurns(t *testing.T) {
	for _, bound := range []bool{false, true} {
		name := "uncertain"
		if bound {
			name = "unresolved-turn"
		}
		t.Run(name, func(t *testing.T) {
			j, _ := testJournal(t)
			l := lease(t, j)
			op, p, current := accountInputFixture(t, j, l)
			out, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", accountInputPayload(t, op), func() (*Admission, error) { return current, nil }, &p)
			if err != nil || !run {
				t.Fatal("admit", run, err)
			}
			state := "uncertain"
			if bound {
				source := NativeTurnSource{Sequence: out.Sequence, LogicalTurnID: logicalWorkerTurn(out.Sequence), NativeGeneration: "unresolved-account", NativeSessionID: "account-session", SourceCommandID: p.SourceCommandID, SourceAdmissionID: p.SourceAdmissionID, InputKind: "account_message", SourceAccountMessage: op.SourceAccountMessage}
				if err := j.BindNativeTurn(t.Context(), source); err != nil {
					t.Fatal(err)
				}
				state = "completed"
			}
			if err := j.Settle(t.Context(), out.Sequence, state, nil); err != nil {
				t.Fatal(err)
			}
			if err := j.Acknowledge(t.Context(), l, out.Sequence); err != nil {
				t.Fatal(err)
			}
			if err := j.RetireDispatches(t.Context(), l, p.DispatchSequence); err == nil {
				t.Fatal("retired retained input")
			}
			if _, err := j.db.Exec(`DELETE FROM worker_account_inputs WHERE sequence=?`, out.Sequence); err == nil {
				t.Fatal("deleted retained input")
			}
			var retained int
			if err := j.db.QueryRow(`SELECT COUNT(*) FROM worker_account_inputs WHERE sequence=?`, out.Sequence).Scan(&retained); err != nil || retained != 1 {
				t.Fatal("lost retained input", retained, err)
			}
		})
	}
}

func TestAccountInputRejectsOversizedEnvelope(t *testing.T) {
	j, _ := testJournal(t)
	l := lease(t, j)
	op, p, current := accountInputFixture(t, j, l)
	original := op.SourceAccountMessage
	d := accountmessage.Descriptor(original.Descriptor)
	envelope, err := e2ee.Encrypt(make([]byte, accountmessage.MaxFrameBytes), [32]byte{1}, d.AAD(d.BindingDigest()))
	if err != nil {
		t.Fatal(err)
	}
	sealed := accountmessage.Sealed{V: 1, MessageID: d.MessageID, BindingDigest: d.BindingDigest(), Descriptor: d, Envelope: envelope}
	sealed.SealedDigest = sealed.Digest()
	source := *original
	source.SealedDigest = sealed.SealedDigest
	op.SourceAccountMessage, op.SealedAccountMessage, p.AccountMessageSource = &source, &envelope, &source
	_, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", accountInputPayload(t, op), func() (*Admission, error) { return current, nil }, &p)
	if !errors.Is(err, ErrFull) || run {
		t.Fatal("oversized envelope", run, err)
	}
	for _, table := range []string{"worker_account_inputs", "worker_dispatches", "worker_intent"} {
		var count int
		if err := j.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial oversized admission", table, count, err)
		}
	}
}
