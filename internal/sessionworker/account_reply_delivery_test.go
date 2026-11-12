//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pagnet-code/pagnet/e2ee"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func deliveryAccountOwner(t *testing.T) (*SessionOwner, string, NativeTurnSource, int64) {
	t.Helper()
	owner, dir, source, _, lease := accountReplyOwner(t)
	owner.origin, _ = json.Marshal(transport.NativeObservationOrigin{ID: uuid.NewString(), TenantID: owner.journal.scope.TenantID, HostID: owner.journal.scope.HostID, InstanceID: owner.journal.scope.InstanceID, Runtime: string(owner.spec.Runtime), NativeGeneration: source.NativeGeneration})
	return owner, dir, source, lease
}

func emitDeliveryReply(t *testing.T, owner *SessionOwner, source NativeTurnSource) NativeObservation {
	t.Helper()
	event := session.SessionEvent{Type: session.EventTurnCompleted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID, FinalOutput: &session.FinalOutput{Version: 1, TextBlocks: []string{"private reply <&>"}}}
	if err := owner.nativeEventObserver(owner.journal.scope.InstanceID)(event); err != nil {
		t.Fatal(err)
	}
	page, err := owner.journal.DeliveryObservationsForLease(t.Context(), lease(t, owner.journal), 32)
	if err != nil || len(page.Observations) != 1 {
		t.Fatal(page, err)
	}
	return page.Observations[0]
}

func deliveryReplyReceipt(t *testing.T, o NativeObservation) *transport.NativeAccountReplyReceiptPayload {
	t.Helper()
	wire, err := NativeAccountReplyObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	b := o.OutputContent.ManifestAAD.BrowserAccountReply
	return &transport.NativeAccountReplyReceiptPayload{OriginID: wire.OriginID, ObservationID: o.ID, ObservationDigest: wire.Digest, MessageID: b.MessageID, ReplyID: b.ReplyID, ContentID: o.OutputContent.ContentID, CiphertextDigest: o.OutputContent.CiphertextDigest, Disposition: "committed"}
}

func TestAccountReplyDeliveryReceiptReplayRestart(t *testing.T) {
	owner, dir, source, _ := deliveryAccountOwner(t)
	j := owner.journal
	o := emitDeliveryReply(t, owner, source)
	l := lease(t, j)
	receipt := deliveryReplyReceipt(t, o)
	if o.SourceSequence != 1 || NativeSourceType(o) != "" {
		t.Fatal("incorrect stream allocation", o.SourceSequence)
	}
	if _, err := NativeBackendObservation(o); !errors.Is(err, ErrNativeSourceUnsupported) {
		t.Fatal(err)
	}
	for _, mutate := range []func(*transport.NativeAccountReplyReceiptPayload){
		func(r *transport.NativeAccountReplyReceiptPayload) { r.Disposition = "staged" },
		func(r *transport.NativeAccountReplyReceiptPayload) { r.ObservationDigest = o.SourceDigest },
		func(r *transport.NativeAccountReplyReceiptPayload) { r.ReplyID = "other" },
		func(r *transport.NativeAccountReplyReceiptPayload) { r.ContentID = "other" },
	} {
		changed := *receipt
		mutate(&changed)
		if err := j.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, o.SourceDigest, &changed); err == nil {
			t.Fatal("malformed ACK accepted")
		}
	}
	if err := j.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, o.SourceDigest, nil); err == nil {
		t.Fatal("missing receipt accepted")
	}
	if err := j.AcknowledgeObservation(t.Context(), l, o.ID, o.SourceDigest); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	if _, err := j.db.Exec(`CREATE TRIGGER reject_account_ack BEFORE DELETE ON worker_observations BEGIN SELECT RAISE(ABORT,'rollback'); END`); err != nil {
		t.Fatal(err)
	}
	if err := j.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, o.SourceDigest, receipt); err == nil {
		t.Fatal("delete failure accepted")
	}
	if sourceCount(t, j, "worker_account_reply_settlements") != 0 || sourceCount(t, j, "worker_content_fragments") == 0 {
		t.Fatal("failed ACK changed original evidence")
	}
	if _, err := j.db.Exec(`DROP TRIGGER reject_account_ack`); err != nil {
		t.Fatal(err)
	}
	if err := j.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, o.SourceDigest, receipt); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"worker_observations", "worker_content_fragments", "worker_source_captures", "worker_observation_sequence"} {
		if sourceCount(t, j, table) != 0 {
			t.Fatal("original retained", table)
		}
	}
	if err := j.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, o.SourceDigest, receipt); err != nil {
		t.Fatal(err)
	}
	scope := j.scope
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	l = lease(t, reopened)
	if err = reopened.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, o.SourceDigest, receipt); err != nil {
		t.Fatal(err)
	}
	changed := *receipt
	changed.MessageID = "other"
	if err = reopened.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, o.SourceDigest, &changed); err == nil {
		t.Fatal("changed replay accepted")
	}
	if err = reopened.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, string(bytes.Repeat([]byte{'a'}, 64)), receipt); err == nil {
		t.Fatal("changed source digest accepted")
	}
	if err = reopened.AcknowledgeObservation(t.Context(), l, o.ID, o.SourceDigest); !errors.Is(err, ErrFenced) {
		t.Fatal("generic replay accepted", err)
	}
}

func TestAccountReplyDeliveryMigrationTailPreservesOriginal(t *testing.T) {
	owner, dir, source, _ := deliveryAccountOwner(t)
	j := owner.journal
	add := func(id string) {
		o := NativeObservation{ID: id, Origin: owner.origin, NativeGeneration: source.NativeGeneration, NativeSessionID: source.NativeSessionID, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventBusy, SessionID: source.NativeSessionID}}
		o.SourceDigest, _ = observationDigest(o)
		if err := j.JournalObservation(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	add("before")
	event := session.SessionEvent{Type: session.EventTurnCompleted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID, FinalOutput: &session.FinalOutput{Version: 1, TextBlocks: []string{"original"}}}
	if err := owner.nativeEventObserver(j.scope.InstanceID)(event); err != nil {
		t.Fatal(err)
	}
	add("after")
	var accountID string
	var payload []byte
	if err := j.db.QueryRow(`SELECT id,payload FROM worker_observations WHERE id NOT IN('before','after')`).Scan(&accountID, &payload); err != nil {
		t.Fatal(err)
	}
	var fragment []byte
	if err := j.db.QueryRow(`SELECT payload FROM worker_content_fragments WHERE observation_id=? LIMIT 1`, accountID).Scan(&fragment); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{`DELETE FROM worker_account_reply_sequence_protocol`, `DELETE FROM worker_observation_sequence WHERE observation_id NOT IN('before','after')`, `UPDATE worker_observation_sequence SET source_sequence=2 WHERE observation_id='after'`, `UPDATE worker_source_stream SET last_sequence=2`} {
		if _, err := j.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	scope := j.scope
	j.Close()
	reopened, err := OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	page, err := reopened.DeliveryObservationsForLease(t.Context(), lease(t, reopened), 2)
	if err != nil || len(page.Observations) != 2 || !page.More || page.After != 0 || page.NextCursor != 0 || page.Observations[0].ID != "before" || page.Observations[1].ID != "after" {
		t.Fatal(page, err)
	}
	var afterPayload, afterFragment []byte
	var sequence int64
	if err = reopened.db.QueryRow(`SELECT payload FROM worker_observations WHERE id=?`, accountID).Scan(&afterPayload); err != nil {
		t.Fatal(err)
	}
	if err = reopened.db.QueryRow(`SELECT payload FROM worker_content_fragments WHERE observation_id=? LIMIT 1`, accountID).Scan(&afterFragment); err != nil {
		t.Fatal(err)
	}
	if err = reopened.db.QueryRow(`SELECT source_sequence FROM worker_observation_sequence WHERE observation_id=?`, accountID).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	if sequence != 3 || !bytes.Equal(payload, afterPayload) || !bytes.Equal(fragment, afterFragment) {
		t.Fatal("migration rewrote original evidence")
	}
}

func TestAccountReplyDeliverySkipsPrivateRowsAndOrdersOrigins(t *testing.T) {
	owner, _, source, _ := deliveryAccountOwner(t)
	j := owner.journal
	// Private account starts and unavailable terminal captures remain in the
	// legacy journal, even when there are more of them than a delivery page.
	for i := 0; i < 40; i++ {
		o := NativeObservation{ID: uuid.NewString(), Origin: owner.origin, NativeGeneration: source.NativeGeneration, NativeSessionID: source.NativeSessionID, ObservedAt: time.Now().UTC(), TurnSource: &source, Event: session.SessionEvent{Type: session.EventTurnStarted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID}}
		if i%2 == 0 {
			o.Event.Type = session.EventTurnCompleted
			o.SourceContentUnavailable = true
		}
		o.SourceDigest, _ = observationDigest(o)
		raw, err := MarshalNativeJSON(o)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = j.db.Exec(`INSERT INTO worker_observations(id,digest,payload,size) VALUES(?,?,?,?)`, o.ID, o.SourceDigest, raw, len(raw)); err != nil {
			t.Fatal(err)
		}
	}
	add := func(id, originID string) {
		var origin transport.NativeObservationOrigin
		json.Unmarshal(owner.origin, &origin)
		origin.ID = originID
		raw, _ := json.Marshal(origin)
		o := NativeObservation{ID: id, Origin: raw, NativeGeneration: source.NativeGeneration, NativeSessionID: source.NativeSessionID, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventBusy, SessionID: source.NativeSessionID}}
		o.SourceDigest, _ = observationDigest(o)
		if err := j.JournalObservation(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	add("z-first", "Z")
	add("a-first", "A")
	add("a-second", "A")
	l := lease(t, j)
	page, err := j.DeliveryObservationsForLease(t.Context(), l, 2)
	if err != nil || len(page.Observations) != 2 || !page.More || page.Observations[0].ID != "a-first" || page.Observations[1].ID != "a-second" {
		t.Fatal(page, err)
	}
	for _, o := range page.Observations {
		if err = j.AcknowledgeObservation(t.Context(), l, o.ID, o.SourceDigest); err != nil {
			t.Fatal(err)
		}
	}
	page, err = j.DeliveryObservationsForLease(t.Context(), l, 2)
	if err != nil || len(page.Observations) != 1 || page.More || page.Observations[0].ID != "z-first" {
		t.Fatal(page, err)
	}
	legacy, err := j.PendingObservationsForLease(t.Context(), l, 32)
	if err != nil || len(legacy) != 32 {
		t.Fatal("legacy observations changed", len(legacy), err)
	}
}

func TestAccountReplyDeliveryRetirementReplenishesCapacity(t *testing.T) {
	owner, _, source, _ := deliveryAccountOwner(t)
	j := owner.journal
	l := lease(t, j)
	// Exercise cardinality rather than power-loss behavior. The separate replay
	// test retains production FULL synchronous writes and an actual reopen.
	if _, err := j.db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		t.Fatal(err)
	}
	var rawProof, rawEnvelope []byte
	if err := j.db.QueryRow(`SELECT proof,envelope FROM worker_account_inputs WHERE sequence=?`, source.Sequence).Scan(&rawProof, &rawEnvelope); err != nil {
		t.Fatal(err)
	}
	var proof transport.NativeDispatchProof
	var envelope e2ee.EncryptedPayloadV1
	if json.Unmarshal(rawProof, &proof) != nil || json.Unmarshal(rawEnvelope, &envelope) != nil {
		t.Fatal("invalid fixture")
	}
	op := Operation{InputKind: "account_message", SourceAccountMessage: source.SourceAccountMessage, SealedAccountMessage: &envelope}
	current := &Admission{Scope: j.scope, Kind: "worker", NetworkID: owner.spec.NetworkID, NativeAdmissionID: proof.SourceAdmissionID, RunnerID: proof.SourceRunnerID, RunnerEpoch: proof.SourceRunnerEpoch, BootID: proof.SourceBootID}
	for n := int64(1); n <= maxCommands+1; n++ {
		if n > 1 {
			proof.DispatchSequence = n
			proof.SourceCommandID = uuid.NewString()
			out, run, err := j.admitDispatch(t.Context(), l, 0, proof.SourceCommandID, "prompt", accountInputPayload(t, op), func() (*Admission, error) { return current, nil }, &proof)
			if err != nil || !run {
				t.Fatal("admit", n, run, err)
			}
			source.Sequence = out.Sequence
			source.LogicalTurnID = logicalWorkerTurn(out.Sequence)
			source.SourceCommandID = proof.SourceCommandID
			source.NativeGeneration = fmt.Sprintf("account-generation-%d", n)
			if err = j.BindNativeTurn(t.Context(), source); err != nil {
				t.Fatal(n, err)
			}
			owner.generation = source.NativeGeneration
			owner.origin, _ = json.Marshal(transport.NativeObservationOrigin{ID: uuid.NewString(), TenantID: j.scope.TenantID, HostID: j.scope.HostID, InstanceID: j.scope.InstanceID, Runtime: string(owner.spec.Runtime), NativeGeneration: source.NativeGeneration})
			owner.pinOriginalTaskContent(source)
		}
		producer, err := j.registerNativeSource(t.Context(), source.NativeGeneration, owner.origin)
		if err != nil {
			t.Fatal(n, err)
		}
		observe := owner.nativeSourceObserver(j.scope.InstanceID, producer)
		event := session.SessionEvent{Type: session.EventTurnCompleted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID, FinalOutput: &session.FinalOutput{Version: 1, TextBlocks: []string{"terminal-only reply"}}}
		if err = observe(event); err != nil {
			t.Fatal(n, err)
		}
		page, err := j.DeliveryObservationsForLease(t.Context(), l, 32)
		if err != nil || len(page.Observations) != 1 {
			t.Fatal(n, page, err)
		}
		o := page.Observations[0]
		receipt := deliveryReplyReceipt(t, o)
		if err = j.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, o.SourceDigest, receipt); err != nil {
			t.Fatal(n, err)
		}
		if err = j.retireNativeSource(t.Context(), producer); err != nil {
			t.Fatal(n, err)
		}
		if err = j.Settle(t.Context(), source.Sequence, "completed", nil); err != nil {
			t.Fatal(n, err)
		}
		if err = j.Acknowledge(t.Context(), l, source.Sequence); err != nil {
			t.Fatal(n, err)
		}
		if err = j.RetireDispatches(t.Context(), l, n); err != nil {
			t.Fatal("retire", n, err)
		}
		if sourceCount(t, j, "worker_account_reply_settlements") != 0 || sourceCount(t, j, "worker_account_inputs") != 0 {
			t.Fatal("retired account evidence retained", n)
		}
		if err = j.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, o.SourceDigest, receipt); err == nil {
			t.Fatal("retired ACK replay accepted", n)
		}
	}
}

func TestAccountReplyDeliveryRetirementRetainsPrivateStart(t *testing.T) {
	owner, _, source, _ := deliveryAccountOwner(t)
	j := owner.journal
	l := lease(t, j)
	producer, err := j.registerNativeSource(t.Context(), source.NativeGeneration, owner.origin)
	if err != nil {
		t.Fatal(err)
	}
	observe := owner.nativeSourceObserver(j.scope.InstanceID, producer)
	if err = observe(session.SessionEvent{Type: session.EventTurnStarted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID}); err != nil {
		t.Fatal(err)
	}
	if err = observe(session.SessionEvent{Type: session.EventTurnCompleted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID, FinalOutput: &session.FinalOutput{Version: 1, TextBlocks: []string{"reply"}}}); err != nil {
		t.Fatal(err)
	}
	page, err := j.DeliveryObservationsForLease(t.Context(), l, 32)
	if err != nil || len(page.Observations) != 1 {
		t.Fatal(page, err)
	}
	o := page.Observations[0]
	receipt := deliveryReplyReceipt(t, o)
	if err = j.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, o.SourceDigest, receipt); err != nil {
		t.Fatal(err)
	}
	if err = j.retireNativeSource(t.Context(), producer); err != nil {
		t.Fatal(err)
	}
	if err = j.Settle(t.Context(), source.Sequence, "completed", nil); err != nil {
		t.Fatal(err)
	}
	if err = j.Acknowledge(t.Context(), l, source.Sequence); err != nil {
		t.Fatal(err)
	}
	if err = j.RetireDispatches(t.Context(), l, 1); !errors.Is(err, ErrConflict) {
		t.Fatal("private start did not block retirement", err)
	}
	if sourceCount(t, j, "worker_observations") != 1 || sourceCount(t, j, "worker_account_reply_settlements") != 1 || sourceCount(t, j, "worker_account_inputs") != 1 {
		t.Fatal("premature retirement erased retained evidence")
	}
	if err = j.AcknowledgeAccountReplyObservation(t.Context(), l, o.ID, o.SourceDigest, receipt); err != nil {
		t.Fatal("blocked retirement lost exact replay", err)
	}
}
