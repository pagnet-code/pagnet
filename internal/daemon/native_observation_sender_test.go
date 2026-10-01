package daemon

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeObservationSendWaitsForExactCommittedReceipt(t *testing.T) {
	state, _ := nativeJournalFixture(t)
	row := nativeJournalRecord()
	if err := state.JournalNativeObservation(t.Context(), row); err != nil {
		t.Fatal(err)
	}
	var sent transport.NativeObservationPayload
	now := time.Now().Add(time.Second)
	send := func(_ context.Context, typ string, p any) error {
		if typ != transport.MsgNativeObservation {
			t.Fatal(typ)
		}
		sent = p.(transport.NativeObservationPayload)
		return nil
	}
	if err := state.SendNativeObservationBatch(t.Context(), now, send, nil); err != nil {
		t.Fatal(err)
	}
	if sent.ObservationID != row.ID || sent.OriginID != row.OriginID || !bytes.Equal(sent.Payload, row.Payload) {
		t.Fatal("publication changed original content", sent)
	}
	// A transport write alone is not delivery; replay exact bytes after loss.
	if err := state.SendNativeObservationBatch(t.Context(), now.Add(time.Minute), send, nil); err != nil {
		t.Fatal(err)
	}
	receipt := transport.NativeObservationReceiptPayload{ObservationID: sent.ObservationID, OriginID: sent.OriginID, Digest: sent.Digest, Disposition: "committed"}
	bad := receipt
	bad.Digest = observationDigest([]byte("different content"))
	if removed, err := state.ReceiveNativeObservationDisposition(t.Context(), transport.MsgNativeObservationReceipt, bad); removed || !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatal(removed, err)
	}
	if removed, err := state.ReceiveNativeObservationDisposition(t.Context(), transport.MsgNativeObservationRejected, receipt); removed || err == nil {
		t.Fatal("rejection became successful receipt", removed, err)
	}
	if removed, err := state.ReceiveNativeObservationDisposition(t.Context(), transport.MsgNativeObservationReceipt, receipt); !removed || err != nil {
		t.Fatal(removed, err)
	}
	if removed, err := state.ReceiveNativeObservationDisposition(t.Context(), transport.MsgNativeObservationReceipt, receipt); removed || err != nil {
		t.Fatal("duplicate receipt was not idempotent", removed, err)
	}
}

func TestNativeObservationSendFailureRetainsJournalAndExpiryIsReported(t *testing.T) {
	state, _ := nativeJournalFixture(t)
	row := nativeJournalRecord()
	if err := state.JournalNativeObservation(t.Context(), row); err != nil {
		t.Fatal(err)
	}
	offline := errors.New("offline")
	if err := state.SendNativeObservationBatch(t.Context(), time.Now().Add(time.Second), func(context.Context, string, any) error { return offline }, nil); !errors.Is(err, offline) {
		t.Fatal(err)
	}
	rows, err := state.DueNativeObservations(t.Context(), time.Now().Add(time.Minute), 32)
	if err != nil || len(rows) != 1 || rows[0].Attempts != 0 {
		t.Fatal("failed send retired content", rows, err)
	}
	failures := 0
	if err := state.SendNativeObservationBatch(t.Context(), rows[0].ExpiresAt, func(context.Context, string, any) error { t.Fatal("expired observation was sent"); return nil }, func(got NativeObservationRecord, reason string) {
		if got.ID != row.ID || reason != "expired" {
			t.Fatal(got, reason)
		}
		failures++
	}); err != nil || failures != 1 {
		t.Fatal(failures, err)
	}
}
