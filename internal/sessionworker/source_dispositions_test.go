//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
	"testing"
	"time"
)

func TestTerminalSourceDispositionRetainsOriginalAndAdvancesSendCursor(t *testing.T) {
	for _, disposition := range []string{"expired", "stale_origin", transport.NativeObservationDeleteQuarantined} {
		t.Run(disposition, func(t *testing.T) {
			j, dir := testJournal(t)
			ctx := context.Background()
			a := lease(t, j)
			key := bytes.Repeat([]byte{13}, 32)
			ciphertext := map[string][]byte{}
			add := func(id string) NativeObservation {
				o := NativeObservation{ID: id, NativeGeneration: "native-A", NativeSessionID: "session-A", Origin: json.RawMessage(`{"id":"origin-A","instanceId":"instance","runtime":"fake","nativeGeneration":"native-A"}`), ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventBusy}}
				capture, encrypted, err := sealNativeCapture(key, j.scope, dir, o, NativeSourceCapture{Format: NativeSourceCaptureFormat, Event: session.SessionEvent{Type: session.EventBusy, Output: "private original source never public"}})
				if err != nil {
					t.Fatal(err)
				}
				o.Capture = capture
				ciphertext[id] = encrypted
				o.SourceDigest, _ = observationDigest(o)
				if err := j.JournalCapturedObservation(ctx, o, encrypted); err != nil {
					t.Fatal(err)
				}
				return o
			}
			first := add("first")
			second := add("second")
			pending, _ := j.PendingObservationsForLease(ctx, a, 32)
			wire, err := NativeBackendObservation(pending[0])
			if err != nil {
				t.Fatal(err)
			}
			receipt := transport.NativeObservationReceiptPayload{ObservationID: first.ID, OriginID: wire.OriginID, Digest: wire.Digest, Disposition: disposition}
			for _, field := range []string{"origin", "digest", "id", "disposition"} {
				bad := receipt
				switch field {
				case "origin":
					bad.OriginID = "foreign"
				case "digest":
					bad.Digest = first.SourceDigest
				case "id":
					bad.ObservationID = second.ID
				case "disposition":
					bad.Disposition = "committed"
				}
				if err := j.RecordNativeSourceDisposition(ctx, a, first.ID, first.SourceDigest, bad); !errors.Is(err, ErrConflict) {
					t.Fatalf("accepted wrong %s: %v", field, err)
				}
			}
			// An aborted marker COMMIT must leave the original eligible for retry.
			if _, err = j.db.Exec(`CREATE TRIGGER fail_disposition BEFORE INSERT ON worker_source_dispositions BEGIN SELECT RAISE(ABORT,'isolated failure'); END`); err != nil {
				t.Fatal(err)
			}
			if err = j.RecordNativeSourceDisposition(ctx, a, first.ID, first.SourceDigest, receipt); err == nil {
				t.Fatal("invented durable marker")
			}
			pending, _ = j.PendingObservationsForLease(ctx, a, 32)
			if len(pending) != 2 {
				t.Fatal("failed marker hid source")
			}
			j.db.Exec(`DROP TRIGGER fail_disposition`)
			if err = j.RecordNativeSourceDisposition(ctx, a, first.ID, first.SourceDigest, receipt); err != nil {
				t.Fatal(err)
			}
			if err = j.RecordNativeSourceDisposition(ctx, a, first.ID, first.SourceDigest, receipt); err != nil {
				t.Fatal(err)
			}
			if err = j.AcknowledgeObservation(ctx, a, first.ID, first.SourceDigest); !errors.Is(err, ErrConflict) {
				t.Fatal("terminal receipt deleted uncommitted evidence", err)
			}
			if err = j.Close(); err != nil {
				t.Fatal(err)
			}
			j, err = OpenJournal(dir, testScope())
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			b := lease(t, j)
			if err = j.RecordNativeSourceDisposition(ctx, a, first.ID, first.SourceDigest, receipt); !errors.Is(err, ErrFenced) {
				t.Fatal("old controller changed marker", err)
			}
			pending, err = j.PendingObservationsForLease(ctx, b, 32)
			if err != nil || len(pending) != 1 || pending[0].ID != second.ID || pending[0].SourceSequence != 2 {
				t.Fatal("terminal retained source starved next sequence", pending, err)
			}
			recovery, err := j.SourceDispositionPageForLease(ctx, b, 0, 32)
			if err != nil || len(recovery.Sources) != 1 || recovery.Sources[0].Receipt != receipt || recovery.Sources[0].Observation.SourceDigest != first.SourceDigest || recovery.Sources[0].Observation.SourceSequence != 1 {
				t.Fatal("reopen lost recovery provenance", recovery, err)
			}
			chunk, err := j.ReadCaptureChunk(ctx, b, first.ID, first.SourceDigest, 0)
			if err != nil || !bytes.Equal(chunk.Data, ciphertext[first.ID]) {
				t.Fatal("terminal disposition changed/deleted original cipher", err)
			}
			plain, err := OpenNativeSourceCapture(key, j.scope, dir, recovery.Sources[0].Observation, ciphertext[first.ID])
			if err != nil || plain.Event.Output != "private original source never public" {
				t.Fatal("original recovery lost private native content", err)
			}
			if err = j.AcknowledgeObservation(ctx, b, second.ID, second.SourceDigest); err != nil {
				t.Fatal(err)
			}
			var count int
			j.db.QueryRow(`SELECT COUNT(*) FROM worker_observations`).Scan(&count)
			if count != 1 {
				t.Fatal("uncommitted original was deleted")
			}
		})
	}
}

func TestTerminalDispositionHasReservedCapacityAtFullCiphertextQuota(t *testing.T) {
	j, dir := testJournal(t)
	defer j.Close()
	ctx := context.Background()
	a := lease(t, j)
	key := bytes.Repeat([]byte{17}, 32)
	build := func(n int) (NativeObservation, []byte) {
		o := NativeObservation{ID: domain.NewID().String(), NativeGeneration: "original", NativeSessionID: "actual", Origin: json.RawMessage(`{"id":"origin","instanceId":"instance","runtime":"fake","nativeGeneration":"original"}`), ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventBusy}}
		var err error
		var cipher []byte
		o.Capture, cipher, err = sealNativeCapture(key, j.scope, dir, o, NativeSourceCapture{Format: NativeSourceCaptureFormat, Event: session.SessionEvent{Type: session.EventBusy, Output: string(bytes.Repeat([]byte("x"), n))}})
		if err != nil {
			t.Fatal(err)
		}
		o.SourceDigest, _ = observationDigest(o)
		return o, cipher
	}
	for {
		var total, count int
		if err := j.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(size),0)+(SELECT COALESCE(SUM(size),0) FROM worker_source_captures) FROM worker_observations`).Scan(&count, &total); err != nil {
			t.Fatal(err)
		}
		remaining := maxPendingObservationBytes - total - (count+1)*sourceDispositionReserveBytes
		if remaining < 4096 {
			break
		}
		small, encrypted := build(1)
		raw, _ := json.Marshal(small)
		n := min(maxPrivateSourceBytes-2048, remaining-len(raw)-len(encrypted)-64)
		o, cipher := build(n)
		raw, _ = json.Marshal(o)
		if excess := len(raw) + len(cipher) - remaining; excess > 0 {
			o, cipher = build(n - excess)
		}
		if err := j.JournalCapturedObservation(ctx, o, cipher); err != nil {
			t.Fatal(err)
		}
	}
	extra, cipher := build(4096)
	if err := j.JournalCapturedObservation(ctx, extra, cipher); !errors.Is(err, ErrFull) {
		t.Fatal("ordinary capture consumed disposition reserve", err)
	}
	page, err := j.PendingObservationsForLease(ctx, a, 32)
	if err != nil || len(page) < 2 {
		t.Fatal(err)
	}
	for _, o := range page {
		p, err := NativeBackendObservation(o)
		if err != nil {
			t.Fatal(err)
		}
		r := transport.NativeObservationReceiptPayload{ObservationID: o.ID, OriginID: p.OriginID, Digest: p.Digest, Disposition: "expired"}
		if err = j.RecordNativeSourceDisposition(ctx, a, o.ID, o.SourceDigest, r); err != nil {
			t.Fatal("full cipher quota prevented terminal durable disposition", err)
		}
	}
	var size int
	j.db.QueryRow(`SELECT (SELECT COALESCE(SUM(size),0) FROM worker_observations)+(SELECT COALESCE(SUM(size),0) FROM worker_source_captures)+(SELECT COALESCE(SUM(size),0) FROM worker_source_dispositions)`).Scan(&size)
	if size > maxPendingObservationBytes {
		t.Fatal("unbounded terminal metadata")
	}
	if pending, err := j.PendingObservationsForLease(ctx, a, 32); err != nil || len(pending) != 0 {
		t.Fatal("full retained evidence still blocked send cursor", err)
	}
}
