package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func nativeJournalFixture(t *testing.T) (*State, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "native-journal.db")
	state, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Close() })
	return state, path
}
func nativeJournalRecord() NativeObservationRecord {
	return NativeObservationRecord{ID: domain.NewID().String(), OriginID: domain.NewID().String(), MessageType: "interaction.started", Payload: []byte(`{"encrypted":true}`)}
}

func TestNativeObservationJournalAbruptProcessRecovery(t *testing.T) {
	if path := os.Getenv("PAGNET_NATIVE_JOURNAL_CHILD"); path != "" {
		state, err := OpenState(path)
		if err != nil {
			os.Exit(2)
		}
		row := NativeObservationRecord{ID: os.Getenv("PAGNET_NATIVE_JOURNAL_ID"), OriginID: os.Getenv("PAGNET_NATIVE_JOURNAL_ORIGIN"), MessageType: "interaction.started", Payload: []byte(`{"ciphertext":"opaque"}`)}
		if state.JournalNativeObservation(context.Background(), row) != nil {
			os.Exit(3)
		}
		// Abrupt exit without State.Close or a websocket send/receipt.
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "crash.db")
	row := nativeJournalRecord()
	command := exec.Command(os.Args[0], "-test.run=^TestNativeObservationJournalAbruptProcessRecovery$")
	command.Env = append(os.Environ(), "PAGNET_NATIVE_JOURNAL_CHILD="+path, "PAGNET_NATIVE_JOURNAL_ID="+row.ID, "PAGNET_NATIVE_JOURNAL_ORIGIN="+row.OriginID)
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("journal subprocess failed: %v %s", err, raw)
	}
	state, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	records, err := state.DueNativeObservations(t.Context(), time.Now(), 32)
	if err != nil || len(records) != 1 {
		t.Fatalf("committed observation lost: %+v %v", records, err)
	}
	if records[0].ID != row.ID || records[0].OriginID != row.OriginID || string(records[0].Payload) != `{"ciphertext":"opaque"}` || records[0].Digest != observationDigest(records[0].Payload) {
		t.Fatal("crash recovery changed immutable payload identity")
	}
	var syncMode int
	if err := state.db.QueryRow(`PRAGMA synchronous`).Scan(&syncMode); err != nil || syncMode < 2 {
		t.Fatal("journal is not crash durable")
	}
}

func TestNativeObservationJournalExactReceiptAndRollback(t *testing.T) {
	state, _ := nativeJournalFixture(t)
	ctx := t.Context()
	row := nativeJournalRecord()
	if err := state.JournalNativeObservation(ctx, row); err != nil {
		t.Fatal(err)
	}
	if err := state.JournalNativeObservation(ctx, row); err != nil {
		t.Fatal("duplicate journal should be idempotent", err)
	}
	changed := row
	changed.Payload = []byte(`{"replacement":true}`)
	if err := state.JournalNativeObservation(ctx, changed); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatal("observation overwritten", err)
	}
	if removed, err := state.FinishNativeObservation(ctx, row.ID, domain.NewID().String(), observationDigest(row.Payload), ""); err != nil || removed {
		t.Fatal("foreign origin cleared journal")
	}
	if removed, err := state.FinishNativeObservation(ctx, row.ID, row.OriginID, "wrong-digest", ""); !errors.Is(err, ErrNativeObservationConflict) || removed {
		t.Fatal("wrong content receipt cleared journal")
	}
	if _, err := state.db.Exec(`CREATE TRIGGER fail_native_retirement BEFORE DELETE ON native_observation_outbox BEGIN SELECT RAISE(ABORT,'fixture journal retirement failure');END;`); err != nil {
		t.Fatal(err)
	}
	if removed, err := state.FinishNativeObservation(ctx, row.ID, row.OriginID, observationDigest(row.Payload), "expired"); err == nil || removed {
		t.Fatal("failed transaction appeared retired")
	}
	var failures int
	if err := state.db.QueryRow(`SELECT count(*) FROM native_observation_failures`).Scan(&failures); err != nil || failures != 0 {
		t.Fatal("failure diagnostic survived rolled-back payload retirement")
	}
	if _, err := state.db.Exec(`DROP TRIGGER fail_native_retirement`); err != nil {
		t.Fatal(err)
	}
	if removed, err := state.FinishNativeObservation(ctx, row.ID, row.OriginID, observationDigest(row.Payload), ""); err != nil || !removed {
		t.Fatal("matching receipt did not retire", err)
	}
	records, err := state.DueNativeObservations(ctx, time.Now(), 32)
	if err != nil || len(records) != 0 {
		t.Fatal("retired payload still queued")
	}
	var count, size int
	if err := state.db.QueryRow(`SELECT row_count,payload_bytes FROM native_observation_usage WHERE slot=1`).Scan(&count, &size); err != nil || count != 0 || size != 0 {
		t.Fatal("retirement did not release reservation")
	}
}

func TestNativeObservationJournalByteCapacitySerializesWriters(t *testing.T) {
	state, path := nativeJournalFixture(t)
	ctx := t.Context()
	// Fill the byte reservation through real inserts and quota triggers. Leave
	// exactly one byte; two independent State objects compete for that byte.
	tx, err := state.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		size := NativeObservationMaxPayload
		if i == 255 {
			size--
		}
		row := nativeJournalRecord()
		payload := bytes.Repeat([]byte{'x'}, size)
		if _, err := tx.Exec(`INSERT INTO native_observation_outbox(observation_id,origin_id,message_type,digest,source_digest,payload,created_at,expires_at,retry_at) VALUES(?,?,?,?,?,?,?,?,?)`, row.ID, row.OriginID, row.MessageType, observationDigest(payload), observationDigest(payload), payload, time.Now().UnixMilli(), time.Now().Add(NativeObservationRetryHorizon).UnixMilli(), time.Now().UnixMilli()); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	other, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, store := range []*State{state, other} {
		wg.Go(func() {
			row := nativeJournalRecord()
			row.Payload = []byte{'y'}
			results <- store.JournalNativeObservation(ctx, row)
		})
	}
	wg.Wait()
	close(results)
	admitted, capacity := 0, 0
	for err := range results {
		if err == nil {
			admitted++
		} else if errors.Is(err, ErrNativeObservationCapacity) {
			capacity++
		} else {
			t.Fatal(err)
		}
	}
	if admitted != 1 || capacity != 1 {
		t.Fatalf("raced byte reservation: admitted=%d capacity=%d", admitted, capacity)
	}
	rows, err := state.DueNativeObservations(ctx, time.Now(), 100000)
	if err != nil || len(rows) != 32 {
		t.Fatal("retry batch is not bounded")
	}
}

func TestNativeObservationJournalExpiryDoesNotSilentlyDiscard(t *testing.T) {
	state, _ := nativeJournalFixture(t)
	row := nativeJournalRecord()
	row.CreatedAt = time.Now().Add(-8 * 24 * time.Hour)
	row.ExpiresAt = row.CreatedAt.Add(NativeObservationRetryHorizon)
	if err := state.JournalNativeObservation(t.Context(), row); err != nil {
		t.Fatal(err)
	}
	records, err := state.DueNativeObservations(t.Context(), time.Now(), 32)
	if err != nil || len(records) != 1 {
		t.Fatal("expired observation silently discarded")
	}
	if removed, err := state.FinishNativeObservation(t.Context(), row.ID, row.OriginID, observationDigest(row.Payload), "expired"); err != nil || !removed {
		t.Fatal(err)
	}
	var reason string
	if err := state.db.QueryRow(`SELECT reason FROM native_observation_failures WHERE observation_id=?`, row.ID).Scan(&reason); err != nil || reason != "expired" {
		t.Fatal("observation loss not recorded truthfully")
	}
}

func TestNativeObservationJournalRowCapacityAndImmutablePayload(t *testing.T) {
	state, _ := nativeJournalFixture(t)
	tx, err := state.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < NativeObservationOutboxMaxRows; i++ {
		row := nativeJournalRecord()
		if _, err = tx.Exec(`INSERT INTO native_observation_outbox(observation_id,origin_id,message_type,digest,source_digest,payload,created_at,expires_at,retry_at) VALUES(?,?,?,?,?,?,?,?,?)`, row.ID, row.OriginID, row.MessageType, observationDigest(row.Payload), observationDigest(row.Payload), row.Payload, time.Now().UnixMilli(), time.Now().Add(NativeObservationRetryHorizon).UnixMilli(), time.Now().UnixMilli()); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = state.JournalNativeObservation(t.Context(), nativeJournalRecord()); !errors.Is(err, ErrNativeObservationCapacity) {
		t.Fatal("row ceiling bypassed", err)
	}
	if _, err = state.db.Exec(`UPDATE native_observation_outbox SET payload='replacement'`); err == nil {
		t.Fatal("SQL mutation bypassed immutable content binding")
	}
	var count int
	if err = state.db.QueryRow(`SELECT row_count FROM native_observation_usage WHERE slot=1`).Scan(&count); err != nil || count != NativeObservationOutboxMaxRows {
		t.Fatal("failed mutation changed quota", count, err)
	}
}

func TestNativeObservationJournalStorageFailureCannotLookDurable(t *testing.T) {
	state, _ := nativeJournalFixture(t)
	if _, err := state.db.Exec(`PRAGMA query_only=ON`); err != nil {
		t.Fatal(err)
	}
	if err := state.JournalNativeObservation(t.Context(), nativeJournalRecord()); err == nil {
		t.Fatal("unwritable journal reported durable admission")
	}
	records, err := state.DueNativeObservations(t.Context(), time.Now(), 32)
	if err != nil || len(records) != 0 {
		t.Fatal("failed admission left a partial observation", err)
	}
}

func TestNativeObservationWorkerRetryDoesNotReencryptAfterCommit(t *testing.T) {
	state, path := nativeJournalFixture(t)
	row := nativeJournalRecord()
	row.SourceDigest = observationDigest([]byte("immutable native event"))
	if known, err := state.NativeObservationKnown(t.Context(), row.ID, row.OriginID, row.MessageType, row.SourceDigest); err != nil || known {
		t.Fatal(known, err)
	}
	if err := state.JournalNativeObservation(t.Context(), row); err != nil {
		t.Fatal(err)
	}
	// Reopen at both crash boundaries: journal COMMIT before worker ACK, and
	// server receipt retirement before the controller acknowledged the worker.
	for _, complete := range []bool{false, true} {
		if complete {
			if removed, err := state.FinishNativeObservation(t.Context(), row.ID, row.OriginID, observationDigest(row.Payload), ""); err != nil || !removed {
				t.Fatal(removed, err)
			}
		}
		reopened, err := OpenState(path)
		if err != nil {
			t.Fatal(err)
		}
		known, err := reopened.NativeObservationKnown(t.Context(), row.ID, row.OriginID, row.MessageType, row.SourceDigest)
		if err != nil || !known {
			t.Fatal("worker retry lost immutable publication", known, err)
		}
		if _, err := reopened.NativeObservationKnown(t.Context(), row.ID, row.OriginID, row.MessageType, observationDigest([]byte("changed event"))); !errors.Is(err, ErrNativeObservationConflict) {
			t.Fatal("worker changed committed event", err)
		}
		if _, err := reopened.NativeObservationKnown(t.Context(), row.ID, domain.NewID().String(), row.MessageType, row.SourceDigest); !errors.Is(err, ErrNativeObservationConflict) {
			t.Fatal("worker rebound committed event", err)
		}
		reopened.Close()
	}
}
