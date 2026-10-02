//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/internal/session"
)

func TestExplicitFreshRestartRequiresRetiredReaderPreservesOriginalCapture(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	producer, observation := retiredFixture(t, j, "original-origin", "original-generation")
	capture := NativeSourceCapture{Format: NativeSourceCaptureFormat, Event: observation.Event}
	ref, cipher, err := sealNativeCapture(bytes.Repeat([]byte{4}, 32), j.scope, j.dir, observation, capture)
	if err != nil {
		t.Fatal(err)
	}
	observation.Capture = ref
	observation.SourceDigest, _ = observationDigest(observation)
	if err = j.journalCapturedObservation(ctx, producer, observation, cipher); err != nil {
		t.Fatal(err)
	}
	if err = j.requireNativeReadersQuiesced(ctx); !errors.Is(err, session.ErrBusy) {
		t.Fatalf("live reader admitted fresh restart: %v", err)
	}
	if err = j.retireNativeSource(ctx, producer); err != nil {
		t.Fatal(err)
	}
	if err = j.requireNativeReadersQuiesced(ctx); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err = j.db.QueryRow(`SELECT payload FROM worker_observations WHERE id=?`, observation.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var persistedCipher []byte
	if err = j.db.QueryRow(`SELECT ciphertext FROM worker_source_captures WHERE id=?`, observation.ID).Scan(&persistedCipher); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(persistedCipher, cipher) {
		t.Fatal("freshness fence rewrote original private ciphertext")
	}
	if sourceCount(t, j, "worker_observations") != 1 || sourceCount(t, j, "worker_source_captures") != 1 {
		t.Fatal("freshness check erased original evidence")
	}
	// A persistent unquiesced registration cannot be overridden by an empty
	// in-memory capability map after a database or callback inconsistency.
	if _, err = j.db.Exec(`UPDATE worker_source_registration SET quiesced=0`); err != nil {
		t.Fatal(err)
	}
	if err = j.requireNativeReadersQuiesced(ctx); !errors.Is(err, session.ErrBusy) {
		t.Fatalf("persistent reader bypassed fence: %v", err)
	}
}
