//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func encoderCapture(sequence int64, generation, text string) nativeOutputSpool {
	return nativeOutputSpool{Source: NativeTurnSource{Sequence: sequence, LogicalTurnID: logicalWorkerTurn(sequence), NativeGeneration: generation, NativeSessionID: "original-session", SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String()}, Origin: json.RawMessage(`{"id":"original-origin"}`), Text: text, NativeBytes: len(text), DeltaCount: 1, RollingDigest: strings.Repeat("a", 64), KeyAvailable: true, Key: bytes.Repeat([]byte{29}, 32)}
}

func TestOutputEncoderIndependentCapturesAndFreshNonces(t *testing.T) {
	var encoder nativeOutputEncoder
	defer encoder.close()
	key := bytes.Repeat([]byte{17}, 32)
	scope := testScope()
	directory := t.TempDir()
	aead, err := captureAEAD(key, scope, directory)
	if err != nil {
		t.Fatal(err)
	}
	original := encoderCapture(1, "native-original", strings.Repeat("private original α", 4000))
	first, err := encoder.seal(key, scope, directory, original)
	if err != nil {
		t.Fatal(err)
	}
	retained := append([]byte(nil), first...)
	nonces := map[string]bool{string(first[:aead.NonceSize()]): true}
	// Alternate large, tiny and distinct turn/generation captures through one
	// encoder. Each must independently open to its own exact original content.
	for n := int64(1); n <= 64; n++ {
		input := original
		if n%2 == 0 {
			input = encoderCapture(n+1, fmt.Sprintf("native-%d", n), fmt.Sprintf("independent-private-%d", n))
		}
		sealed, err := encoder.seal(key, scope, directory, input)
		if err != nil {
			t.Fatal(err)
		}
		nonce := string(sealed[:aead.NonceSize()])
		if nonces[nonce] {
			t.Fatal("separate capture reused AEAD nonce")
		}
		nonces[nonce] = true
		recovered, err := openOutputSpool(key, scope, directory, input.Source.NativeGeneration, input.Source.Sequence, sealed)
		if err != nil || recovered.Text != input.Text || !bytes.Equal(recovered.Key, input.Key) || !bytes.Equal(recovered.Origin, input.Origin) {
			t.Fatal("independent capture changed original content", err)
		}
		clear(recovered.Key)
		if !bytes.Equal(first, retained) {
			t.Fatal("later capture mutated retained ciphertext")
		}
	}
	// A reused compressor does not confer authority to another directory,
	// ownership scope, key, generation or operation ordinal.
	changedScope := scope
	changedScope.Generation = "foreign-owner"
	for _, test := range []struct {
		key                   []byte
		scope                 Scope
		directory, generation string
		sequence              int64
	}{
		{bytes.Repeat([]byte{18}, 32), scope, directory, original.Source.NativeGeneration, 1},
		{key, changedScope, directory, original.Source.NativeGeneration, 1},
		{key, scope, directory + "-foreign", original.Source.NativeGeneration, 1},
		{key, scope, directory, "foreign-generation", 1},
		{key, scope, directory, original.Source.NativeGeneration, 2},
	} {
		if _, err := openOutputSpool(test.key, test.scope, test.directory, test.generation, test.sequence, first); !errors.Is(err, ErrConflict) {
			t.Fatal("foreign capture scope decrypted", err)
		}
	}
}

func TestOutputEncoderConcurrentCaptureAndCloseFencing(t *testing.T) {
	j, _ := testJournal(t)
	key := bytes.Repeat([]byte{23}, 32)
	var wg sync.WaitGroup
	for n := int64(1); n <= 24; n++ {
		wg.Go(func() {
			input := encoderCapture(n, fmt.Sprintf("native-%d", n), strings.Repeat(fmt.Sprintf("source-%d-", n), 256))
			sealed, err := j.outputEncoder.seal(key, j.scope, j.dir, input)
			if err != nil {
				t.Error(err)
				return
			}
			recovered, err := openOutputSpool(key, j.scope, j.dir, input.Source.NativeGeneration, n, sealed)
			if err != nil || recovered.Text != input.Text {
				t.Error("concurrent streams contaminated", err)
			}
			clear(recovered.Key)
		})
	}
	wg.Wait()
	// Closing the actual journal revokes its reusable capture capability. A
	// completed capture remains decryptable; close never mutates durable bytes.
	input := encoderCapture(25, "original-before-close", "retained original capture")
	retained, err := j.outputEncoder.seal(key, j.scope, j.dir, input)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = j.outputEncoder.seal(key, j.scope, j.dir, input); !errors.Is(err, ErrFenced) {
			t.Fatal("closed journal produced another capture", err)
		}
		j.outputEncoder.close()
	}
	recovered, err := openOutputSpool(key, j.scope, j.dir, input.Source.NativeGeneration, 25, retained)
	if err != nil || recovered.Text != input.Text {
		t.Fatal("closing scratch damaged independent ciphertext", err)
	}
	clear(recovered.Key)
}

func TestOutputEncoderCloseRacesIndependentCaptures(t *testing.T) {
	var encoder nativeOutputEncoder
	key := bytes.Repeat([]byte{31}, 32)
	scope, directory := testScope(), t.TempDir()
	original := encoderCapture(1, "native-original", "original before concurrent close")
	retained, err := encoder.seal(key, scope, directory, original)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for n := int64(2); n <= 33; n++ {
		wg.Go(func() {
			<-start
			input := encoderCapture(n, fmt.Sprintf("native-%d", n), strings.Repeat(fmt.Sprintf("distinct-%d-", n), 512))
			encrypted, err := encoder.seal(key, scope, directory, input)
			if errors.Is(err, ErrFenced) {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			recovered, err := openOutputSpool(key, scope, directory, input.Source.NativeGeneration, n, encrypted)
			if err != nil || recovered.Text != input.Text {
				t.Error("close raced partial capture", err)
			}
			clear(recovered.Key)
		})
	}
	wg.Go(func() { <-start; encoder.close() })
	close(start)
	wg.Wait()
	if _, err := encoder.seal(key, scope, directory, original); !errors.Is(err, ErrFenced) {
		t.Fatal("close did not fence subsequent capture", err)
	}
	recovered, err := openOutputSpool(key, scope, directory, original.Source.NativeGeneration, 1, retained)
	if err != nil || recovered.Text != original.Text {
		t.Fatal("close modified earlier encrypted capture", err)
	}
	clear(recovered.Key)
}

func TestOutputEncoderLargePreparedCaptureDoesNotRetainPeakWorkspace(t *testing.T) {
	var encoder nativeOutputEncoder
	defer encoder.close()
	key := bytes.Repeat([]byte{19}, 32)
	scope, directory := testScope(), t.TempDir()
	random := make([]byte, 512<<10)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	large := encoderCapture(1, "large-original-generation", base64.StdEncoding.EncodeToString(random))
	large.Ready = &nativeOutputReady{Observation: NativeObservation{ID: "original-prepared-observation"}, Capture: append([]byte(nil), random[:128<<10]...), Remaining: append([]byte(nil), random[128<<10:256<<10]...)}
	sealed, err := encoder.seal(key, scope, directory, large)
	if err != nil {
		t.Fatal(err)
	}
	if encoder.buffer.Cap() > 4*nativeOutputBatchBytes {
		t.Fatal("large prepared capture retained oversized journal compression scratch")
	}
	tiny := encoderCapture(2, "tiny-independent-generation", "small independent native source")
	tinyCipher, err := encoder.seal(key, scope, directory, tiny)
	if err != nil {
		t.Fatal(err)
	}
	original, err := openOutputSpool(key, scope, directory, large.Source.NativeGeneration, 1, sealed)
	if err != nil || original.Text != large.Text || original.Ready == nil || !bytes.Equal(original.Ready.Capture, large.Ready.Capture) || !bytes.Equal(original.Ready.Remaining, large.Ready.Remaining) {
		t.Fatal("large prepared immutable capture changed after scratch release", err)
	}
	clear(original.Key)
	small, err := openOutputSpool(key, scope, directory, tiny.Source.NativeGeneration, 2, tinyCipher)
	if err != nil || small.Text != tiny.Text || small.Ready != nil {
		t.Fatal("large prepared content contaminated next independent stream", err)
	}
	clear(small.Key)
	clear(random)
}
