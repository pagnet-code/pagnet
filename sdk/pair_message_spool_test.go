//go:build linux || darwin

package sdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func spoolInput(t *testing.T) (pairMessageBinding, []byte) {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	b := pairMessageBinding{PrincipalID: "sender", GrantID: "grant", Generation: 1, NetworkID: "network", MessageID: id.String(), InputDigest: sha256.Sum256([]byte("plaintext"))}
	w := pairMessageWire{Version: 1, GrantID: b.GrantID, Generation: 1, NetworkID: b.NetworkID, ID: b.MessageID, ThreadID: b.MessageID, Kind: "ASK", SenderPrincipalID: b.PrincipalID, RecipientPrincipalID: "recipient"}
	raw, _ := json.Marshal(w)
	return b, raw
}
func storeSpool(t *testing.T, k *keyring, b pairMessageBinding, raw []byte) pairMessageState {
	t.Helper()
	if _, exists, err := k.reservePairMessage(b); err != nil || exists {
		t.Fatalf("reserve: exists=%v %v", exists, err)
	}
	s, err := k.storePairMessage(b, raw, sha256.Sum256(raw))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPairMessageSpoolRestartAndRetirement(t *testing.T) {
	dir := t.TempDir()
	k, _ := newKeyring(dir)
	b, raw := spoolInput(t)
	state := storeSpool(t, k, b, raw)
	k, _ = newKeyring(dir)
	got, err := k.loadPairMessage(b)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("restart: %v", err)
	}
	if _, exists, err := k.reservePairMessage(b); err != nil || !exists {
		t.Fatalf("retry reservation: %v", err)
	}
	conflict := b
	conflict.InputDigest[0]++
	if _, _, err := k.reservePairMessage(conflict); err == nil {
		t.Fatal("conflicting input accepted")
	}
	changed := append([]byte(nil), raw...)
	changed[0] = ' '
	if _, err := k.storePairMessage(b, changed, sha256.Sum256(changed)); err == nil {
		t.Fatal("changed wire accepted")
	}
	for _, bad := range []pairMessageBinding{conflict, func() pairMessageBinding { x := b; x.Generation++; return x }(), func() pairMessageBinding { x := b; x.NetworkID = "other"; return x }(), func() pairMessageBinding { x := b; x.GrantID = "other"; return x }()} {
		if err := k.retirePairMessage(bad, state.WireDigest, "pending"); err == nil {
			t.Fatal("conflicting receipt accepted")
		}
	}
	if err := k.retirePairMessage(b, [32]byte{}, "pending"); err == nil {
		t.Fatal("wrong receipt digest accepted")
	}
	if err := k.retirePairMessage(b, state.WireDigest, "pending"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(k.pairMessagePath(b)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wire retained: %v", err)
	}
	k, _ = newKeyring(dir)
	if _, err := k.loadPairMessage(b); err == nil {
		t.Fatal("retired wire exposed")
	}
	if _, _, err := k.reservePairMessage(conflict); err == nil {
		t.Fatal("tombstone lost input binding")
	}
	if s, err := k.storePairMessage(b, raw, state.WireDigest); err != nil || !s.Retired {
		t.Fatalf("retired retry: %v", err)
	}
	unresolved, err := k.unresolvedPairMessages(b.PrincipalID)
	if err != nil || len(unresolved) != 0 {
		t.Fatalf("unresolved: %v", err)
	}
}

func TestPairMessageSpoolCorruptionFailsClosed(t *testing.T) {
	for _, kind := range []string{"missing-wire", "wire-mac", "index-mac", "missing-index", "missing-key"} {
		t.Run(kind, func(t *testing.T) {
			k := newTestKeyring(t)
			b, raw := spoolInput(t)
			storeSpool(t, k, b, raw)
			path := k.pairMessagePath(b)
			switch kind {
			case "missing-wire":
				os.Remove(path)
			case "wire-mac":
				os.WriteFile(path, []byte(`{"wire":"YQ==","mac":"Yg=="}`), 0600)
			case "index-mac":
				os.WriteFile(filepath.Join(k.pairMessageDir(b.PrincipalID), "index.json"), []byte(`{"records":{},"mac":""}`), 0600)
			case "missing-index":
				os.Remove(filepath.Join(k.pairMessageDir(b.PrincipalID), "index.json"))
			case "missing-key":
				os.Remove(filepath.Join(k.pairMessageDir(b.PrincipalID), "auth.key"))
			}
			if _, err := k.loadPairMessage(b); err == nil {
				t.Fatal("corruption accepted")
			}
			if _, _, err := k.reservePairMessage(b); err == nil {
				t.Fatal("corruption regenerated")
			}
			if _, err := k.storePairMessage(b, raw, sha256.Sum256(raw)); err == nil {
				t.Fatal("corruption overwritten")
			}
		})
	}
}

func TestPairMessageSpoolReservationAndWireCrash(t *testing.T) {
	k := newTestKeyring(t)
	b, raw := spoolInput(t)
	if _, _, err := k.reservePairMessage(b); err != nil {
		t.Fatal(err)
	}
	records, err := k.unresolvedPairMessages(b.PrincipalID)
	if err != nil || len(records) != 1 || records[0].WireBytes != 0 {
		t.Fatalf("lost reservation: %v", err)
	}
	if _, exists, err := k.reservePairMessage(b); err != nil || !exists {
		t.Fatalf("reservation regenerated: %v", err)
	}
	// Fail after the manifest rename/fsync, before the wire write can commit.
	calls := 0
	k.pendingPairSyncDir = func(path string) error {
		if path == k.pairMessageDir(b.PrincipalID) {
			calls++
			if calls == 3 {
				return errors.New("injected crash")
			}
		}
		return syncPairDir(path)
	}
	if _, err := k.storePairMessage(b, raw, sha256.Sum256(raw)); err == nil {
		t.Fatal("fault was not injected")
	}
	k.pendingPairSyncDir = nil
	if _, err := k.loadPairMessage(b); err == nil {
		t.Fatal("missing wire returned")
	}
	if _, err := k.storePairMessage(b, raw, sha256.Sum256(raw)); err == nil {
		t.Fatal("missing reserved wire regenerated")
	}
}

func TestPairMessageSpoolRetirementCrash(t *testing.T) {
	k := newTestKeyring(t)
	b, raw := spoolInput(t)
	state := storeSpool(t, k, b, raw)
	// Manifest rename survives while its fsync reports failure. Ciphertext must
	// remain until a successful durable tombstone read on the next call.
	k.pendingPairSyncDir = func(path string) error {
		if path == k.pairMessageDir(b.PrincipalID) {
			content, _ := os.ReadFile(filepath.Join(path, "index.json"))
			if bytes.Contains(content, []byte(`"retired":true`)) {
				return errors.New("injected tombstone fsync")
			}
		}
		return syncPairDir(path)
	}
	if err := k.retirePairMessage(b, state.WireDigest, "pending"); err == nil {
		t.Fatal("fault not injected")
	}
	if _, err := os.Stat(k.pairMessagePath(b)); err != nil {
		t.Fatal("deleted before tombstone durable", err)
	}
	k.pendingPairSyncDir = nil
	if err := k.retirePairMessage(b, state.WireDigest, "pending"); err != nil {
		t.Fatal(err)
	}
}

func TestPairMessageSpoolCountAndConcurrentReservation(t *testing.T) {
	k := newTestKeyring(t)
	b, _ := spoolInput(t)
	var wg sync.WaitGroup
	results := make(chan bool, 16)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, exists, err := k.reservePairMessage(b); results <- exists; errs <- err }()
	}
	wg.Wait()
	close(results)
	close(errs)
	fresh := 0
	for exists := range results {
		if !exists {
			fresh++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if fresh != 1 {
		t.Fatalf("fresh reservations: %d", fresh)
	}
	for i := 1; i < pairMessageSpoolCount; i++ {
		next, _ := spoolInput(t)
		if _, _, err := k.reservePairMessage(next); err != nil {
			t.Fatal(i, err)
		}
	}
	next, _ := spoolInput(t)
	if _, _, err := k.reservePairMessage(next); err == nil {
		t.Fatal("record limit exceeded")
	}
	// Per-principal state is independent.
	next.PrincipalID = "another"
	if _, _, err := k.reservePairMessage(next); err != nil {
		t.Fatal(err)
	}
}

func TestPairMessageSpoolActualWireByteBoundary(t *testing.T) {
	k := newTestKeyring(t)
	b, raw := spoolInput(t)
	var w pairMessageWire
	json.Unmarshal(raw, &w)
	w.Envelope.Ciphertext = string(bytes.Repeat([]byte("x"), pairMessageSpoolBytes-len(raw)))
	raw, _ = json.Marshal(w)
	if len(raw) != pairMessageSpoolBytes {
		t.Fatalf("test wire size: %d", len(raw))
	}
	state := storeSpool(t, k, b, raw)
	next, nextRaw := spoolInput(t)
	if _, _, err := k.reservePairMessage(next); err != nil {
		t.Fatal(err)
	}
	if _, err := k.storePairMessage(next, nextRaw, sha256.Sum256(nextRaw)); err == nil {
		t.Fatal("byte limit exceeded")
	}
	if err := k.retirePairMessage(b, state.WireDigest, "pending"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.storePairMessage(next, nextRaw, sha256.Sum256(nextRaw)); err != nil {
		t.Fatal("retirement did not release quota", err)
	}
}

func TestPairMessageSpoolProcessReservation(t *testing.T) {
	if dir := os.Getenv("PAGNET_SPOOL_TEST_DIR"); dir != "" {
		k, err := newKeyring(dir)
		if err != nil {
			t.Fatal(err)
		}
		b := pairMessageBinding{PrincipalID: "sender", GrantID: "grant", Generation: 1, NetworkID: "network", MessageID: os.Getenv("PAGNET_SPOOL_TEST_ID"), InputDigest: sha256.Sum256([]byte("input"))}
		_, exists, err := k.reservePairMessage(b)
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			fmt.Println("FRESH_RESERVATION")
		}
		return
	}
	dir := t.TempDir()
	b, _ := spoolInput(t)
	var wg sync.WaitGroup
	outputs := make(chan []byte, 4)
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestPairMessageSpoolProcessReservation$")
			cmd.Env = append(os.Environ(), "PAGNET_SPOOL_TEST_DIR="+dir, "PAGNET_SPOOL_TEST_ID="+b.MessageID)
			out, err := cmd.CombinedOutput()
			outputs <- out
			errs <- err
		}()
	}
	wg.Wait()
	close(outputs)
	close(errs)
	fresh := 0
	for out := range outputs {
		fresh += bytes.Count(out, []byte("FRESH_RESERVATION"))
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if fresh != 1 {
		t.Fatalf("cross-process fresh reservations: %d", fresh)
	}
}
