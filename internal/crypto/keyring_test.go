package crypto

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

func testTime() time.Time { return time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC) }

func testAAD(networkID, epochID string) e2ee.AAD {
	return e2ee.AAD{
		ProtocolVersion: e2ee.AADVersion,
		TenantID:        "tenant-1",
		NetworkID:       networkID,
		ObjectType:      "message",
		ObjectID:        "object-1",
		Sender:          "s",
		Recipient:       "r",
		CreatedAt:       "2026-09-14T12:00:00Z",
		KeyEpochID:      epochID,
	}
}

// TestKeyringRotation verifies that rotation mints a new active epoch, new
// content uses the new epoch, and old ciphertext still decrypts with the old
// epoch (plan §11.8).
func TestKeyringRotation(t *testing.T) {
	networkID := "01900000-0000-7000-8000-0000000000a1"
	kr := NewKeyring(networkID)

	e1, err := kr.Activate(testTime())
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	k1, _ := e1.KeyArray()

	// Encrypt content under the first epoch.
	oldAAD := testAAD(networkID, e1.ID)
	oldEnv, err := e2ee.Encrypt([]byte("old content"), k1, oldAAD)
	if err != nil {
		t.Fatalf("Encrypt old: %v", err)
	}

	// Rotate: a new active epoch appears; the old one becomes rotated.
	e2, err := kr.Rotate(testTime().Add(time.Hour))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if e2.ID == e1.ID {
		t.Fatal("rotation produced the same epoch id")
	}
	oldEpoch, _ := kr.EpochByID(e1.ID)
	if oldEpoch.State != EpochRotated {
		t.Fatalf("old epoch state = %s, want %s", oldEpoch.State, EpochRotated)
	}
	if e2.State != EpochActive {
		t.Fatalf("new epoch state = %s, want %s", e2.State, EpochActive)
	}

	// New content uses the NEW active epoch.
	active, err := kr.ActiveEpoch()
	if err != nil {
		t.Fatalf("ActiveEpoch: %v", err)
	}
	if active.ID != e2.ID {
		t.Fatalf("ActiveEpoch = %s, want the new epoch %s", active.ID, e2.ID)
	}
	k2, _ := active.KeyArray()
	newAAD := testAAD(networkID, active.ID)
	newEnv, err := e2ee.Encrypt([]byte("new content"), k2, newAAD)
	if err != nil {
		t.Fatalf("Encrypt new: %v", err)
	}
	if newEnv.KeyEpochID != e2.ID {
		t.Fatalf("new content epoch = %s, want %s", newEnv.KeyEpochID, e2.ID)
	}

	// Old ciphertext still decrypts with the OLD epoch (retained for history).
	if got, err := e2ee.Decrypt(oldEnv, k1, oldAAD); err != nil || string(got) != "old content" {
		t.Fatalf("old content decrypt = %q, %v", got, err)
	}
	// New ciphertext decrypts with the NEW epoch.
	if got, err := e2ee.Decrypt(newEnv, k2, newAAD); err != nil || string(got) != "new content" {
		t.Fatalf("new content decrypt = %q, %v", got, err)
	}
	// The old epoch can no longer open new content (different CEK wrap key).
	if _, err := e2ee.Decrypt(newEnv, k1, newAAD); err == nil {
		t.Fatal("new content decrypted with the old epoch key, want failure")
	}
}

// TestKeyringSaveLoad verifies the keyring round-trips through the 0600 file
// and that the file permission is 0600.
func TestKeyringSaveLoad(t *testing.T) {
	stateDir := t.TempDir()
	networkID := "01900000-0000-7000-8000-0000000000a2"
	kr := NewKeyring(networkID)
	if _, err := kr.Activate(testTime()); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if _, err := kr.Rotate(testTime().Add(time.Hour)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if err := SaveKeyring(stateDir, kr); err != nil {
		t.Fatalf("SaveKeyring: %v", err)
	}

	// Permission must be 0600 (the file holds epoch keys).
	path, _ := KeyringPath(stateDir, networkID)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat keyring: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("keyring file permission = %o, want 0600", perm)
	}

	loaded, err := LoadKeyring(stateDir, networkID)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if len(loaded.Epochs) != 2 {
		t.Fatalf("loaded %d epochs, want 2", len(loaded.Epochs))
	}
	// The epoch keys survive the round-trip.
	for _, e := range kr.Epochs {
		le, ok := loaded.EpochByID(e.ID)
		if !ok {
			t.Fatalf("loaded keyring missing epoch %s", e.ID)
		}
		if string(le.Key) != string(e.Key) {
			t.Fatalf("epoch %s key changed on round-trip", e.ID)
		}
	}
}

// TestKeyringPathRejectsTraversal verifies a non-UUID network id is refused
// before it can steer the filesystem path (SEC-407).
func TestKeyringPathRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"../../etc", "a/b", "..", "", "not-a-uuid"} {
		if _, err := KeyringPath(t.TempDir(), bad); err == nil {
			t.Errorf("KeyringPath(%q) succeeded, want refusal", bad)
		}
	}
}

// TestKeyringSaveOverwriteKeeps0600 verifies re-saving an existing keyring
// file keeps the 0600 permission (os.WriteFile alone would not tighten it).
func TestKeyringSaveOverwriteKeeps0600(t *testing.T) {
	stateDir := t.TempDir()
	networkID := "01900000-0000-7000-8000-0000000000a3"
	kr := NewKeyring(networkID)
	if _, err := kr.Activate(testTime()); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if err := SaveKeyring(stateDir, kr); err != nil {
		t.Fatalf("SaveKeyring: %v", err)
	}
	// Loosen the permission, then re-save; it must be tightened back to 0600.
	path, _ := KeyringPath(stateDir, networkID)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Rotate(testTime().Add(time.Hour)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := SaveKeyring(stateDir, kr); err != nil {
		t.Fatalf("SaveKeyring (2nd): %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("keyring file permission after re-save = %o, want 0600", perm)
	}
}

// TestActivateIdempotent verifies Activate returns the existing active epoch
// rather than minting a second one.
func TestActivateIdempotent(t *testing.T) {
	kr := NewKeyring("01900000-0000-7000-8000-0000000000a4")
	e1, err := kr.Activate(testTime())
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	e2, err := kr.Activate(testTime().Add(time.Hour))
	if err != nil {
		t.Fatalf("Activate (2nd): %v", err)
	}
	if e1.ID != e2.ID {
		t.Fatalf("Activate minted a second epoch (%s vs %s)", e1.ID, e2.ID)
	}
	if len(kr.Epochs) != 1 {
		t.Fatalf("keyring has %d epochs after double-activate, want 1", len(kr.Epochs))
	}
}

// TestRevoke verifies revoking an epoch changes its state.
func TestRevoke(t *testing.T) {
	kr := NewKeyring("01900000-0000-7000-8000-0000000000a5")
	e1, _ := kr.Activate(testTime())
	if err := kr.Revoke(e1.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revoked, _ := kr.EpochByID(e1.ID)
	if revoked.State != EpochRevoked {
		t.Fatalf("epoch state = %s, want %s", revoked.State, EpochRevoked)
	}
	if err := kr.Revoke("missing"); err == nil {
		t.Fatal("Revoke(missing) succeeded, want error")
	}
	// A revoked-only keyring has no active epoch.
	if _, err := kr.ActiveEpoch(); err == nil {
		t.Fatal("ActiveEpoch succeeded on a revoked-only keyring, want error")
	}
}

// TestKeyringStringOmitsKeys verifies the safe String() never leaks key
// material (it carries only the id, state, and timestamp).
func TestKeyringStringOmitsKeys(t *testing.T) {
	kr := NewKeyring("01900000-0000-7000-8000-0000000000a6")
	e, _ := kr.Activate(testTime())
	s := fmt.Sprintf("%s %s", kr, e)
	if !strings.Contains(s, e.ID) {
		t.Fatalf("String() = %q does not contain the epoch id %s", s, e.ID)
	}
	if strings.Contains(s, base64.StdEncoding.EncodeToString(e.Key)) {
		t.Fatalf("String() = %q leaks the epoch key", s)
	}
}
