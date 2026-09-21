package sdk

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestKeyring(t *testing.T) *keyring {
	t.Helper()
	kr, err := newKeyring(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Mode().Perm()
}

func TestKeyringIdentityPersistAndLoad(t *testing.T) {
	kr := newTestKeyring(t)
	priv, err := newIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.PersistIdentity("principal-1", "pgn_epd_v1_c1", priv); err != nil {
		t.Fatal(err)
	}
	// Identity key file exists and is 0600.
	idPath := kr.identityPath("principal-1")
	if got := fileMode(t, idPath); got != 0o600 {
		t.Fatalf("identity.key mode = %o, want 600", got)
	}
	// Credential file exists and is 0600.
	credPath := kr.credentialPath("principal-1")
	if got := fileMode(t, credPath); got != 0o600 {
		t.Fatalf("credential mode = %o, want 600", got)
	}
	// The principal dir is 0700.
	dirMode := fileMode(t, filepath.Join(kr.root, "principal-1"))
	if dirMode != 0o700 {
		t.Fatalf("principal dir mode = %o, want 700", dirMode)
	}
	// Load round-trips the same private key.
	got, principalID, err := kr.loadOrCreateIdentity("pgn_epd_v1_c1")
	if err != nil {
		t.Fatal(err)
	}
	if principalID != "principal-1" {
		t.Fatalf("principalID = %q", principalID)
	}
	if string(got) != string(priv) {
		t.Fatal("loaded identity key differs from persisted key")
	}
}

func TestKeyringFreshIdentityWhenUnknown(t *testing.T) {
	kr := newTestKeyring(t)
	priv, principalID, err := kr.loadOrCreateIdentity("pgn_epd_v1_unknown")
	if err != nil {
		t.Fatal(err)
	}
	if principalID != "" {
		t.Fatalf("principalID = %q, want empty for unknown credential", principalID)
	}
	if len(priv) != 32 {
		t.Fatalf("fresh identity key is %d bytes, want 32", len(priv))
	}
}

func TestKeyringCredentialLookup(t *testing.T) {
	kr := newTestKeyring(t)
	priv, _ := newIdentityKey()
	if err := kr.PersistIdentity("p1", "pgn_epd_v1_c1", priv); err != nil {
		t.Fatal(err)
	}
	if got, err := kr.CredentialForPrincipal("p1"); err != nil || got != "pgn_epd_v1_c1" {
		t.Fatalf("CredentialForPrincipal = %q, %v", got, err)
	}
	// CredentialForCredential resolves the durable credential for the same
	// principal (the activation-fallback path).
	if got, err := kr.CredentialForCredential("pgn_epd_v1_c1"); err != nil || got != "pgn_epd_v1_c1" {
		t.Fatalf("CredentialForCredential = %q, %v", got, err)
	}
	// An indexed-but-not-durable credential (activation) also resolves.
	if err := kr.IndexCredential("pgn_act_v1_act1", "p1"); err != nil {
		t.Fatal(err)
	}
	if got, err := kr.CredentialForCredential("pgn_act_v1_act1"); err != nil || got != "pgn_epd_v1_c1" {
		t.Fatalf("CredentialForCredential(activation) = %q, %v", got, err)
	}
}

// TestStoredPrincipalReadWindow pins the exported read window the CLI's
// principal-actor commands use: the credential for one principal, and the list
// of principals the store can actually ACT as (a directory with an identity key
// but no credential is not an actor, and "networks" is the shared epoch-key
// directory rather than a principal).
func TestStoredPrincipalReadWindow(t *testing.T) {
	dir := t.TempDir()

	// An empty store is an ordinary state, not an error.
	ids, err := StoredPrincipalIDs(dir)
	if err != nil {
		t.Fatalf("StoredPrincipalIDs on an empty store: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("empty store lists %v, want none", ids)
	}
	if cred, err := StoredCredential(dir, "p1"); err != nil || cred != "" {
		t.Fatalf("StoredCredential = %q (%v), want empty for an unknown principal", cred, err)
	}

	kr, err := newKeyring(dir)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := newIdentityKey()
	if err := kr.PersistIdentity("p1", "pgn_epd_v1_c1", priv); err != nil {
		t.Fatal(err)
	}
	if err := kr.PersistIdentity("p2", "pgn_epd_v1_c2", priv); err != nil {
		t.Fatal(err)
	}
	// A principal with an identity key but no stored credential cannot act, so
	// it must not be offered as a choice.
	if err := os.MkdirAll(filepath.Dir(kr.identityPath("p3")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(kr.identityPath("p3"), priv); err != nil {
		t.Fatal(err)
	}
	// The shared epoch directory must never look like a principal.
	if err := kr.StoreEpoch("net-1", "e1", [32]byte{}); err != nil {
		t.Fatal(err)
	}

	got, err := StoredPrincipalIDs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "p2" || got[1] != "p1" {
		t.Fatalf("StoredPrincipalIDs = %v, want [p2 p1] (newest first, no credential-less principal, no networks dir)", got)
	}
	if cred, err := StoredCredential(dir, "p2"); err != nil || cred != "pgn_epd_v1_c2" {
		t.Fatalf("StoredCredential(p2) = %q (%v), want pgn_epd_v1_c2", cred, err)
	}
	if cred, err := StoredCredential(dir, "p3"); err != nil || cred != "" {
		t.Fatalf("StoredCredential(p3) = %q (%v), want empty", cred, err)
	}
}

func TestKeyringEpochStoreAndActive(t *testing.T) {
	kr := newTestKeyring(t)
	var old, newer [32]byte
	for i := range old {
		old[i] = byte(i)
	}
	for i := range newer {
		newer[i] = byte(i + 100)
	}
	// UUIDv7-style ids: lexicographic order == time order.
	if err := kr.StoreEpoch("net1", "01900000-0000-7000-8000-000000000001", old); err != nil {
		t.Fatal(err)
	}
	if err := kr.StoreEpoch("net1", "01900000-0000-7000-8000-000000000002", newer); err != nil {
		t.Fatal(err)
	}
	key, epochID, err := kr.ActiveEpoch("net1")
	if err != nil {
		t.Fatal(err)
	}
	if epochID != "01900000-0000-7000-8000-000000000002" {
		t.Fatalf("ActiveEpoch id = %q, want the newer", epochID)
	}
	if key != newer {
		t.Fatal("ActiveEpoch key should be the newer epoch's key")
	}
	// Both epochs remain decryptable (history).
	if _, err := kr.EpochKey("net1", "01900000-0000-7000-8000-000000000001"); err != nil {
		t.Fatalf("old epoch should still be loadable: %v", err)
	}
}

func TestKeyringEpochLazyLoad(t *testing.T) {
	dir := t.TempDir()
	kr1, _ := newKeyring(dir)
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	if err := kr1.StoreEpoch("net1", "epoch-1", key); err != nil {
		t.Fatal(err)
	}
	// A NEW keyring over the same root (simulates a process restart): the
	// in-memory cache is empty, so EpochKeys must lazy-load from disk.
	kr2, _ := newKeyring(dir)
	epochs, err := kr2.EpochKeys("net1")
	if err != nil {
		t.Fatal(err)
	}
	if epochs["epoch-1"] != key {
		t.Fatal("lazy-loaded epoch key does not match the stored key")
	}
}

func TestKeyringPerPrincipalIsolation(t *testing.T) {
	kr := newTestKeyring(t)
	priv1, _ := newIdentityKey()
	priv2, _ := newIdentityKey()
	if err := kr.PersistIdentity("p1", "pgn_epd_v1_c1", priv1); err != nil {
		t.Fatal(err)
	}
	if err := kr.PersistIdentity("p2", "pgn_epd_v1_c2", priv2); err != nil {
		t.Fatal(err)
	}
	// Each credential resolves to its own principal + identity.
	if _, pid, _ := kr.loadOrCreateIdentity("pgn_epd_v1_c1"); pid != "p1" {
		t.Fatalf("c1 resolved to %q", pid)
	}
	if _, pid, _ := kr.loadOrCreateIdentity("pgn_epd_v1_c2"); pid != "p2" {
		t.Fatalf("c2 resolved to %q", pid)
	}
	// Distinct identity files.
	if fileMode(t, kr.identityPath("p1")) != 0o600 || fileMode(t, kr.identityPath("p2")) != 0o600 {
		t.Fatal("identity files must be 0600")
	}
}

func TestKeyringNoEpochForUnknownNetwork(t *testing.T) {
	kr := newTestKeyring(t)
	if _, _, err := kr.ActiveEpoch("nope"); err == nil {
		t.Fatal("ActiveEpoch for a network with no epochs should error")
	}
}
