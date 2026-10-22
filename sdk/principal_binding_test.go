package sdk

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExpectedPrincipalCredentialRotationPreservesIdentity(t *testing.T) {
	fs := newFakeServer(t)
	principal, activation := fs.createPrincipal("service", "bridge")
	stateDir := t.TempDir()
	connect := func(credential string) *Client {
		t.Helper()
		c, err := Connect(testCtx(t), Config{Server: fs.URL(), Credential: credential, StateDir: stateDir, ExpectedPrincipalID: principal})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	first := connect(activation)
	identity := append([]byte(nil), first.identityPriv...)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	freshActivation := "pgn_act_v1_rotated"
	fs.mu.Lock()
	fs.activationCreds[freshActivation] = principal
	fs.mu.Unlock()
	second := connect(freshActivation)
	if !bytes.Equal(identity, second.identityPriv) {
		t.Fatal("credential rotation changed live crypto identity")
	}
	stored, err := os.ReadFile(filepath.Join(stateDir, "principals", principal, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(identity, stored) {
		t.Fatal("credential rotation changed persisted crypto identity")
	}
	if credential, err := StoredCredential(stateDir, principal); err != nil || credential == "" || credential == freshActivation {
		t.Fatal("SDK did not persist durable rotated credential")
	}
}
func TestExpectedPrincipalRejectsWrongActivationWithoutPersistence(t *testing.T) {
	fs := newFakeServer(t)
	expected, activation := fs.createPrincipal("service", "expected")
	wrong, wrongActivation := fs.createPrincipal("service", "wrong")
	dir := t.TempDir()
	c, err := Connect(testCtx(t), Config{Server: fs.URL(), Credential: activation, StateDir: dir, ExpectedPrincipalID: expected})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "principals", expected, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	credentialBefore, err := StoredCredential(dir, expected)
	if err != nil {
		t.Fatal(err)
	}
	c, err = Connect(testCtx(t), Config{Server: fs.URL(), Credential: wrongActivation, StateDir: dir, ExpectedPrincipalID: expected})
	if c != nil {
		_ = c.Close()
		t.Fatal("wrong-principal activation connected")
	}
	if err == nil {
		t.Fatal("wrong-principal activation accepted")
	}
	after, err := os.ReadFile(filepath.Join(dir, "principals", expected, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("wrong-principal activation overwrote expected identity")
	}
	if credentialAfter, err := StoredCredential(dir, expected); err != nil || credentialBefore != credentialAfter {
		t.Fatal("wrong-principal activation overwrote expected credential")
	}
	if credential, err := StoredCredential(dir, wrong); err != nil || credential != "" {
		t.Fatal("wrong-principal activation persisted a credential")
	}
}
func TestExpectedPrincipalRejectsIndexedCredentialMismatch(t *testing.T) {
	kr := newTestKeyring(t)
	key, err := newIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.PersistIdentity("expected", "pgn_epd_v1_expected", key); err != nil {
		t.Fatal(err)
	}
	if err := kr.IndexCredential("pgn_act_v1_wrong", "wrong"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := kr.loadBoundIdentity("pgn_act_v1_wrong", "expected"); err == nil {
		t.Fatal("indexed credential crossed principal binding")
	}
}
