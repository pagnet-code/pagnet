package crypto

import (
	"testing"
)

// TestSelfTest verifies the client-side crypto round trip succeeds on an
// activated keyring.
func TestSelfTest(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := ActivateNetwork(stateDir, testTenantID, testNetworkID, testTime()); err != nil {
		t.Fatalf("ActivateNetwork: %v", err)
	}
	nka, err := NewNKA(stateDir, testTenantID, testNetworkID, testNKAHost)
	if err != nil {
		t.Fatalf("NewNKA: %v", err)
	}
	if err := SelfTest(nka.Keyring(), testTenantID, testNKAHost, testTime()); err != nil {
		t.Fatalf("SelfTest: %v", err)
	}
}

// TestSelfTestFailsWithoutActivation verifies the self-test fails on a
// keyring with no active epoch (nothing to encrypt under).
func TestSelfTestFailsWithoutActivation(t *testing.T) {
	kr := NewKeyring(testNetworkID)
	if err := SelfTest(kr, testTenantID, testNKAHost, testTime()); err == nil {
		t.Fatal("SelfTest succeeded on an unactivated keyring, want failure")
	}
}
