package crypto

import (
	"testing"
	"time"
)

const (
	testTenantID  = "01900000-0000-7000-8000-0000000000b1"
	testNetworkID = "01900000-0000-7000-8000-0000000000b2"
	testNKAHost   = "host-nka"
	testNewHost   = "host-new"
)

// TestNKAEnrollmentFlow exercises the full customer-side enrollment:
// activate → build key package → new host opens it → issue challenge → new
// host proves decryption → NKA verifies (plan §11.7).
func TestNKAEnrollmentFlow(t *testing.T) {
	stateDir := t.TempDir()
	now := testTime()

	// (a) The NKA host activates the network (first key epoch).
	if _, err := ActivateNetwork(stateDir, testTenantID, testNetworkID, now); err != nil {
		t.Fatalf("ActivateNetwork: %v", err)
	}
	nka, err := NewNKA(stateDir, testTenantID, testNetworkID, testNKAHost)
	if err != nil {
		t.Fatalf("NewNKA: %v", err)
	}

	// The new host generates its own identity.
	newHost, err := NewHostIdentity()
	if err != nil {
		t.Fatalf("NewHostIdentity: %v", err)
	}

	// (b) The NKA builds an HPKE key package for the new host's public key.
	pkg, err := nka.BuildKeyPackage(newHost.X25519Pub)
	if err != nil {
		t.Fatalf("BuildKeyPackage: %v", err)
	}

	// The new host opens the package and obtains the keyring.
	kr, err := OpenKeyPackage(pkg, newHost.X25519Priv)
	if err != nil {
		t.Fatalf("OpenKeyPackage: %v", err)
	}
	if kr.NetworkID != testNetworkID {
		t.Fatalf("opened keyring network = %s, want %s", kr.NetworkID, testNetworkID)
	}
	if len(kr.Epochs) != 1 {
		t.Fatalf("opened keyring has %d epochs, want 1", len(kr.Epochs))
	}

	// (c) The NKA issues a decryption challenge.
	ch, err := nka.IssueChallenge(testNewHost, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	// The new host decrypts the challenge and returns its proof.
	proof, err := ComputeChallengeProof(kr, ch)
	if err != nil {
		t.Fatalf("ComputeChallengeProof: %v", err)
	}

	// The NKA verifies the proof.
	if err := nka.VerifyChallenge(ch, proof); err != nil {
		t.Fatalf("VerifyChallenge: %v", err)
	}
}

// TestNKAKeyPackageWrongHost verifies a key package cannot be opened by a
// different host (the server or another host cannot read the keyring).
func TestNKAKeyPackageWrongHost(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := ActivateNetwork(stateDir, testTenantID, testNetworkID, testTime()); err != nil {
		t.Fatalf("ActivateNetwork: %v", err)
	}
	nka, err := NewNKA(stateDir, testTenantID, testNetworkID, testNKAHost)
	if err != nil {
		t.Fatalf("NewNKA: %v", err)
	}
	alice, _ := NewHostIdentity()
	bob, _ := NewHostIdentity()

	pkg, err := nka.BuildKeyPackage(alice.X25519Pub)
	if err != nil {
		t.Fatalf("BuildKeyPackage: %v", err)
	}
	if _, err := OpenKeyPackage(pkg, bob.X25519Priv); err == nil {
		t.Fatal("Bob opened Alice's key package, want failure")
	}
}

// TestNKAChallengeWrongKeyring verifies a host WITHOUT the correct keyring
// cannot produce a valid proof (it cannot decrypt the challenge).
func TestNKAChallengeWrongKeyring(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := ActivateNetwork(stateDir, testTenantID, testNetworkID, testTime()); err != nil {
		t.Fatalf("ActivateNetwork: %v", err)
	}
	nka, err := NewNKA(stateDir, testTenantID, testNetworkID, testNKAHost)
	if err != nil {
		t.Fatalf("NewNKA: %v", err)
	}
	ch, err := nka.IssueChallenge(testNewHost, testTime())
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	// A host with a DIFFERENT keyring (different epoch keys) cannot decrypt.
	otherState := t.TempDir()
	if _, err := ActivateNetwork(otherState, testTenantID, testNetworkID, testTime()); err != nil {
		t.Fatalf("ActivateNetwork (other): %v", err)
	}
	otherNKA, err := NewNKA(otherState, testTenantID, testNetworkID, testNKAHost)
	if err != nil {
		t.Fatalf("NewNKA (other): %v", err)
	}
	if _, err := ComputeChallengeProof(otherNKA.Keyring(), ch); err == nil {
		t.Fatal("a host with the wrong keyring produced a challenge proof, want failure")
	}
}

// TestNKAChallengeSingleUse verifies a challenge is consumed after one
// verification (replay protection).
func TestNKAChallengeSingleUse(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := ActivateNetwork(stateDir, testTenantID, testNetworkID, testTime()); err != nil {
		t.Fatalf("ActivateNetwork: %v", err)
	}
	nka, err := NewNKA(stateDir, testTenantID, testNetworkID, testNKAHost)
	if err != nil {
		t.Fatalf("NewNKA: %v", err)
	}
	ch, err := nka.IssueChallenge(testNewHost, testTime())
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	proof, err := ComputeChallengeProof(nka.Keyring(), ch)
	if err != nil {
		t.Fatalf("ComputeChallengeProof: %v", err)
	}
	if err := nka.VerifyChallenge(ch, proof); err != nil {
		t.Fatalf("first VerifyChallenge: %v", err)
	}
	// Replaying the same challenge+proof must fail (consumed).
	if err := nka.VerifyChallenge(ch, proof); err == nil {
		t.Fatal("replayed challenge verified, want failure (single-use)")
	}
}

// TestNKARotateThenChallenge verifies a challenge issued after rotation uses
// the new epoch and a host with the rotated keyring can still verify.
func TestNKARotateThenChallenge(t *testing.T) {
	stateDir := t.TempDir()
	now := testTime()
	if _, err := ActivateNetwork(stateDir, testTenantID, testNetworkID, now); err != nil {
		t.Fatalf("ActivateNetwork: %v", err)
	}
	nka, err := NewNKA(stateDir, testTenantID, testNetworkID, testNKAHost)
	if err != nil {
		t.Fatalf("NewNKA: %v", err)
	}
	newHost, _ := NewHostIdentity()
	// Enroll the host under epoch 1.
	pkg, _ := nka.BuildKeyPackage(newHost.X25519Pub)
	kr, _ := OpenKeyPackage(pkg, newHost.X25519Priv)

	// Rotate to epoch 2 and re-issue the key package (a real deployment would
	// push the new epoch to enrolled hosts).
	if _, err := nka.Rotate(now.Add(time.Hour)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	pkg2, _ := nka.BuildKeyPackage(newHost.X25519Pub)
	kr2, _ := OpenKeyPackage(pkg2, newHost.X25519Priv)

	// A challenge now uses the new (epoch 2) key.
	ch, err := nka.IssueChallenge(testNewHost, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	if ch.Envelope.KeyEpochID == kr.Epochs[0].ID {
		t.Fatal("challenge used the old epoch after rotation")
	}
	// The host with the updated keyring verifies.
	proof, err := ComputeChallengeProof(kr2, ch)
	if err != nil {
		t.Fatalf("ComputeChallengeProof: %v", err)
	}
	if err := nka.VerifyChallenge(ch, proof); err != nil {
		t.Fatalf("VerifyChallenge: %v", err)
	}
	// The host with only the OLD keyring cannot verify the new-epoch challenge.
	if _, err := ComputeChallengeProof(kr, ch); err == nil {
		t.Fatal("old keyring verified a new-epoch challenge, want failure")
	}
}
