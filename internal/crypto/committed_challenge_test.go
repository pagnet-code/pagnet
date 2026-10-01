package crypto

import (
	"testing"
	"time"
)

func TestChallengeUsesAdmittedRetainedEpochAfterUncommittedRotation(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC()
	ring, err := ActivateNetwork(stateDir, testTenantID, testNetworkID, now)
	if err != nil {
		t.Fatal(err)
	}
	committed := ring.Epochs[0].ID
	nka, err := NewNKA(stateDir, testTenantID, testNetworkID, testNKAHost)
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := nka.BuildKeyPackage(target.X25519Pub)
	if err != nil {
		t.Fatal(err)
	}
	originalTargetRing, err := OpenKeyPackage(pkg, target.X25519Priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nka.Rotate(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	challenge, err := nka.IssueChallenge(testNewHost, committed, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Envelope.KeyEpochID != committed {
		t.Fatal("challenge used an uncommitted local candidate")
	}
	proof, err := ComputeChallengeProof(originalTargetRing, challenge)
	if err != nil {
		t.Fatal("target with the committed key cannot answer enrollment challenge", err)
	}
	if err := nka.VerifyChallenge(challenge, proof); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"", "missing"} {
		if _, err := nka.IssueChallenge(testNewHost, missing, now); err == nil {
			t.Fatal("missing epoch admitted")
		}
	}
	if err := nka.keyring.Revoke(committed); err != nil {
		t.Fatal(err)
	}
	if _, err := nka.IssueChallenge(testNewHost, committed, now); err == nil {
		t.Fatal("revoked epoch admitted")
	}
}
