package daemon

import (
	"encoding/base64"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

// newCryptoDaemon builds a daemon backed by a fresh temp state dir. The crypto
// handlers only need StateDir + stateID, so no adapters or roots are required.
func newCryptoDaemon(t *testing.T) *Daemon {
	t.Helper()
	d, err := New(Config{StateDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// TestCryptoEnrollmentRoundTrip exercises the full 5-leg enrollment relay
// (plan §11.7) between two real daemons: the NKA host (activates + enrolls)
// and the target host (opens the key package, proves). It verifies the
// daemon-side handlers produce a valid key package → install → challenge →
// prove → verify round trip, and that the target's keyring is persisted.
func TestCryptoEnrollmentRoundTrip(t *testing.T) {
	tenantID := "tenant-1"
	networkID := string(domain.NewID())
	targetHostID := "target-host"

	ka := newCryptoDaemon(t) // NKA host
	tb := newCryptoDaemon(t) // enrolling target

	// The target's stable identity seals the key package.
	targetID, err := tb.cryptoManager().hostIdentity()
	if err != nil {
		t.Fatalf("target hostIdentity: %v", err)
	}
	targetX25519Pub := base64.StdEncoding.EncodeToString(targetID.X25519Pub)

	// Activation on the NKA host: first epoch + self-test.
	actRes, err := ka.doCryptoActivate(transport.CryptoActivatePayload{
		TenantID: tenantID, NetworkID: networkID,
	})
	if err != nil {
		t.Fatalf("doCryptoActivate: %v", err)
	}
	act, ok := actRes.(*transport.CryptoActivateResult)
	if !ok {
		t.Fatalf("activate result type = %T", actRes)
	}
	if !act.SelfTestOK {
		t.Fatalf("self-test did not pass")
	}
	if act.EpochID == "" {
		t.Fatalf("empty epoch id")
	}
	if act.HostPub.X25519 == "" || act.HostPub.Ed25519 == "" {
		t.Fatalf("activation result missing public identity")
	}

	// Leg 1: key package (NKA → sealed to the target's X25519 public key).
	kpRes, err := ka.doCryptoKeyPackage(transport.CryptoKeyPackagePayload{
		TenantID: tenantID, NetworkID: networkID,
		TargetHostID: targetHostID, TargetX25519Pub: targetX25519Pub,
	})
	if err != nil {
		t.Fatalf("doCryptoKeyPackage: %v", err)
	}
	kp := kpRes.(*transport.CryptoKeyPackageResult)

	// Leg 2: install (target opens the package, stores the keyring).
	if _, err := tb.doCryptoInstallKeyPackage(transport.CryptoInstallKeyPackagePayload{
		TenantID: tenantID, NetworkID: networkID, KeyPackage: kp.KeyPackage,
	}); err != nil {
		t.Fatalf("doCryptoInstallKeyPackage: %v", err)
	}

	// The target's keyring must be persisted on disk (survives restarts).
	if _, err := crypto.LoadKeyring(tb.StateDir, networkID); err != nil {
		t.Fatalf("target keyring not persisted: %v", err)
	}

	// Leg 3: challenge (NKA issues for the target).
	chRes, err := ka.doCryptoChallenge(transport.CryptoChallengePayload{
		TenantID: tenantID, NetworkID: networkID, TargetHostID: targetHostID,
	})
	if err != nil {
		t.Fatalf("doCryptoChallenge: %v", err)
	}
	ch := chRes.(*transport.CryptoChallengeResult)

	// Leg 4: prove (target decrypts the challenge with its keyring).
	proofRes, err := tb.doCryptoProve(transport.CryptoProvePayload{
		TenantID: tenantID, NetworkID: networkID, Challenge: ch.Challenge,
	})
	if err != nil {
		t.Fatalf("doCryptoProve: %v", err)
	}
	proof := proofRes.(*transport.CryptoProveResult)

	// Leg 5: verify (NKA checks the proof against the remembered plaintext).
	if _, err := ka.doCryptoVerify(transport.CryptoVerifyPayload{
		TenantID: tenantID, NetworkID: networkID,
		Challenge: ch.Challenge, Proof: proof.Proof,
	}); err != nil {
		t.Fatalf("doCryptoVerify: %v", err)
	}
}

// TestCryptoVerify_RejectsReplayedChallenge: the challenge is single-use. A
// second verify with the same (already-consumed) challenge must fail, so a
// captured proof cannot be replayed against a re-issued leg-5 command.
func TestCryptoVerify_RejectsReplayedChallenge(t *testing.T) {
	tenantID := "tenant-1"
	networkID := string(domain.NewID())
	targetHostID := "target-host"

	ka := newCryptoDaemon(t)
	tb := newCryptoDaemon(t)
	targetID, _ := tb.cryptoManager().hostIdentity()
	targetX25519Pub := base64.StdEncoding.EncodeToString(targetID.X25519Pub)

	if _, err := ka.doCryptoActivate(transport.CryptoActivatePayload{
		TenantID: tenantID, NetworkID: networkID,
	}); err != nil {
		t.Fatalf("doCryptoActivate: %v", err)
	}
	kpRes, err := ka.doCryptoKeyPackage(transport.CryptoKeyPackagePayload{
		TenantID: tenantID, NetworkID: networkID,
		TargetHostID: targetHostID, TargetX25519Pub: targetX25519Pub,
	})
	if err != nil {
		t.Fatalf("doCryptoKeyPackage: %v", err)
	}
	kp := kpRes.(*transport.CryptoKeyPackageResult)
	if _, err := tb.doCryptoInstallKeyPackage(transport.CryptoInstallKeyPackagePayload{
		TenantID: tenantID, NetworkID: networkID, KeyPackage: kp.KeyPackage,
	}); err != nil {
		t.Fatalf("doCryptoInstallKeyPackage: %v", err)
	}
	chRes, err := ka.doCryptoChallenge(transport.CryptoChallengePayload{
		TenantID: tenantID, NetworkID: networkID, TargetHostID: targetHostID,
	})
	if err != nil {
		t.Fatalf("doCryptoChallenge: %v", err)
	}
	ch := chRes.(*transport.CryptoChallengeResult)
	proofRes, err := tb.doCryptoProve(transport.CryptoProvePayload{
		TenantID: tenantID, NetworkID: networkID, Challenge: ch.Challenge,
	})
	if err != nil {
		t.Fatalf("doCryptoProve: %v", err)
	}
	proof := proofRes.(*transport.CryptoProveResult)

	// First verify consumes the challenge and succeeds.
	if _, err := ka.doCryptoVerify(transport.CryptoVerifyPayload{
		TenantID: tenantID, NetworkID: networkID,
		Challenge: ch.Challenge, Proof: proof.Proof,
	}); err != nil {
		t.Fatalf("first doCryptoVerify: %v", err)
	}
	// Replaying the same challenge must fail (single-use).
	if _, err := ka.doCryptoVerify(transport.CryptoVerifyPayload{
		TenantID: tenantID, NetworkID: networkID,
		Challenge: ch.Challenge, Proof: proof.Proof,
	}); err == nil {
		t.Fatalf("replayed challenge accepted; want single-use refusal")
	}
}

// TestCryptoRotate mints a new epoch on the NKA host (plan §11.8): the new
// epoch id differs from the activation epoch, and a subsequent key package is
// sealed under the new keyring (the old epoch is retained, not destroyed).
func TestCryptoRotate(t *testing.T) {
	tenantID := "tenant-1"
	networkID := string(domain.NewID())

	ka := newCryptoDaemon(t)
	act, err := ka.doCryptoActivate(transport.CryptoActivatePayload{
		TenantID: tenantID, NetworkID: networkID,
	})
	if err != nil {
		t.Fatalf("doCryptoActivate: %v", err)
	}
	firstEpoch := act.(*transport.CryptoActivateResult).EpochID

	rot, err := ka.doCryptoRotate(transport.CryptoRotatePayload{
		TenantID: tenantID, NetworkID: networkID,
	})
	if err != nil {
		t.Fatalf("doCryptoRotate: %v", err)
	}
	newEpoch := rot.(*transport.CryptoRotateResult).EpochID
	if newEpoch == "" || newEpoch == firstEpoch {
		t.Fatalf("rotation epoch = %q, want a fresh id != %q", newEpoch, firstEpoch)
	}

	// The keyring now has two epochs: the original (rotated) + the new (active).
	kr, err := crypto.LoadKeyring(ka.StateDir, networkID)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if len(kr.Epochs) != 2 {
		t.Fatalf("keyring has %d epochs, want 2 (old retained + new)", len(kr.Epochs))
	}
	active, err := kr.ActiveEpoch()
	if err != nil {
		t.Fatalf("ActiveEpoch: %v", err)
	}
	if active.ID != newEpoch {
		t.Fatalf("active epoch = %q, want %q", active.ID, newEpoch)
	}
}

// TestCryptoActivate_IsIdempotent: re-activating an already-active network
// returns the same epoch (no second epoch is minted), so a re-sent
// host.crypto_activate (reconnect re-dispatch) is a no-op.
func TestCryptoActivate_IsIdempotent(t *testing.T) {
	tenantID := "tenant-1"
	networkID := string(domain.NewID())

	ka := newCryptoDaemon(t)
	first, err := ka.doCryptoActivate(transport.CryptoActivatePayload{
		TenantID: tenantID, NetworkID: networkID,
	})
	if err != nil {
		t.Fatalf("first doCryptoActivate: %v", err)
	}
	second, err := ka.doCryptoActivate(transport.CryptoActivatePayload{
		TenantID: tenantID, NetworkID: networkID,
	})
	if err != nil {
		t.Fatalf("second doCryptoActivate: %v", err)
	}
	if first.(*transport.CryptoActivateResult).EpochID != second.(*transport.CryptoActivateResult).EpochID {
		t.Fatalf("re-activation minted a new epoch: %q != %q",
			second.(*transport.CryptoActivateResult).EpochID,
			first.(*transport.CryptoActivateResult).EpochID)
	}
}
