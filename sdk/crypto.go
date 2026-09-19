package sdk

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

// AAD conventions (V2 cutover). The AAD binds a protected object to its
// routing metadata; the control plane relays the AAD verbatim (the AAD
// server obligation) and GCM authentication fails if any bound field is
// altered in transit.
//
//   - ProtocolVersion is the CONTENT protocol version: transport.ProtocolVersion
//     (= 2) for all V2 objects. (The v1 daemon used 1; the V2 cutover moves
//     every content path to 2 — the daemon side of the cutover must match.)
//   - Sender / Recipient are PRINCIPAL ids ("" when the object has no
//     specific recipient, e.g. network-wide events).
//   - ObjectID is the object's id: client-generated UUIDv7 for messages and
//     events (the AAD binds object_id, so the id must exist at encryption
//     time — the server adopts the client-generated id); the
//     server-assigned invocation id for invocation objects.
//   - CreatedAt is RFC3339 UTC, taken from the UUIDv7's embedded timestamp
//     when the object id is a UUIDv7 (single clock source), else the wall
//     clock.
//   - KeyEpochID is the epoch the object is encrypted under.

// enrollmentInfo is the HPKE info context for endpoint crypto enrollment
// (plan D6): the host wraps the network epoch key under the endpoint's
// X25519 public key with EXACTLY this info. It is a binding cross-wave
// constant — the daemon side (W5) must use the same string.
const enrollmentInfo = "pagnet/endpoint-enrollment/epoch-wrap/v1"

// proofContext is the context bound into the challenge-proof MAC. It MUST
// match the host-side NKA verifier (internal/crypto: proofContext) — the
// endpoint enrollment reuses the host challenge/verify pattern (D6).
const proofContext = "pagnet/e2ee/challenge-proof/v1"

// newObjectID mints a client-generated UUIDv7 for a protected object.
func newObjectID() string {
	id, err := uuid.NewV7()
	if err != nil {
		id, _ = uuid.NewRandom()
	}
	return id.String()
}

// uuidV7Time extracts the Unix timestamp (ms) embedded in a UUIDv7.
func uuidV7Time(id string) (time.Time, bool) {
	u, err := uuid.Parse(id)
	if err != nil || u.Version() != 7 {
		return time.Time{}, false
	}
	ms := uint64(u[0])<<40 | uint64(u[1])<<32 | uint64(u[2])<<24 |
		uint64(u[3])<<16 | uint64(u[4])<<8 | uint64(u[5])
	return time.UnixMilli(int64(ms)).UTC(), true
}

// buildAAD builds the AAD for a protected object (see the file header for
// the conventions).
func (c *Client) buildAAD(networkID, objectType, objectID, sender, recipient, epochID string) e2ee.AAD {
	aad := e2ee.AAD{
		ProtocolVersion: transport.ProtocolVersion,
		TenantID:        c.tenantID.Load(),
		NetworkID:       networkID,
		ObjectType:      objectType,
		ObjectID:        objectID,
		Sender:          sender,
		Recipient:       recipient,
		KeyEpochID:      epochID,
	}
	if t, ok := uuidV7Time(objectID); ok {
		aad.CreatedAt = t.Format(time.RFC3339)
	} else {
		aad.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	return aad
}

// encryptObject encrypts plaintext under the network's ACTIVE epoch,
// returning the envelope + the AAD used (the server stores/relays both
// verbatim). The BINDING epoch rule: encrypt under the newest enrolled
// epoch; when none is enrolled the operation fails with
// ErrNetworkCryptoNotReady (never a plaintext fallback — networks are
// always encrypted, D6).
func (c *Client) encryptObject(networkID, objectType, objectID, sender, recipient string, plaintext []byte) (e2ee.EncryptedPayloadV1, e2ee.AAD, error) {
	key, epochID, err := c.kr.ActiveEpoch(networkID)
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	aad := c.buildAAD(networkID, objectType, objectID, sender, recipient, epochID)
	env, err := e2ee.Encrypt(plaintext, key, aad)
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, fmt.Errorf("sdk: encrypt %s: %w", objectType, err)
	}
	return env, aad, nil
}

// decryptObject decrypts an envelope with the epoch named by the envelope's
// key_epoch_id (ANY enrolled epoch — rotated epochs keep decrypting
// history). aad is the server-relayed AAD; if the server altered any bound
// field, GCM authentication fails.
func (c *Client) decryptObject(networkID string, env e2ee.EncryptedPayloadV1, aad e2ee.AAD) ([]byte, error) {
	key, err := c.kr.EpochKey(networkID, env.KeyEpochID)
	if err != nil {
		return nil, fmt.Errorf("sdk: %w: %s (enrollment may still be in flight)", ErrNetworkCryptoNotReady, err)
	}
	plain, err := e2ee.Decrypt(env, key, aad)
	if err != nil {
		return nil, fmt.Errorf("sdk: decrypt (AAD mismatch or wrong epoch key): %w", err)
	}
	return plain, nil
}

// --- crypto enrollment (plan D6) ---------------------------------------------
//
// Flow (server + host + SDK must match):
//  1. The endpoint announces its X25519 public key in endpoint.register
//     (stored on the participant_endpoints row, rotation-capable).
//  2. When the endpoint's principal has an active membership in a
//     crypto-active network, the server asks a ready crypto-authority host
//     (host.crypto_share_endpoint) to wrap the current epoch key under the
//     endpoint public key (HPKE base, info enrollmentInfo, no AAD,
//     plaintext = the raw 32-byte epoch key).
//  3. The server relays the wrap to the endpoint as
//     endpoint.crypto_key_package {networkId, epochId, wrappedKey{enc,
//     ciphertext}} — the server never sees key material.
//  4. The SDK unwraps with its X25519 private key, validates the epoch id,
//     and stores the epoch key in the local keyring.
//  5. The server relays a decryption challenge (issued by the host,
//     encrypted under the epoch key, AAD object type e2ee_challenge) as
//     endpoint.crypto_challenge {networkId, challenge, expectedProof}.
//  6. The SDK decrypts the challenge and proves possession:
//     proof.MAC = HMAC-SHA256(key = challenge plaintext,
//     msg = nonce || proofContext) — the SAME construction the host NKA
//     verifies (internal/crypto). The SDK sends endpoint.crypto_prove
//     {networkId, proof}; the server compares it to expectedProof and
//     marks the endpoint crypto-ready.

// handleCryptoKeyPackage unwraps a relayed epoch-key wrap and stores it.
func (c *Client) handleCryptoKeyPackage(p EndpointCryptoKeyPackagePayload) error {
	if p.NetworkID == "" || p.EpochID == "" {
		return fmt.Errorf("sdk: crypto_key_package missing networkId/epochId")
	}
	plain, err := e2ee.HPKEUnwrap(c.identityPriv, p.WrappedKey.Enc, []byte(enrollmentInfo), nil, p.WrappedKey.Ciphertext)
	if err != nil {
		return fmt.Errorf("sdk: unwrap epoch key for network %s (wrong identity key?): %w", p.NetworkID, err)
	}
	if len(plain) != 32 {
		return fmt.Errorf("sdk: unwrapped epoch key is %d bytes, want 32", len(plain))
	}
	var key [32]byte
	copy(key[:], plain)
	if err := c.kr.StoreEpoch(p.NetworkID, p.EpochID, key); err != nil {
		return err
	}
	c.markCryptoReady(p.NetworkID)
	// A challenge may have arrived before the key package: answer it now.
	if ch, ok := c.takePendingChallenge(p.NetworkID); ok {
		if err := c.answerChallenge(p.NetworkID, ch); err != nil {
			return err
		}
	}
	return nil
}

// handleCryptoChallenge proves possession of the epoch key. When the epoch
// key is not enrolled yet (key package in flight), the challenge is queued
// and answered when the key package lands.
func (c *Client) handleCryptoChallenge(p EndpointCryptoChallengePayload) error {
	if p.NetworkID == "" {
		return fmt.Errorf("sdk: crypto_challenge missing networkId")
	}
	if _, err := c.kr.EpochKey(p.NetworkID, p.Challenge.Envelope.KeyEpochID); err == nil {
		return c.answerChallenge(p.NetworkID, p)
	}
	c.pendingMu.Lock()
	c.pendingChallenges[p.NetworkID] = p
	c.pendingMu.Unlock()
	return nil
}

// answerChallenge decrypts the challenge and sends the proof.
func (c *Client) answerChallenge(networkID string, p EndpointCryptoChallengePayload) error {
	plain, err := c.decryptObject(networkID, p.Challenge.Envelope, p.Challenge.AAD)
	if err != nil {
		return fmt.Errorf("sdk: decrypt enrollment challenge: %w", err)
	}
	mac := challengeMAC(plain, p.Challenge.Nonce)
	proof := e2ee.Proof{MAC: mac}
	if err := c.send(MsgEndpointCryptoProve, EndpointCryptoProvePayload{
		NetworkID: networkID,
		Proof:     proof,
	}); err != nil {
		return fmt.Errorf("sdk: send crypto prove: %w", err)
	}
	c.markCryptoReady(networkID)
	return nil
}

// challengeMAC computes the proof MAC: HMAC-SHA256 keyed by the challenge
// plaintext, over (nonce || proofContext). MUST match the host NKA
// verifier (internal/crypto challengeMAC).
func challengeMAC(challengePlaintext, nonce []byte) []byte {
	mac := hmac.New(sha256.New, challengePlaintext)
	mac.Write(nonce)
	mac.Write([]byte(proofContext))
	return mac.Sum(nil)
}

// takePendingChallenge removes and returns a queued challenge for a network.
func (c *Client) takePendingChallenge(networkID string) (EndpointCryptoChallengePayload, bool) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	ch, ok := c.pendingChallenges[networkID]
	if ok {
		delete(c.pendingChallenges, networkID)
	}
	return ch, ok
}

// markCryptoReady records that the endpoint has enrolled + proved for a
// network (NetworkInfo.CryptoReady).
func (c *Client) markCryptoReady(networkID string) {
	c.cryptoMu.Lock()
	c.cryptoReadySet[networkID] = true
	c.cryptoMu.Unlock()
}

// cryptoReady reports the enrollment state for a network.
func (c *Client) cryptoReady(networkID string) bool {
	c.cryptoMu.Lock()
	defer c.cryptoMu.Unlock()
	return c.cryptoReadySet[networkID]
}
