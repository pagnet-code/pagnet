package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
)

// NKA is the Network Key Authority: a role played by an online customer-side
// host (plan §11.7), not a server component. It manages the network keyring
// and enrolls new hosts. The control plane only relays the opaque HPKE key
// package and the decryption challenge — it never sees key material.
//
// An NKA instance must stay alive across an enrollment round-trip (issue
// challenge → verify proof): the challenge plaintexts are held in memory so
// the proof can be verified (see IssueChallenge).
type NKA struct {
	TenantID  string
	NetworkID string
	// HostID is this NKA host's id (the sender of challenges).
	HostID string

	stateDir string
	keyring  *Keyring

	challengesMu sync.Mutex
	// challenges maps a challenge object id to its (random) plaintext and
	// creation time, so VerifyChallenge can check the host's proof.
	// Single-use: consumed on verify. The map is bounded (challengeTTL +
	// challengeCap) so an abandoned enrollment round (a host that never
	// proves) cannot leak entries in the long-lived per-network NKA cache.
	challenges map[string]challengeEntry
}

// challengeEntry is a pending decryption challenge: the random plaintext the
// host must decrypt, plus its creation time (for TTL pruning).
type challengeEntry struct {
	plaintext []byte
	createdAt time.Time
}

// challengeTTL bounds how long an unconsumed challenge is remembered. A host
// that is issued a challenge but never proves (abandoned round) leaves no
// residue past this window.
const challengeTTL = 10 * time.Minute

// challengeCap bounds the number of pending challenges the NKA holds at once
// (a burst of concurrent enrollments must not grow the map without bound);
// the oldest entries are dropped first.
const challengeCap = 32

// NewNKA loads the NKA for a network. The keyring must already exist on disk
// (create it with ActivateNetwork).
func NewNKA(stateDir, tenantID, networkID, hostID string) (*NKA, error) {
	kr, err := LoadKeyring(stateDir, networkID)
	if err != nil {
		return nil, err
	}
	return &NKA{
		TenantID:   tenantID,
		NetworkID:  networkID,
		HostID:     hostID,
		stateDir:   stateDir,
		keyring:    kr,
		challenges: map[string]challengeEntry{},
	}, nil
}

// ActivateNetwork creates the keyring and first key epoch for a network
// (private-network activation, plan §11.6). It is idempotent: an existing
// active epoch is left unchanged.
func ActivateNetwork(stateDir, tenantID, networkID string, now time.Time) (*Keyring, error) {
	kr, err := LoadKeyring(stateDir, networkID)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		kr = NewKeyring(networkID)
	}
	if _, err := kr.Activate(now); err != nil {
		return nil, err
	}
	if err := SaveKeyring(stateDir, kr); err != nil {
		return nil, err
	}
	return kr, nil
}

// Keyring returns the NKA's keyring. Callers must not mutate it directly;
// use the NKA methods (which persist).
func (n *NKA) Keyring() *Keyring { return n.keyring }

// Activate creates the first key epoch if the keyring is not yet activated,
// and persists it. Idempotent.
func (n *NKA) Activate(now time.Time) (KeyEpoch, error) {
	epoch, err := n.keyring.Activate(now)
	if err != nil {
		return KeyEpoch{}, err
	}
	if err := SaveKeyring(n.stateDir, n.keyring); err != nil {
		return KeyEpoch{}, err
	}
	return epoch, nil
}

// Rotate mints a new active epoch, marks the previous one rotated, and
// persists (plan §11.8). New content uses the new epoch; the old epoch is
// retained to read history.
func (n *NKA) Rotate(now time.Time) (KeyEpoch, error) {
	epoch, err := n.keyring.Rotate(now)
	if err != nil {
		return KeyEpoch{}, err
	}
	if err := SaveKeyring(n.stateDir, n.keyring); err != nil {
		return KeyEpoch{}, err
	}
	return epoch, nil
}

// keyPackageInfo is the HPKE info context for key packages, binding the
// package to the network.
func keyPackageInfo(networkID string) []byte {
	return []byte("pagnet/e2ee/keypackage/v1/" + networkID)
}

// BuildKeyPackage wraps the current keyring to the new host's X25519 public
// key using HPKE. Only that host can open it. The returned e2ee.KeyPackage is
// the wire type the control plane relays opaquely (plan §11.7).
func (n *NKA) BuildKeyPackage(hostPub []byte) (*e2ee.KeyPackage, error) {
	keyringJSON, err := json.Marshal(n.keyring)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal keyring for package: %w", err)
	}
	info := keyPackageInfo(n.NetworkID)
	enc, ct, err := WrapKey(hostPub, info, nil, keyringJSON)
	if err != nil {
		return nil, err
	}
	return &e2ee.KeyPackage{Enc: enc, Ciphertext: ct, Info: info}, nil
}

// OpenKeyPackage unwraps a key package with the host's X25519 private key,
// returning the network keyring. This is the new-host side of enrollment.
func OpenKeyPackage(pkg *e2ee.KeyPackage, hostPriv []byte) (*Keyring, error) {
	keyringJSON, err := OpenKey(hostPriv, pkg.Enc, pkg.Info, nil, pkg.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("crypto: open key package: %w", err)
	}
	var kr Keyring
	if err := json.Unmarshal(keyringJSON, &kr); err != nil {
		return nil, fmt.Errorf("crypto: parse keyring from package: %w", err)
	}
	return &kr, nil
}

// challengeObjectType is the AAD object type for decryption challenges.
const challengeObjectType = "e2ee_challenge"

// IssueChallenge creates a decryption challenge under the current epoch. The
// NKA remembers the challenge plaintext (in memory) so it can verify the
// host's proof later. The returned e2ee.Challenge is the wire type the
// control plane relays opaquely (plan §11.7 step 7).
func (n *NKA) IssueChallenge(newHostID string, now time.Time) (*e2ee.Challenge, error) {
	epoch, err := n.keyring.ActiveEpoch()
	if err != nil {
		return nil, err
	}
	epochKey, err := epoch.KeyArray()
	if err != nil {
		return nil, err
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("crypto: read challenge: %w", err)
	}
	objectID := string(domain.NewID())
	aad := e2ee.AAD{
		ProtocolVersion: e2ee.AADVersion,
		TenantID:        n.TenantID,
		NetworkID:       n.NetworkID,
		ObjectType:      challengeObjectType,
		ObjectID:        objectID,
		Sender:          n.HostID,
		Recipient:       newHostID,
		CreatedAt:       now.UTC().Format(time.RFC3339),
		KeyEpochID:      epoch.ID,
	}
	env, err := e2ee.Encrypt(challenge, epochKey, aad)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: read challenge nonce: %w", err)
	}
	n.challengesMu.Lock()
	n.purgeChallenges(now)
	n.challenges[objectID] = challengeEntry{plaintext: challenge, createdAt: now}
	n.enforceChallengeCap()
	n.challengesMu.Unlock()
	return &e2ee.Challenge{Envelope: env, AAD: aad, Nonce: nonce}, nil
}

// purgeChallenges drops challenge entries older than challengeTTL. The
// caller holds challengesMu.
func (n *NKA) purgeChallenges(now time.Time) {
	cutoff := now.Add(-challengeTTL)
	for id, e := range n.challenges {
		if e.createdAt.Before(cutoff) {
			delete(n.challenges, id)
		}
	}
}

// enforceChallengeCap bounds the challenge map at challengeCap entries,
// dropping the oldest first. The caller holds challengesMu.
func (n *NKA) enforceChallengeCap() {
	if len(n.challenges) <= challengeCap {
		return
	}
	type kv struct {
		id string
		at time.Time
	}
	entries := make([]kv, 0, len(n.challenges))
	for id, e := range n.challenges {
		entries = append(entries, kv{id: id, at: e.createdAt})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].at.Before(entries[j].at) })
	excess := len(n.challenges) - challengeCap
	for i := 0; i < excess; i++ {
		delete(n.challenges, entries[i].id)
	}
}

// proofContext is the context bound into the challenge-proof MAC.
const proofContext = "pagnet/e2ee/challenge-proof/v1"

// ComputeChallengeProof decrypts the challenge with the host's keyring and
// returns the proof. This is the new-host side of the challenge. The returned
// e2ee.Proof is the wire type the control plane relays opaquely.
func ComputeChallengeProof(kr *Keyring, ch *e2ee.Challenge) (*e2ee.Proof, error) {
	epoch, ok := kr.EpochByID(ch.Envelope.KeyEpochID)
	if !ok {
		return nil, fmt.Errorf("crypto: keyring has no epoch %s", ch.Envelope.KeyEpochID)
	}
	epochKey, err := epoch.KeyArray()
	if err != nil {
		return nil, err
	}
	plaintext, err := e2ee.Decrypt(ch.Envelope, epochKey, ch.AAD)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt challenge: %w", err)
	}
	return &e2ee.Proof{MAC: challengeMAC(plaintext, ch.Nonce)}, nil
}

// VerifyChallenge checks the new host's proof against the remembered
// challenge plaintext. The challenge is single-use: it is consumed whether or
// not the proof is valid.
func (n *NKA) VerifyChallenge(ch *e2ee.Challenge, proof *e2ee.Proof) error {
	n.challengesMu.Lock()
	n.purgeChallenges(time.Now().UTC())
	entry, ok := n.challenges[ch.AAD.ObjectID]
	delete(n.challenges, ch.AAD.ObjectID)
	n.challengesMu.Unlock()
	if !ok {
		return fmt.Errorf("crypto: unknown or already-consumed challenge %s", ch.AAD.ObjectID)
	}
	expected := challengeMAC(entry.plaintext, ch.Nonce)
	if !hmac.Equal(proof.MAC, expected) {
		return fmt.Errorf("crypto: challenge proof MAC mismatch")
	}
	return nil
}

// challengeMAC computes the proof MAC: HMAC-SHA256 keyed by the challenge
// plaintext, over (nonce || context).
func challengeMAC(challengePlaintext, nonce []byte) []byte {
	mac := hmac.New(sha256.New, challengePlaintext)
	mac.Write(nonce)
	mac.Write([]byte(proofContext))
	return mac.Sum(nil)
}
