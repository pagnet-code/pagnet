package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	// challenges maps a challenge object id to its (random) plaintext, so
	// VerifyChallenge can check the host's proof. Single-use: consumed on
	// verify.
	challenges map[string][]byte
}

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
		challenges: map[string][]byte{},
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

// KeyPackage is the HPKE-encrypted keyring for a new host. The control plane
// stores/relays only these opaque bytes (plan §11.7).
type KeyPackage struct {
	// Enc is the HPKE encapsulated (ephemeral) key.
	Enc []byte `json:"enc"`
	// Ciphertext is the HPKE-sealed keyring.
	Ciphertext []byte `json:"ciphertext"`
	// Info is the HPKE info context (public).
	Info []byte `json:"info"`
}

// BuildKeyPackage wraps the current keyring to the new host's X25519 public
// key using HPKE. Only that host can open it.
func (n *NKA) BuildKeyPackage(hostPub []byte) (*KeyPackage, error) {
	keyringJSON, err := json.Marshal(n.keyring)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal keyring for package: %w", err)
	}
	info := keyPackageInfo(n.NetworkID)
	enc, ct, err := WrapKey(hostPub, info, nil, keyringJSON)
	if err != nil {
		return nil, err
	}
	return &KeyPackage{Enc: enc, Ciphertext: ct, Info: info}, nil
}

// OpenKeyPackage unwraps a key package with the host's X25519 private key,
// returning the network keyring. This is the new-host side of enrollment.
func OpenKeyPackage(pkg *KeyPackage, hostPriv []byte) (*Keyring, error) {
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

// Challenge is a decryption challenge: a random value encrypted under the
// keyring, which the new host must decrypt and MAC to prove it holds the
// keys (plan §11.7 step 7). The Challenge is safe to relay: it carries no
// plaintext or key material.
type Challenge struct {
	// Envelope is the encrypted challenge (e2ee.EncryptedPayloadV1).
	Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
	// AAD is the AAD used to encrypt the challenge (public routing metadata).
	AAD e2ee.AAD `json:"aad"`
	// Nonce is a random nonce the host must include in its proof (replay
	// protection).
	Nonce []byte `json:"nonce"`
}

// IssueChallenge creates a decryption challenge under the current epoch. The
// NKA remembers the challenge plaintext (in memory) so it can verify the
// host's proof later.
func (n *NKA) IssueChallenge(newHostID string, now time.Time) (*Challenge, error) {
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
	n.challenges[objectID] = challenge
	n.challengesMu.Unlock()
	return &Challenge{Envelope: env, AAD: aad, Nonce: nonce}, nil
}

// proofContext is the context bound into the challenge-proof MAC.
const proofContext = "pagnet/e2ee/challenge-proof/v1"

// Proof is the new host's response to a challenge: an HMAC over the nonce,
// keyed by the decrypted challenge plaintext. Only a host that decrypted the
// challenge (i.e. holds the epoch key) can produce a valid proof.
type Proof struct {
	MAC []byte `json:"mac"`
}

// ComputeChallengeProof decrypts the challenge with the host's keyring and
// returns the proof. This is the new-host side of the challenge.
func ComputeChallengeProof(kr *Keyring, ch *Challenge) (*Proof, error) {
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
	return &Proof{MAC: challengeMAC(plaintext, ch.Nonce)}, nil
}

// VerifyChallenge checks the new host's proof against the remembered
// challenge plaintext. The challenge is single-use: it is consumed whether or
// not the proof is valid.
func (n *NKA) VerifyChallenge(ch *Challenge, proof *Proof) error {
	n.challengesMu.Lock()
	plaintext, ok := n.challenges[ch.AAD.ObjectID]
	delete(n.challenges, ch.AAD.ObjectID)
	n.challengesMu.Unlock()
	if !ok {
		return fmt.Errorf("crypto: unknown or already-consumed challenge %s", ch.AAD.ObjectID)
	}
	expected := challengeMAC(plaintext, ch.Nonce)
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
