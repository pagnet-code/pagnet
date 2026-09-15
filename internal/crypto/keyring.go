package crypto

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

// EpochState is the lifecycle state of a key epoch.
type EpochState string

const (
	// EpochActive is the epoch new content is encrypted under.
	EpochActive EpochState = "active"
	// EpochRotated is a superseded epoch, retained customer-side to read
	// history (plan §11.8).
	EpochRotated EpochState = "rotated"
	// EpochRevoked is an epoch whose key is considered compromised and must
	// no longer be used to decrypt new content.
	EpochRevoked EpochState = "revoked"
)

// epochKeySize is the size of a network key-epoch key.
const epochKeySize = 32

// KeyEpoch is one network key epoch: a 256-bit key plus metadata.
type KeyEpoch struct {
	ID        string     `json:"id"`
	State     EpochState `json:"state"`
	CreatedAt time.Time  `json:"created_at"`
	// Key is the 256-bit epoch key (base64 in JSON). NEVER logged.
	Key []byte `json:"key"`
}

// KeyArray returns the epoch key as a [32]byte, validating the length.
func (e *KeyEpoch) KeyArray() ([32]byte, error) {
	if len(e.Key) != epochKeySize {
		return [32]byte{}, fmt.Errorf("crypto: epoch %s key is %d bytes, want %d", e.ID, len(e.Key), epochKeySize)
	}
	var k [32]byte
	copy(k[:], e.Key)
	return k, nil
}

// String is a safe, key-free representation for logging.
func (e KeyEpoch) String() string {
	return fmt.Sprintf("KeyEpoch{id=%s state=%s created=%s}", e.ID, e.State, e.CreatedAt.UTC().Format(time.RFC3339))
}

// Keyring is the per-network set of key epochs. It is the customer-side
// authority for a Private Network's content keys.
type Keyring struct {
	NetworkID string     `json:"network_id"`
	Epochs    []KeyEpoch `json:"epochs"`
}

// String is a safe, key-free representation for logging.
func (k *Keyring) String() string {
	return fmt.Sprintf("Keyring{network=%s epochs=%d}", k.NetworkID, len(k.Epochs))
}

// NewKeyring creates an empty keyring for a network.
func NewKeyring(networkID string) *Keyring {
	return &Keyring{NetworkID: networkID}
}

// All public getters return COPIES of epochs (immutable snapshots); the
// keyring's slice is the source of truth. This avoids stale-pointer footguns
// when the slice is reallocated by a later Rotate/Activate.

// Activate creates the first key epoch (private-network activation, plan
// §11.6). It is idempotent: if an active epoch already exists it is returned
// unchanged.
func (k *Keyring) Activate(now time.Time) (KeyEpoch, error) {
	if active, ok := k.activeEpochCopy(); ok {
		return active, nil
	}
	epoch, err := mintEpoch(now)
	if err != nil {
		return KeyEpoch{}, err
	}
	k.Epochs = append(k.Epochs, *epoch)
	return *epoch, nil
}

// Rotate mints a new active epoch and marks the previous active epoch as
// rotated (plan §11.8). New content uses the new epoch; the old epoch is
// retained customer-side to read history.
func (k *Keyring) Rotate(now time.Time) (KeyEpoch, error) {
	idx := k.activeEpochIndex()
	if idx < 0 {
		return KeyEpoch{}, fmt.Errorf("crypto: no active epoch to rotate; call Activate first")
	}
	k.Epochs[idx].State = EpochRotated
	epoch, err := mintEpoch(now)
	if err != nil {
		return KeyEpoch{}, err
	}
	k.Epochs = append(k.Epochs, *epoch)
	return *epoch, nil
}

// Revoke marks the epoch with the given id as revoked.
func (k *Keyring) Revoke(id string) error {
	idx := k.epochIndex(id)
	if idx < 0 {
		return fmt.Errorf("crypto: no epoch %s", id)
	}
	k.Epochs[idx].State = EpochRevoked
	return nil
}

// ActiveEpoch returns a copy of the newest active epoch (the one new content
// is encrypted under).
func (k *Keyring) ActiveEpoch() (KeyEpoch, error) {
	e, ok := k.activeEpochCopy()
	if !ok {
		return KeyEpoch{}, fmt.Errorf("crypto: keyring %s has no active epoch", k.NetworkID)
	}
	return e, nil
}

// EpochByID returns a copy of the epoch with the given id, in any state.
func (k *Keyring) EpochByID(id string) (KeyEpoch, bool) {
	idx := k.epochIndex(id)
	if idx < 0 {
		return KeyEpoch{}, false
	}
	return k.Epochs[idx], true
}

func (k *Keyring) epochIndex(id string) int {
	for i := range k.Epochs {
		if k.Epochs[i].ID == id {
			return i
		}
	}
	return -1
}

func (k *Keyring) activeEpochIndex() int {
	best := -1
	for i := range k.Epochs {
		if k.Epochs[i].State != EpochActive {
			continue
		}
		if best == -1 || k.Epochs[i].CreatedAt.After(k.Epochs[best].CreatedAt) {
			best = i
		}
	}
	return best
}

func (k *Keyring) activeEpochCopy() (KeyEpoch, bool) {
	idx := k.activeEpochIndex()
	if idx < 0 {
		return KeyEpoch{}, false
	}
	return k.Epochs[idx], true
}

// mintEpoch creates a fresh active epoch with a random 256-bit key.
func mintEpoch(now time.Time) (*KeyEpoch, error) {
	key := make([]byte, epochKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("crypto: read epoch key: %w", err)
	}
	return &KeyEpoch{
		ID:        string(domain.NewID()),
		State:     EpochActive,
		CreatedAt: now.UTC(),
		Key:       key,
	}, nil
}

// KeyringPath returns the keyring file path for a network. The network id is
// validated as a UUID before it becomes a path component (SEC-407: a crafted
// value like "../../x" must never reach filepath.Join).
func KeyringPath(stateDir, networkID string) (string, error) {
	if _, err := domain.ParseID(networkID); err != nil {
		return "", fmt.Errorf("crypto: invalid network id %q: %w", networkID, err)
	}
	return filepath.Join(stateDir, "e2ee", networkID, "keyring.json"), nil
}

// writeFileAtomic durably replaces path with b: write a temp file in the same
// directory, fsync it, then rename it over the target (directory fsync
// best-effort). A crash at any point leaves either the old file or the new
// one — never a torn file. Both call sites hold secret key material whose
// only copy lives at path, so a torn write must be impossible, not unlikely.
// The replacement file arrives 0600 (CreateTemp's mode, re-asserted below),
// which also re-tightens a pre-existing file with a looser mode.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename succeeds
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// SaveKeyring writes the keyring to disk as a 0600 file, atomically. The file
// holds every epoch key for the network, so it must survive daemon crashes
// (a torn write would make all network content undecryptable).
func SaveKeyring(stateDir string, kr *Keyring) error {
	path, err := KeyringPath(stateDir, kr.NetworkID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("crypto: mkdir keyring dir: %w", err)
	}
	b, err := json.Marshal(kr)
	if err != nil {
		return fmt.Errorf("crypto: marshal keyring: %w", err)
	}
	if err := writeFileAtomic(path, b); err != nil {
		return fmt.Errorf("crypto: write keyring: %w", err)
	}
	return nil
}

// LoadKeyring reads and validates the keyring from disk.
func LoadKeyring(stateDir, networkID string) (*Keyring, error) {
	path, err := KeyringPath(stateDir, networkID)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: read keyring: %w", err)
	}
	var kr Keyring
	if err := json.Unmarshal(b, &kr); err != nil {
		return nil, fmt.Errorf("crypto: parse keyring: %w", err)
	}
	if kr.NetworkID != networkID {
		return nil, fmt.Errorf("crypto: keyring network %q does not match %q", kr.NetworkID, networkID)
	}
	for i := range kr.Epochs {
		if len(kr.Epochs[i].Key) != epochKeySize {
			return nil, fmt.Errorf("crypto: epoch %s key is %d bytes, want %d", kr.Epochs[i].ID, len(kr.Epochs[i].Key), epochKeySize)
		}
	}
	return &kr, nil
}
