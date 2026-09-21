package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/cloudflare/circl/hpke"
)

// Keyring layout (plan D6, north-star BI/BJ). Per-principal state dir under
// <StateDir>/principals/<principalID>/:
//
//	<StateDir>/principals/
//	  index.json                     0600  credential-hash → principalID
//	  <principalID>/
//	    identity.key                 0600  32-byte X25519 private key (raw)
//	    credential                   0600  durable endpoint credential
//	    networks/<networkID>/
//	      epoch-<epochID>.key        0600  32-byte network epoch key (raw)
//
// The identity key is the endpoint's crypto identity (its public key rides
// in endpoint.register and is stored on the participant_endpoints row;
// rotation-capable). Private key material NEVER crosses to the control
// plane. Files are 0600, directories 0700, written atomically (temp +
// rename) so a crash mid-write cannot tear a key whose regeneration would
// orphan pending key packages.
//
// Epoch keys are LAZY-loaded per network (north-star BJ: a service in many
// networks never loads every network key at startup) and held in a bounded
// in-memory LRU cache (epochCacheCap networks).
const (
	// epochCacheCap bounds the in-memory per-network epoch cache.
	epochCacheCap = 32
)

// keyring is the SDK's local key material store (sdk-internal; the public
// surface is Connect/Config only).
type keyring struct {
	root string // <StateDir>/principals

	epochMu    sync.Mutex
	epochLRU   map[string]map[string][32]byte // networkID → (epochID → key)
	epochOrder []string                       // networkID, front = most recent
}

func newKeyring(stateDir string) (*keyring, error) {
	root := filepath.Join(stateDir, "principals")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("sdk: create keyring dir: %w", err)
	}
	return &keyring{
		root:       root,
		epochLRU:   map[string]map[string][32]byte{},
		epochOrder: nil,
	}, nil
}

// --- credential → principal index -----------------------------------------

// credentialHash is the index key for a credential (the credential itself
// is a secret; its hash is not).
func credentialHash(cred string) string {
	sum := sha256.Sum256([]byte(cred))
	return hex.EncodeToString(sum[:])
}

func (k *keyring) indexPath() string { return filepath.Join(k.root, "index.json") }

// loadIndex reads the credential-hash → principalID index ({} when absent).
func (k *keyring) loadIndex() (map[string]string, error) {
	b, err := os.ReadFile(k.indexPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("sdk: read keyring index: %w", err)
	}
	idx := map[string]string{}
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("sdk: parse keyring index: %w", err)
	}
	return idx, nil
}

// saveIndex writes the index atomically.
func (k *keyring) saveIndex(idx map[string]string) error {
	b, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	return writeFileAtomic(k.indexPath(), b)
}

// principalForCredential resolves a credential to a principal id via the
// index ("" when unknown).
func (k *keyring) principalForCredential(cred string) (string, error) {
	idx, err := k.loadIndex()
	if err != nil {
		return "", err
	}
	return idx[credentialHash(cred)], nil
}

// --- identity key -----------------------------------------------------------

func (k *keyring) identityPath(principalID string) string {
	return filepath.Join(k.root, principalID, "identity.key")
}

// identityKey loads the principal's X25519 identity private key (raw 32
// bytes).
func (k *keyring) identityKey(principalID string) ([]byte, error) {
	b, err := os.ReadFile(k.identityPath(principalID))
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("sdk: identity key for %s is %d bytes, want 32", principalID, len(b))
	}
	return b, nil
}

// loadOrCreateIdentity resolves the identity key for a credential: the
// stored key when the credential is indexed and the key file exists, else a
// FRESH keypair (in memory; persist it with PersistIdentity after
// endpoint.auth_ok reveals the principal id).
func (k *keyring) loadOrCreateIdentity(cred string) (priv []byte, principalID string, err error) {
	principalID, err = k.principalForCredential(cred)
	if err != nil {
		return nil, "", err
	}
	if principalID != "" {
		if priv, err = k.identityKey(principalID); err == nil {
			return priv, principalID, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, "", err
		}
		// Indexed principal but the key file is gone: regenerate. The
		// server's stored public key is stale, but re-registering updates
		// it (rotation-capable).
	}
	priv, err = newIdentityKey()
	return priv, "", err
}

// newIdentityKey generates a fresh X25519 keypair (the audited circl KEM
// scheme — the same suite the host crypto identity uses).
func newIdentityKey() ([]byte, error) {
	pub, priv, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("sdk: generate x25519 identity: %w", err)
	}
	_ = pub
	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("sdk: marshal x25519 identity: %w", err)
	}
	return privBytes, nil
}

// PersistIdentity writes the identity key + credential for a principal and
// indexes the credential. Idempotent (an existing identity key is left
// untouched — it is the stable crypto identity).
func (k *keyring) PersistIdentity(principalID, cred string, priv []byte) error {
	dir := filepath.Join(k.root, principalID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("sdk: create principal dir: %w", err)
	}
	idPath := k.identityPath(principalID)
	if _, err := os.Stat(idPath); errors.Is(err, os.ErrNotExist) {
		if err := writeFileAtomic(idPath, priv); err != nil {
			return fmt.Errorf("sdk: write identity key: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("sdk: stat identity key: %w", err)
	}
	if cred != "" {
		if err := k.StoreCredential(principalID, cred); err != nil {
			return err
		}
	}
	idx, err := k.loadIndex()
	if err != nil {
		return err
	}
	if cred != "" {
		idx[credentialHash(cred)] = principalID
	}
	return k.saveIndex(idx)
}

// --- durable endpoint credential --------------------------------------------

func (k *keyring) credentialPath(principalID string) string {
	return filepath.Join(k.root, principalID, "credential")
}

// StoreCredential persists the durable endpoint credential for a principal
// (0600) and indexes it.
func (k *keyring) StoreCredential(principalID, cred string) error {
	dir := filepath.Join(k.root, principalID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("sdk: create principal dir: %w", err)
	}
	if err := writeFileAtomic(k.credentialPath(principalID), []byte(cred)); err != nil {
		return fmt.Errorf("sdk: write credential: %w", err)
	}
	idx, err := k.loadIndex()
	if err != nil {
		return err
	}
	idx[credentialHash(cred)] = principalID
	return k.saveIndex(idx)
}

// IndexCredential maps a credential to a principal in the index WITHOUT
// storing it as the durable credential. It is used for the presented
// (one-time activation) credential: after the activation exchange the
// durable credential is the one to present, but a later Connect that still
// presents the consumed activation credential must be able to resolve the
// principal (and thus fall back to the stored durable credential).
func (k *keyring) IndexCredential(cred, principalID string) error {
	if cred == "" || principalID == "" {
		return nil
	}
	idx, err := k.loadIndex()
	if err != nil {
		return err
	}
	idx[credentialHash(cred)] = principalID
	return k.saveIndex(idx)
}

// CredentialForPrincipal returns the stored durable credential ("" when
// none).
func (k *keyring) CredentialForPrincipal(principalID string) (string, error) {
	if principalID == "" {
		return "", nil
	}
	b, err := os.ReadFile(k.credentialPath(principalID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("sdk: read credential: %w", err)
	}
	return string(b), nil
}

// storedPrincipalIDs lists the principals whose durable endpoint credential
// the keyring holds: a principal directory that actually carries a
// credential file (an identity key with no credential is not connectable, so
// it is not an actor). "networks" is the shared epoch-key directory, not a
// principal.
func (k *keyring) storedPrincipalIDs() ([]string, error) {
	entries, err := os.ReadDir(k.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("sdk: read principal store: %w", err)
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "networks" {
			continue
		}
		if _, err := os.Stat(k.credentialPath(e.Name())); err != nil {
			continue // no credential stored for this principal
		}
		ids = append(ids, e.Name())
	}
	sort.Strings(ids)
	return ids, nil
}

// StoredCredential returns the durable endpoint credential the SDK stored for
// principalID under stateDir ("" when the store holds none for it).
//
// It is the ONE read window onto the SDK's per-principal credential store for
// a caller outside the SDK — the CLI's principal-actor commands (`pagnet
// invoke`, `pagnet subscriptions`) run as the principal whose endpoint
// credential this host already holds instead of asking the operator to paste
// the secret again. The layout is the SDK's business (see the package docs);
// reaching past this function duplicates it.
func StoredCredential(stateDir, principalID string) (string, error) {
	if stateDir == "" {
		return "", errors.New("sdk: StoredCredential requires a state dir")
	}
	k, err := newKeyring(stateDir)
	if err != nil {
		return "", err
	}
	return k.CredentialForPrincipal(principalID)
}

// StoredPrincipalIDs lists the principal ids whose durable endpoint
// credential the SDK holds under stateDir (newest first — the ids are
// UUIDv7, so they are time-sortable). An empty store is an empty list, not an
// error: "this host holds no principal credential" is an ordinary state.
func StoredPrincipalIDs(stateDir string) ([]string, error) {
	if stateDir == "" {
		return nil, errors.New("sdk: StoredPrincipalIDs requires a state dir")
	}
	k, err := newKeyring(stateDir)
	if err != nil {
		return nil, err
	}
	ids, err := k.storedPrincipalIDs()
	if err != nil {
		return nil, err
	}
	// Newest first: when a host holds exactly one credential it is the one
	// most recently connected here, and the ambiguity message lists the
	// choices in the order the operator would recognise.
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	return ids, nil
}

// CredentialForCredential resolves a (possibly consumed) credential to the
// stored durable credential of the same principal ("" when unknown). This
// is the fallback that makes "second connect after activation" work even
// when the operator still presents the one-time activation credential.
func (k *keyring) CredentialForCredential(cred string) (string, error) {
	principalID, err := k.principalForCredential(cred)
	if err != nil {
		return "", err
	}
	return k.CredentialForPrincipal(principalID)
}

// --- network epoch keys (lazy, bounded cache) --------------------------------

// StoreEpoch persists a network epoch key (0600) and caches it in memory.
func (k *keyring) StoreEpoch(networkID, epochID string, key [32]byte) error {
	dir := filepath.Join(k.root, "networks", networkID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("sdk: create network keyring dir: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "epoch-"+epochID+".key"), key[:]); err != nil {
		return fmt.Errorf("sdk: write epoch key: %w", err)
	}
	k.epochMu.Lock()
	defer k.epochMu.Unlock()
	epochs, ok := k.epochLRU[networkID]
	if !ok {
		epochs = map[string][32]byte{}
		k.epochLRU[networkID] = epochs
		k.epochOrder = append(k.epochOrder, networkID)
		if len(k.epochOrder) > epochCacheCap {
			old := k.epochOrder[0]
			k.epochOrder = k.epochOrder[1:]
			delete(k.epochLRU, old)
		}
	}
	epochs[epochID] = key
	return nil
}

// EpochKeys returns ALL epoch keys for a network: the in-memory cache when
// warm, else a lazy load from disk (north-star BJ).
func (k *keyring) EpochKeys(networkID string) (map[string][32]byte, error) {
	k.epochMu.Lock()
	if epochs, ok := k.epochLRU[networkID]; ok {
		out := make(map[string][32]byte, len(epochs))
		for id, key := range epochs {
			out[id] = key
		}
		k.touchLocked(networkID)
		k.epochMu.Unlock()
		return out, nil
	}
	k.epochMu.Unlock()

	dir := filepath.Join(k.root, "networks", networkID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string][32]byte{}, nil
		}
		return nil, fmt.Errorf("sdk: read network keyring: %w", err)
	}
	epochs := map[string][32]byte{}
	for _, e := range entries {
		name := e.Name()
		if len(name) < len("epoch-") || len(name) < 5 || name[:6] != "epoch-" || name[len(name)-4:] != ".key" {
			continue
		}
		epochID := name[len("epoch-") : len(name)-len(".key")]
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("sdk: read epoch key %s: %w", epochID, err)
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("sdk: epoch key %s is %d bytes, want 32", epochID, len(b))
		}
		var key [32]byte
		copy(key[:], b)
		epochs[epochID] = key
	}
	k.epochMu.Lock()
	k.epochLRU[networkID] = epochs
	k.epochOrder = append(k.epochOrder, networkID)
	if len(k.epochOrder) > epochCacheCap {
		old := k.epochOrder[0]
		k.epochOrder = k.epochOrder[1:]
		delete(k.epochLRU, old)
	}
	k.epochMu.Unlock()
	return epochs, nil
}

// touchLocked moves networkID to most-recent (caller holds epochMu).
func (k *keyring) touchLocked(networkID string) {
	for i, id := range k.epochOrder {
		if id == networkID {
			k.epochOrder = append(k.epochOrder[:i], k.epochOrder[i+1:]...)
			k.epochOrder = append(k.epochOrder, networkID)
			return
		}
	}
}

// EpochKey returns one epoch key by id (lazy load on miss).
func (k *keyring) EpochKey(networkID, epochID string) ([32]byte, error) {
	epochs, err := k.EpochKeys(networkID)
	if err != nil {
		return [32]byte{}, err
	}
	key, ok := epochs[epochID]
	if !ok {
		return [32]byte{}, fmt.Errorf("sdk: epoch %s not enrolled for network %s", epochID, networkID)
	}
	return key, nil
}

// ActiveEpoch returns the newest enrolled epoch for a network (UUIDv7 ids
// are time-sortable, so the lexicographic max is the newest). It is the
// epoch new content is encrypted under.
func (k *keyring) ActiveEpoch(networkID string) ([32]byte, string, error) {
	epochs, err := k.EpochKeys(networkID)
	if err != nil {
		return [32]byte{}, "", err
	}
	if len(epochs) == 0 {
		return [32]byte{}, "", fmt.Errorf("sdk: %w: %s", ErrNetworkCryptoNotReady, networkID)
	}
	ids := make([]string, 0, len(epochs))
	for id := range epochs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	newest := ids[len(ids)-1]
	return epochs[newest], newest, nil
}

// --- atomic file write --------------------------------------------------------

// writeFileAtomic writes b to path (0600) via temp-file + rename: a crash
// mid-write never tears a key file.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
