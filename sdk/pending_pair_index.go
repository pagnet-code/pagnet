package sdk

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type pendingPairIndex struct {
	Bindings map[string]bool `json:"bindings"`
	MAC      []byte          `json:"mac"`
}

func pendingPairMAC(key []byte, domain string, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("pagnet-pending-pair-v1/" + domain + "\x00"))
	mac.Write(payload)
	return mac.Sum(nil)
}

func readPrivatePairFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("sdk: pending pair metadata is not private regular file")
	}
	return os.ReadFile(path)
}

// All callers hold the parent process lock. The MAC detects partial corruption
// and rewrites while the authentication key is retained. It does not protect
// against an attacker replacing the entire local store. Complete store deletion
// is indistinguishable from first use; server immutable publication must reject
// an attempt to republish a different key/package for an existing grant.
func (k *keyring) initPendingPairStore() error {
	dir := filepath.Join(k.root, "pending-pairs")
	err := os.Mkdir(dir, 0700)
	if errors.Is(err, os.ErrExist) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			return errors.New("sdk: pending pair directory is not private")
		}
		_, _, err = k.readPendingPairIndex()
		return err
	}
	if err != nil {
		return err
	}
	// A surviving incomplete store fails closed rather than generating a new key.
	if err := k.syncPendingPairDir(k.root); err != nil {
		return err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if err := k.writePairFileDurable(filepath.Join(dir, "auth.key"), key); err != nil {
		return err
	}
	return k.writePendingPairIndex(map[string]bool{}, key)
}

func (k *keyring) readPendingPairIndex() (map[string]bool, []byte, error) {
	dir := filepath.Join(k.root, "pending-pairs")
	key, err := readPrivatePairFile(filepath.Join(dir, "auth.key"))
	if err != nil {
		return nil, nil, err
	}
	if len(key) != 32 {
		return nil, nil, errors.New("sdk: invalid pending pair authentication key")
	}
	b, err := readPrivatePairFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, nil, err
	}
	var index pendingPairIndex
	if err := json.Unmarshal(b, &index); err != nil {
		return nil, nil, err
	}
	payload, _ := json.Marshal(index.Bindings)
	if index.Bindings == nil || !hmac.Equal(index.MAC, pendingPairMAC(key, "index", payload)) {
		return nil, nil, errors.New("sdk: pending pair index authentication failed")
	}
	// Heal a predecessor's crash after rename but before directory fsync.
	if err := k.syncPendingPairDir(dir); err != nil {
		return nil, nil, err
	}
	return index.Bindings, key, nil
}

func (k *keyring) writePendingPairIndex(bindings map[string]bool, key []byte) error {
	payload, err := json.Marshal(bindings)
	if err != nil {
		return err
	}
	b, err := json.Marshal(pendingPairIndex{Bindings: bindings, MAC: pendingPairMAC(key, "index", payload)})
	if err != nil {
		return err
	}
	return k.writePairFileDurable(filepath.Join(k.root, "pending-pairs", "index.json"), b)
}
