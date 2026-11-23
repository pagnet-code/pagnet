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

type pendingDirectChannelIndex struct {
	Bindings map[string]bool `json:"bindings"`
	MAC      []byte          `json:"mac"`
}

func pendingDirectChannelMAC(key []byte, domain string, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("pagnet-pending-direct-channel-v1/" + domain + "\x00"))
	mac.Write(payload)
	return mac.Sum(nil)
}

func readPrivateDirectChannelFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("sdk: pending direct channel metadata is not private regular file")
	}
	return os.ReadFile(path)
}

// All callers hold the parent process lock. The MAC detects partial corruption
// and rewrites while the authentication key is retained. It does not protect
// against replacement with valid older files: selective record rollback can
// erase outbox entries, and rolling back the index then deleting a channel can
// allow different material to be generated. The server must retain immutable
// exact publication and message wire bytes; authoritative publication status
// detects material disagreement, and message-ID conflicts must be terminal.
// Complete store deletion is also indistinguishable from first use. This module
// supplies no local monotonic freshness guarantee against arbitrary file replay.
func (k *keyring) initPendingDirectChannelStore() error {
	dir := filepath.Join(k.root, "pending-direct-channels")
	err := os.Mkdir(dir, 0700)
	if errors.Is(err, os.ErrExist) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			return errors.New("sdk: pending direct channel directory is not private")
		}
		_, _, err = k.readPendingDirectChannelIndex()
		return err
	}
	if err != nil {
		return err
	}
	// A surviving incomplete store fails closed rather than generating a new key.
	if err := k.syncPendingDirectChannelDir(k.root); err != nil {
		return err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if err := k.writeDirectChannelFileDurable(filepath.Join(dir, "auth.key"), key); err != nil {
		return err
	}
	return k.writePendingDirectChannelIndex(map[string]bool{}, key)
}

func (k *keyring) readPendingDirectChannelIndex() (map[string]bool, []byte, error) {
	dir := filepath.Join(k.root, "pending-direct-channels")
	key, err := readPrivateDirectChannelFile(filepath.Join(dir, "auth.key"))
	if err != nil {
		return nil, nil, err
	}
	if len(key) != 32 {
		return nil, nil, errors.New("sdk: invalid pending direct channel authentication key")
	}
	b, err := readPrivateDirectChannelFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, nil, err
	}
	var index pendingDirectChannelIndex
	if err := directCanonical(b, &index, len(b)); err != nil {
		return nil, nil, err
	}
	payload, _ := json.Marshal(index.Bindings)
	if index.Bindings == nil || !hmac.Equal(index.MAC, pendingDirectChannelMAC(key, "index", payload)) {
		return nil, nil, errors.New("sdk: pending direct channel index authentication failed")
	}
	// Heal a predecessor's crash after rename but before directory fsync.
	if err := k.syncPendingDirectChannelDir(dir); err != nil {
		return nil, nil, err
	}
	return index.Bindings, key, nil
}

func (k *keyring) writePendingDirectChannelIndex(bindings map[string]bool, key []byte) error {
	payload, err := json.Marshal(bindings)
	if err != nil {
		return err
	}
	b, err := json.Marshal(pendingDirectChannelIndex{Bindings: bindings, MAC: pendingDirectChannelMAC(key, "index", payload)})
	if err != nil {
		return err
	}
	return k.writeDirectChannelFileDurable(filepath.Join(k.root, "pending-direct-channels", "index.json"), b)
}
