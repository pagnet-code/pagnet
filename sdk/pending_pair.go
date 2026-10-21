package sdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// pendingPairEpoch is deliberately separate from enrolled epoch files. Publication
// and recipient possession proofs may only use the record returned after storage.
// Publication is the exact AuthHPKE wire payload; recipients leave it empty.
type pendingPairEpoch struct {
	GrantID              string   `json:"grant_id"`
	Generation           uint64   `json:"generation"`
	NetworkID            string   `json:"network_id"`
	EpochID              string   `json:"epoch_id"`
	Descriptor           []byte   `json:"descriptor"`
	DescriptorHash       [32]byte `json:"descriptor_hash"`
	EpochKey             []byte   `json:"epoch_key"`
	Publication          []byte   `json:"publication"`
	IssuerFingerprint    [32]byte `json:"issuer_fingerprint"`
	RecipientFingerprint [32]byte `json:"recipient_fingerprint"`
}

type pendingPairFile struct {
	Record   pendingPairEpoch `json:"record"`
	Checksum [32]byte         `json:"checksum"`
}

func (p pendingPairEpoch) validate() error {
	if p.GrantID == "" || p.Generation == 0 || p.NetworkID == "" || p.EpochID == "" || filepath.Base(p.NetworkID) != p.NetworkID || p.NetworkID == "." || filepath.Base(p.EpochID) != p.EpochID || p.EpochID == "." || len(p.Descriptor) == 0 || len(p.Descriptor) > 4096 || len(p.EpochKey) != 32 || sha256.Sum256(p.Descriptor) != p.DescriptorHash || p.IssuerFingerprint == ([32]byte{}) || p.RecipientFingerprint == ([32]byte{}) {
		return errors.New("sdk: invalid pending pair epoch")
	}
	return nil
}

func (k *keyring) pendingPairDir(grantID string, generation uint64) string {
	binding, _ := json.Marshal([]any{grantID, generation})
	sum := sha256.Sum256(binding)
	return filepath.Join(k.root, "pending-pairs", hex.EncodeToString(sum[:]))
}

// storePendingPairEpoch must complete before sending a publication or proof.
// A retry with the same immutable binding returns the ORIGINAL key/publication,
// even if the caller generated fresh randomized bytes. A directory without a
// valid record is an error: an interrupted or lost record cannot be regenerated.
func (k *keyring) storePendingPairEpoch(p pendingPairEpoch) (pendingPairEpoch, error) {
	if err := p.validate(); err != nil {
		return pendingPairEpoch{}, err
	}
	unlock, err := k.lockPendingPairs()
	if err != nil {
		return pendingPairEpoch{}, err
	}
	defer unlock()
	dir := k.pendingPairDir(p.GrantID, p.Generation)
	err = os.Mkdir(dir, 0700)
	if errors.Is(err, os.ErrExist) {
		old, err := k.readPendingPairEpoch(p.GrantID, p.Generation)
		if err != nil {
			return pendingPairEpoch{}, err
		}
		if old.NetworkID != p.NetworkID || old.EpochID != p.EpochID || !bytes.Equal(old.Descriptor, p.Descriptor) || old.DescriptorHash != p.DescriptorHash || old.IssuerFingerprint != p.IssuerFingerprint || old.RecipientFingerprint != p.RecipientFingerprint || (len(old.Publication) == 0) != (len(p.Publication) == 0) || (len(old.Publication) == 0 && !bytes.Equal(old.EpochKey, p.EpochKey)) {
			return pendingPairEpoch{}, errors.New("sdk: pending pair epoch binding conflict")
		}
		return old, nil
	}
	if err != nil {
		return pendingPairEpoch{}, err
	}
	// Persist the directory reservation first; its survival forbids regeneration
	// if a crash occurs before the complete record is committed.
	if err := syncPairDir(filepath.Dir(dir)); err != nil {
		return pendingPairEpoch{}, err
	}
	payload, _ := json.Marshal(p)
	encoded, err := json.Marshal(pendingPairFile{Record: p, Checksum: sha256.Sum256(payload)})
	if err != nil {
		return pendingPairEpoch{}, err
	}
	if err := writePairFileDurable(filepath.Join(dir, "record.json"), encoded); err != nil {
		return pendingPairEpoch{}, err
	}
	return k.readPendingPairEpoch(p.GrantID, p.Generation)
}

// loadPendingPairEpoch never creates or repairs missing/corrupt pending state.
func (k *keyring) loadPendingPairEpoch(grantID string, generation uint64) (pendingPairEpoch, error) {
	unlock, err := k.lockPendingPairs()
	if err != nil {
		return pendingPairEpoch{}, err
	}
	defer unlock()
	return k.readPendingPairEpoch(grantID, generation)
}

func (k *keyring) readPendingPairEpoch(grantID string, generation uint64) (pendingPairEpoch, error) {
	dir := k.pendingPairDir(grantID, generation)
	info, err := os.Lstat(dir)
	if err != nil {
		return pendingPairEpoch{}, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return pendingPairEpoch{}, errors.New("sdk: pending pair record directory is not private")
	}
	path := filepath.Join(dir, "record.json")
	info, err = os.Lstat(path)
	if err != nil {
		return pendingPairEpoch{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return pendingPairEpoch{}, errors.New("sdk: pending pair record is not private regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return pendingPairEpoch{}, err
	}
	var f pendingPairFile
	if err := json.Unmarshal(b, &f); err != nil {
		return pendingPairEpoch{}, fmt.Errorf("sdk: corrupt pending pair epoch: %w", err)
	}
	payload, _ := json.Marshal(f.Record)
	if sha256.Sum256(payload) != f.Checksum || f.Record.GrantID != grantID || f.Record.Generation != generation {
		return pendingPairEpoch{}, errors.New("sdk: corrupt pending pair epoch")
	}
	if err := f.Record.validate(); err != nil {
		return pendingPairEpoch{}, err
	}
	return f.Record, nil
}

// activatePendingPairEpoch is only for a caller that has verified an
// authoritative server ACTIVE response matching this exact binding. Merely
// publishing a package or receiving/proving a key MUST NOT call this method.
// Keep the pending record for stable retries, including after a crash here.
func (k *keyring) activatePendingPairEpoch(grantID string, generation uint64, networkID, epochID string, descriptorHash [32]byte) error {
	unlock, err := k.lockPendingPairs()
	if err != nil {
		return err
	}
	defer unlock()
	p, err := k.readPendingPairEpoch(grantID, generation)
	if err != nil {
		return err
	}
	if p.NetworkID != networkID || p.EpochID != epochID || p.DescriptorHash != descriptorHash {
		return errors.New("sdk: active pair epoch binding conflict")
	}
	dir := filepath.Join(k.root, "networks", networkID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := syncPairDir(k.root); err != nil {
		return err
	}
	if err := syncPairDir(filepath.Dir(dir)); err != nil {
		return err
	}
	path := filepath.Join(dir, "epoch-"+epochID+".key")
	existing, err := os.ReadFile(path)
	if err == nil && !bytes.Equal(existing, p.EpochKey) {
		return errors.New("sdk: active pair epoch key conflict")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writePairFileDurable(path, p.EpochKey); err != nil {
		return err
	}
	// Invalidate our lazy cache only after the enrollment is durable.
	k.epochMu.Lock()
	delete(k.epochLRU, networkID)
	for i, id := range k.epochOrder {
		if id == networkID {
			k.epochOrder = append(k.epochOrder[:i], k.epochOrder[i+1:]...)
			break
		}
	}
	k.epochMu.Unlock()
	return nil
}

func syncPairDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func writePairFileDurable(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncPairDir(filepath.Dir(path))
}
