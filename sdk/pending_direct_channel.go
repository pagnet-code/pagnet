package sdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// pendingDirectChannel is local-only. Descriptor binds parent grant/generation,
// S/P principals and endpoints, epoch and all policy. Publication retains the
// source's exact randomized HPKE bytes; P leaves it empty. No key is enrolled in
// the network keyring, including when Active becomes true.
type pendingDirectChannel struct {
	ChannelID         string            `json:"channel_id"`
	Descriptor        []byte            `json:"descriptor"`
	DescriptorHash    [32]byte          `json:"descriptor_hash"`
	Role              string            `json:"role"`
	SourceFingerprint [32]byte          `json:"source_fingerprint"`
	PeerFingerprint   [32]byte          `json:"peer_fingerprint"`
	ChannelKey        []byte            `json:"channel_key"`
	Publication       []byte            `json:"publication"`
	Active            bool              `json:"active"`
	Outbox            map[string][]byte `json:"outbox"`
}
type pendingDirectChannelFile struct {
	Record pendingDirectChannel `json:"record"`
	MAC    []byte               `json:"mac"`
}

func pendingDirectChannelFor(m *directMaterial, publication []byte) (pendingDirectChannel, error) {
	if m == nil {
		return pendingDirectChannel{}, errDirect
	}
	raw, _ := json.Marshal(m.descriptor)
	s, _ := directBinary(m.descriptor.S.PublicKey, 32)
	p, _ := directBinary(m.descriptor.P.PublicKey, 32)
	r := pendingDirectChannel{ChannelID: directChannelID(m.descriptor), Descriptor: raw, DescriptorHash: m.hash, Role: m.role, SourceFingerprint: sha256.Sum256(s), PeerFingerprint: sha256.Sum256(p), ChannelKey: append([]byte(nil), m.key[:]...), Publication: append([]byte(nil), publication...), Outbox: map[string][]byte{}}
	return r, r.validate()
}

func (r pendingDirectChannel) material() (*directMaterial, error) {
	var d directDescriptor
	if directCanonical(r.Descriptor, &d, 4096) != nil {
		return nil, errDirect
	}
	if _, err := directValidate(r.Descriptor, d, time.Time{}); err != nil {
		return nil, err
	}
	s, _ := directBinary(d.S.PublicKey, 32)
	p, _ := directBinary(d.P.PublicKey, 32)
	if r.ChannelID != directChannelID(d) || r.DescriptorHash != sha256.Sum256(r.Descriptor) || r.SourceFingerprint != sha256.Sum256(s) || r.PeerFingerprint != sha256.Sum256(p) {
		return nil, errDirect
	}
	return directMaterialFor(d, r.Descriptor, r.ChannelKey, r.Role)
}
func (r pendingDirectChannel) validate() error {
	m, err := r.material()
	if err != nil || r.Outbox == nil {
		return errDirect
	}
	if r.Role == "S" {
		var p directPackage
		if directCanonical(r.Publication, &p, 8192) != nil || !bytes.Equal(p.Descriptor, r.Descriptor) {
			return errDirect
		}
		if _, err := directBinary(p.Enc, 32); err != nil {
			return err
		}
		if _, err := directBinary(p.Ciphertext, 48); err != nil {
			return err
		}
	} else if len(r.Publication) != 0 {
		return errDirect
	}
	for id, wire := range r.Outbox {
		if err := r.validateOutgoing(m, id, wire); err != nil {
			return err
		}
	}
	return nil
}

// validateOutgoing accepts only a complete authenticated ciphertext for our role.
// Plaintext is neither an input to the journal nor part of its persisted format.
func (r pendingDirectChannel) validateOutgoing(m *directMaterial, id string, wire []byte) error {
	var w directWire
	if directCanonical(wire, &w, m.descriptor.Limits.MaxMessageWireBytes) != nil || directWireBinary(w) != nil {
		return errDirect
	}
	h := w.Header
	kind := "ASK"
	if r.Role == "P" {
		kind = "REPLY"
	}
	if h.Domain != directDomain+"/message" || h.Kind != kind || h.ChannelID != r.ChannelID || h.DescriptorHash != directB64(r.DescriptorHash[:]) || h.MessageID != id || !validPairPathID(id) || !validPairPathID(h.RootID) {
		return errDirect
	}
	if kind == "ASK" {
		if h.From != m.descriptor.S || h.To != m.descriptor.P || h.AskID != "" || h.AskWireHash != "" {
			return errDirect
		}
	} else {
		if h.From != m.descriptor.P || h.To != m.descriptor.S || !validPairPathID(h.AskID) {
			return errDirect
		}
		if _, err := directBinary(h.AskWireHash, 32); err != nil {
			return err
		}
	}
	aead, err := m.aead(kind)
	if err != nil {
		return err
	}
	nonce, _ := directBinary(w.Nonce, 12)
	ct, _ := directBinary(w.Ciphertext, -1)
	aad, _ := json.Marshal(h)
	_, err = aead.Open(nil, nonce, ct, aad)
	return err
}
func (k *keyring) pendingDirectChannelDir(id string) string {
	return filepath.Join(k.root, "pending-direct-channels", id)
}
func validDirectChannelID(id string) bool { _, err := directBinary(id, 32); return err == nil }

// storePendingDirectChannel returns the only material that may be published.
// Reservation is durable before record creation. A missing/corrupt reserved
// record must never be regenerated. A retry preserves original randomized bytes.
func (k *keyring) storePendingDirectChannel(r pendingDirectChannel) (pendingDirectChannel, error) {
	if err := r.validate(); err != nil {
		return pendingDirectChannel{}, err
	}
	if r.Active || len(r.Outbox) != 0 {
		return pendingDirectChannel{}, errDirect
	}
	unlock, err := k.lockPendingDirectChannels()
	if err != nil {
		return pendingDirectChannel{}, err
	}
	defer unlock()
	index, key, err := k.readPendingDirectChannelIndex()
	if err != nil {
		return pendingDirectChannel{}, err
	}
	dir := k.pendingDirectChannelDir(r.ChannelID)
	if index[r.ChannelID] {
		old, err := k.readPendingDirectChannel(r.ChannelID)
		if err != nil {
			return pendingDirectChannel{}, err
		}
		if !bytes.Equal(old.Descriptor, r.Descriptor) || old.DescriptorHash != r.DescriptorHash || old.Role != r.Role || old.SourceFingerprint != r.SourceFingerprint || old.PeerFingerprint != r.PeerFingerprint || (r.Role == "P" && !bytes.Equal(old.ChannelKey, r.ChannelKey)) {
			return pendingDirectChannel{}, errors.New("sdk: pending direct channel binding conflict")
		}
		return old, nil
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		return pendingDirectChannel{}, errors.New("sdk: unreserved direct channel directory")
	}
	index[r.ChannelID] = true
	if err := k.writePendingDirectChannelIndex(index, key); err != nil {
		return pendingDirectChannel{}, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return pendingDirectChannel{}, err
	}
	if err := k.syncPendingDirectChannelDir(filepath.Dir(dir)); err != nil {
		return pendingDirectChannel{}, err
	}
	if err := k.writePendingDirectChannel(r, key); err != nil {
		return pendingDirectChannel{}, err
	}
	return k.readPendingDirectChannel(r.ChannelID)
}
func (k *keyring) loadPendingDirectChannel(id string) (pendingDirectChannel, error) {
	if !validDirectChannelID(id) {
		return pendingDirectChannel{}, errDirect
	}
	unlock, err := k.lockPendingDirectChannels()
	if err != nil {
		return pendingDirectChannel{}, err
	}
	defer unlock()
	return k.readPendingDirectChannel(id)
}
func (k *keyring) readPendingDirectChannel(id string) (pendingDirectChannel, error) {
	if !validDirectChannelID(id) {
		return pendingDirectChannel{}, errDirect
	}
	index, key, err := k.readPendingDirectChannelIndex()
	if err != nil {
		return pendingDirectChannel{}, err
	}
	if !index[id] {
		return pendingDirectChannel{}, errors.New("sdk: direct channel is not reserved")
	}
	dir := k.pendingDirectChannelDir(id)
	info, err := os.Lstat(dir)
	if err != nil {
		return pendingDirectChannel{}, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return pendingDirectChannel{}, errors.New("sdk: direct channel directory is not private")
	}
	b, err := readPrivateDirectChannelFile(filepath.Join(dir, "record.json"))
	if err != nil {
		return pendingDirectChannel{}, err
	}
	var f pendingDirectChannelFile
	if err := directCanonical(b, &f, len(b)); err != nil {
		return pendingDirectChannel{}, err
	}
	payload, _ := json.Marshal(f.Record)
	if f.Record.ChannelID != id || !hmac.Equal(f.MAC, pendingDirectChannelMAC(key, "record", payload)) {
		return pendingDirectChannel{}, errors.New("sdk: direct channel authentication failed")
	}
	if err := f.Record.validate(); err != nil {
		return pendingDirectChannel{}, err
	}
	if err := k.syncPendingDirectChannelDir(dir); err != nil {
		return pendingDirectChannel{}, err
	}
	return f.Record, nil
}
func (k *keyring) writePendingDirectChannel(r pendingDirectChannel, key []byte) error {
	payload, _ := json.Marshal(r)
	b, err := json.Marshal(pendingDirectChannelFile{r, pendingDirectChannelMAC(key, "record", payload)})
	if err != nil {
		return err
	}
	return k.writeDirectChannelFileDurable(filepath.Join(k.pendingDirectChannelDir(r.ChannelID), "record.json"), b)
}

// storeDirectOutgoing must return successfully before the first send. The same
// message ID can only retry identical complete wire bytes; no plaintext is kept.
func (k *keyring) storeDirectOutgoing(id string, wire []byte) ([]byte, error) {
	if !validDirectChannelID(id) {
		return nil, errDirect
	}
	unlock, err := k.lockPendingDirectChannels()
	if err != nil {
		return nil, err
	}
	defer unlock()
	r, err := k.readPendingDirectChannel(id)
	if err != nil {
		return nil, err
	}
	if !r.Active {
		return nil, errors.New("sdk: direct channel is not locally active")
	}
	m, err := r.material()
	if err != nil {
		return nil, err
	}
	var w directWire
	if directCanonical(wire, &w, m.descriptor.Limits.MaxMessageWireBytes) != nil {
		return nil, errDirect
	}
	messageID := w.Header.MessageID
	if err := r.validateOutgoing(m, messageID, wire); err != nil {
		return nil, err
	}
	if old, ok := r.Outbox[messageID]; ok {
		if !bytes.Equal(old, wire) {
			return nil, errors.New("sdk: direct message ID conflict")
		}
		return old, nil
	}
	_, key, err := k.readPendingDirectChannelIndex()
	if err != nil {
		return nil, err
	}
	r.Outbox[messageID] = append([]byte(nil), wire...)
	if err := k.writePendingDirectChannel(r, key); err != nil {
		return nil, err
	}
	stored, err := k.readPendingDirectChannel(id)
	if err != nil {
		return nil, err
	}
	return stored.Outbox[messageID], nil
}

// directAuthoritativeStatus is a caller-verified authoritative status contract.
// This module performs no server call. Publication and possession alone do not
// satisfy this contract: ACTIVE must bind this exact complete descriptor.
type directAuthoritativeStatus struct {
	State      string
	ChannelID  string
	Descriptor []byte
}

func (k *keyring) markDirectChannelActive(status directAuthoritativeStatus) error {
	if status.State != "ACTIVE" || !validDirectChannelID(status.ChannelID) {
		return errDirect
	}
	unlock, err := k.lockPendingDirectChannels()
	if err != nil {
		return err
	}
	defer unlock()
	r, err := k.readPendingDirectChannel(status.ChannelID)
	if err != nil {
		return err
	}
	if !bytes.Equal(r.Descriptor, status.Descriptor) {
		return errors.New("sdk: active direct channel binding conflict")
	}
	_, key, err := k.readPendingDirectChannelIndex()
	if err != nil {
		return err
	}
	r.Active = true
	if err := k.writePendingDirectChannel(r, key); err != nil {
		return err
	}
	_, err = k.readPendingDirectChannel(status.ChannelID)
	return err
}
func (k *keyring) syncPendingDirectChannelDir(path string) error {
	if k.pendingDirectChannelSyncDir != nil {
		return k.pendingDirectChannelSyncDir(path)
	}
	return syncPairDir(path)
}
func (k *keyring) writeDirectChannelFileDurable(path string, b []byte) error {
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
	return k.syncPendingDirectChannelDir(filepath.Dir(path))
}
