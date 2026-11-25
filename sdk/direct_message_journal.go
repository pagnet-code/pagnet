package sdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

const directMessageRecordLimit = 256

// The physical file-content budget includes encoded ciphertext files, the
// authentication key, and both old/new manifests during atomic replacement.
const directMessageByteLimit = 16 << 20
const directMessageMetadataReserve = 2*directMessageIndexLimit + 32
const directMessageIndexLimit = 1 << 20

// This namespace is independent of pending-channel Outbox and the V1 pair spool.
// Surviving reservations are never encrypted again, including after crashes.
// MACs detect corruption, not rollback or complete deletion of local state.
type directMessageBinding struct {
	Local             directParty  `json:"local"`
	Role              string       `json:"role"`
	PublicationHash   [32]byte     `json:"publication_hash"`
	GrantID           string       `json:"grant_id"`
	GrantGeneration   string       `json:"grant_generation"`
	ChannelGeneration string       `json:"channel_generation"`
	IntentID          string       `json:"intent_id"`
	NetworkID         string       `json:"network_id"`
	Header            directHeader `json:"header"`
	InputMAC          [32]byte     `json:"input_mac"`
}
type directMessageRecord struct {
	Binding        directMessageBinding `json:"binding"`
	ReservedBytes  int                  `json:"reserved_bytes"`
	WireDigest     [32]byte             `json:"wire_digest"`
	WireBytes      int                  `json:"wire_bytes"`
	Admitted       bool                 `json:"admitted"`
	DependencyDone bool                 `json:"dependency_done"`
	Tombstone      bool                 `json:"tombstone"`
}
type directMessageManifest struct {
	Records map[string]directMessageRecord `json:"records"`
	MAC     []byte                         `json:"mac"`
}
type directMessageFile struct {
	Wire []byte `json:"wire"`
	MAC  []byte `json:"mac"`
}

// Only a durable reread can create a prepared handle. Fields stay private.
type directPreparedMessage struct {
	binding directMessageBinding
	wire    []byte
}

func directMessageMAC(key []byte, domain string, raw []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("pagnet-direct-messages-v2/" + domain + "\x00"))
	mac.Write(raw)
	return mac.Sum(nil)
}
func (k *keyring) directMessageDir() string { return filepath.Join(k.root, "direct-messages-v2") }
func (k *keyring) directMessagePath(id string) string {
	return filepath.Join(k.directMessageDir(), id+".json")
}
func (k *keyring) syncDirectMessages(path string) error {
	if k.directMessageSyncDir != nil {
		return k.directMessageSyncDir(path)
	}
	return syncPairDir(path)
}
func (k *keyring) writeDirectMessageFile(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".direct-v2-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if k.directMessageBeforeRename != nil {
		k.directMessageBeforeRename()
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return k.syncDirectMessages(filepath.Dir(path))
}

// Check on-disk sizes before any read or JSON/base64 allocation.
func readDirectMessageFile(path string, max int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > int64(max) {
		return nil, errDirect
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(raw) > max {
		return nil, errDirect
	}
	return raw, nil
}

// Stored []byte fields use padded base64 inside the authenticated JSON envelope.
func directMessageStoredBytes(wireBytes int) int {
	empty, _ := json.Marshal(directMessageFile{Wire: []byte{}, MAC: make([]byte, 32)})
	return len(empty) + base64.StdEncoding.EncodedLen(wireBytes)
}

// Every caller holds the root journal flock. Streaming prevents an abandoned
// directory from forcing an unbounded allocation. Only our exact temp grammar
// and private owned regular files qualify for crash cleanup.
func (k *keyring) recoverDirectMessageTemps() error {
	dir := k.directMessageDir()
	owner, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !owner.IsDir() || owner.Mode().Perm() != 0700 || !directMessagePrivateOwner(owner) {
		return errDirect
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		entries, e := f.ReadDir(32)
		if e != nil && !errors.Is(e, io.EOF) {
			return e
		}
		for _, entry := range entries {
			name := entry.Name()
			info, err := os.Lstat(filepath.Join(dir, name))
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !directMessagePrivateOwner(info) {
				return errDirect
			}
			if strings.HasPrefix(name, ".direct-v2-") {
				suffix := strings.TrimPrefix(name, ".direct-v2-")
				if len(suffix) == 0 || len(suffix) > 10 || info.Size() > directMessageIndexLimit {
					return errDirect
				}
				for _, c := range suffix {
					if c < '0' || c > '9' {
						return errDirect
					}
				}
				if err = os.Remove(filepath.Join(dir, name)); err != nil {
					return err
				}
				continue
			}
			if name == "auth.key" || name == "manifest.json" {
				continue
			}
			id := strings.TrimSuffix(name, ".json")
			parsed, err := uuid.Parse(id)
			if err != nil || parsed.String() != id || name != id+".json" {
				return errDirect
			}
		}
		if errors.Is(e, io.EOF) {
			break
		}
	}
	return k.syncDirectMessages(dir)
}

// Unrecognized files are never deleted. They fail closed, as do files that are
// absent from the authoritative reservation manifest, so they cannot consume
// unaccounted capacity while this journal continues writing.
func (k *keyring) validateDirectMessageStorage(records map[string]directMessageRecord) error {
	f, err := os.Open(k.directMessageDir())
	if err != nil {
		return err
	}
	defer f.Close()
	total := 0
	for {
		entries, e := f.ReadDir(32)
		if e != nil && !errors.Is(e, io.EOF) {
			return e
		}
		for _, entry := range entries {
			name := entry.Name()
			info, err := os.Lstat(filepath.Join(k.directMessageDir(), name))
			if err != nil {
				return err
			}
			max := 0
			switch name {
			case "auth.key":
				max = 32
			case "manifest.json":
				max = directMessageIndexLimit
			default:
				id := strings.TrimSuffix(name, ".json")
				r, ok := records[id]
				if !ok || r.Tombstone || name != id+".json" {
					return errDirect
				}
				max = r.ReservedBytes
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !directMessagePrivateOwner(info) || info.Size() < 0 || info.Size() > int64(max) {
				return errDirect
			}
			total += int(info.Size())
			if total > directMessageByteLimit {
				return errDirect
			}
		}
		if errors.Is(e, io.EOF) {
			return nil
		}
	}
}

func (k *keyring) initDirectMessages() error {
	dir := k.directMessageDir()
	err := os.Mkdir(dir, 0700)
	if errors.Is(err, os.ErrExist) {
		info, e := os.Lstat(dir)
		if e != nil {
			return e
		}
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			return errDirect
		}
		if e = k.recoverDirectMessageTemps(); e != nil {
			return e
		}
		records, _, e := k.readDirectMessages()
		if e != nil {
			return e
		}
		return k.validateDirectMessageStorage(records)
	}
	if err != nil {
		return err
	}
	if err = k.syncDirectMessages(k.root); err != nil {
		return err
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err = rand.Read(key); err != nil {
		return err
	}
	if err = k.writeDirectMessageFile(filepath.Join(dir, "auth.key"), key); err != nil {
		return err
	}
	return k.writeDirectMessages(map[string]directMessageRecord{}, key)
}
func (k *keyring) writeDirectMessages(records map[string]directMessageRecord, key []byte) error {
	payload, err := json.Marshal(records)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(directMessageManifest{records, directMessageMAC(key, "manifest", payload)})
	if err != nil || len(raw) > directMessageIndexLimit {
		return errDirect
	}
	return k.writeDirectMessageFile(filepath.Join(k.directMessageDir(), "manifest.json"), raw)
}
func (k *keyring) readDirectMessages() (map[string]directMessageRecord, []byte, error) {
	key, err := readDirectMessageFile(filepath.Join(k.directMessageDir(), "auth.key"), 32)
	if err != nil || len(key) != 32 {
		return nil, nil, errDirect
	}
	raw, err := readDirectMessageFile(filepath.Join(k.directMessageDir(), "manifest.json"), directMessageIndexLimit)
	if err != nil {
		return nil, nil, err
	}
	var manifest directMessageManifest
	if directCanonical(raw, &manifest, directMessageIndexLimit) != nil {
		return nil, nil, errDirect
	}
	payload, _ := json.Marshal(manifest.Records)
	if manifest.Records == nil || len(manifest.Records) > directMessageRecordLimit || !hmac.Equal(manifest.MAC, directMessageMAC(key, "manifest", payload)) {
		return nil, nil, errDirect
	}
	total := directMessageMetadataReserve
	for id, r := range manifest.Records {
		b := r.Binding
		if _, err := b.Header.CanonicalBytes(); err != nil {
			return nil, nil, errDirect
		}
		if id != b.Header.MessageID || b.Role != b.Header.SenderRole || b.Local.TenantID == "" || b.Local.PrincipalID == "" || b.Local.EndpointID == "" || b.Local.CredentialID == "" || b.PublicationHash == ([32]byte{}) || b.InputMAC == ([32]byte{}) || b.GrantID == "" || b.GrantGeneration == "" || b.ChannelGeneration == "" || b.IntentID == "" || b.NetworkID == "" || r.ReservedBytes <= 0 || r.ReservedBytes > directMessageStoredBytes(transport.DirectChannelMessageMaxBytesV2) || r.WireBytes < 0 || r.WireBytes > transport.DirectChannelMessageMaxBytesV2 || r.WireBytes > 0 && directMessageStoredBytes(r.WireBytes) != r.ReservedBytes || (r.WireBytes == 0) != (r.WireDigest == ([32]byte{})) || r.Tombstone && (!r.Admitted || !r.DependencyDone || r.WireBytes == 0) {
			return nil, nil, errDirect
		}
		if !r.Tombstone {
			total += r.ReservedBytes
			if total > directMessageByteLimit {
				return nil, nil, errDirect
			}
		}
	}
	// Finish a crash after tombstone commit but before ciphertext unlink. Do
	// this before admitting more capacity so retained bytes stay bounded.
	for id, r := range manifest.Records {
		if r.Tombstone {
			if err = os.Remove(k.directMessagePath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, nil, err
			}
		}
	}
	if err = k.syncDirectMessages(k.directMessageDir()); err != nil {
		return nil, nil, err
	}
	return manifest.Records, key, nil
}
func (k *keyring) readDirectMessage(r directMessageRecord, key []byte) ([]byte, error) {
	if r.Tombstone || r.WireBytes == 0 {
		return nil, errDirect
	}
	raw, err := readDirectMessageFile(k.directMessagePath(r.Binding.Header.MessageID), 2*transport.DirectChannelMessageMaxBytesV2)
	if err != nil {
		return nil, err
	}
	var f directMessageFile
	if directCanonical(raw, &f, 2*transport.DirectChannelMessageMaxBytesV2) != nil || len(f.Wire) != r.WireBytes || sha256.Sum256(f.Wire) != r.WireDigest || !hmac.Equal(f.MAC, directMessageMAC(key, "wire", f.Wire)) {
		return nil, errDirect
	}
	w, err := transport.DecodeDirectChannelMessageV2(f.Wire)
	if err != nil || w.Header != r.Binding.Header {
		return nil, errDirect
	}
	if err = k.syncDirectMessages(k.directMessageDir()); err != nil {
		return nil, err
	}
	return f.Wire, nil
}

// prepareDirectMessage binds authenticated local identity and all deterministic
// inputs before reserving both the ID and exact encoded capacity. No caller
// supplies an input digest. The lock covers local durability only.
func (k *keyring) prepareDirectMessage(m *directMaterial, local directParty, h directHeader, ask, reply, plaintext []byte, now time.Time) (*directPreparedMessage, error) {
	if m == nil || m.publicationHash == ([32]byte{}) || len(plaintext) > transport.DirectChannelMessageMaxBytesV2 {
		return nil, errDirect
	}
	party := m.descriptor.S
	if m.role == "P" {
		party = m.descriptor.P
	}
	if local != party {
		return nil, errDirect
	}
	var expected directHeader
	var err error
	if h.Kind == "ASK" && h.ParentMessageID != "" {
		expected, err = m.prepareContinuationHeader(h.MessageID, ask, reply, now)
	} else {
		if len(reply) != 0 {
			return nil, errDirect
		}
		expected, err = m.prepareHeader(h.Kind, h.MessageID, h.RootID, ask, now)
	}
	if err != nil || expected != h {
		return nil, errDirect
	}
	// Encoded length is deterministic for GCM (12-byte nonce, 16-byte tag).
	dummy, _ := json.Marshal(directWire{Header: h, Nonce: "AAAAAAAAAAAAAAAA", Ciphertext: ""})
	size := len(dummy) + base64.RawURLEncoding.EncodedLen(len(plaintext)+16)
	if size > m.descriptor.Limits.MaxMessageWireBytes || size > transport.DirectChannelMessageMaxBytesV2 {
		return nil, errDirect
	}
	unlock, err := k.lockDirectMessages()
	if err != nil {
		return nil, err
	}
	defer unlock()
	records, key, err := k.readDirectMessages()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	b := directMessageBinding{Local: local, Role: m.role, PublicationHash: m.publicationHash, GrantID: m.descriptor.ParentGrantID, GrantGeneration: m.descriptor.GrantGeneration, ChannelGeneration: m.descriptor.ChannelGeneration, IntentID: m.descriptor.DirectIntentID, NetworkID: m.descriptor.NetworkID, Header: h}
	binding, _ := json.Marshal(b)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("pagnet-direct-messages-v2/input\x00"))
	mac.Write(binding)
	mac.Write([]byte{0})
	mac.Write(plaintext)
	copy(b.InputMAC[:], mac.Sum(nil))
	if old, ok := records[h.MessageID]; ok {
		if old.Binding != b {
			return nil, errDirect
		}
		wire, err := k.readDirectMessage(old, key)
		if err != nil {
			return nil, err
		}
		return &directPreparedMessage{b, wire}, nil
	}
	storedSize := directMessageStoredBytes(size)
	total := directMessageMetadataReserve + storedSize
	for _, r := range records {
		if !r.Tombstone {
			total += r.ReservedBytes
		}
	}
	if len(records) >= directMessageRecordLimit || total > directMessageByteLimit {
		return nil, errDirect
	}
	if _, err = os.Lstat(k.directMessagePath(h.MessageID)); !errors.Is(err, os.ErrNotExist) {
		return nil, errDirect
	}
	record := directMessageRecord{Binding: b, ReservedBytes: storedSize}
	records[h.MessageID] = record
	if err = k.writeDirectMessages(records, key); err != nil {
		return nil, err
	}
	// Only this freshly persisted reservation reaches random encryption.
	wire, err := m.sealHeader(h, ask, reply, plaintext, now)
	if err != nil {
		return nil, err
	}
	if len(wire) != size {
		return nil, errDirect
	}
	raw, _ := json.Marshal(directMessageFile{wire, directMessageMAC(key, "wire", wire)})
	if len(raw) != storedSize {
		return nil, errDirect
	}
	if err = k.writeDirectMessageFile(k.directMessagePath(h.MessageID), raw); err != nil {
		return nil, err
	}
	record.WireDigest = sha256.Sum256(wire)
	record.WireBytes = len(wire)
	records[h.MessageID] = record
	if err = k.writeDirectMessages(records, key); err != nil {
		return nil, err
	}
	records, key2, err := k.readDirectMessages()
	if err != nil {
		return nil, err
	}
	defer clear(key2)
	reread, err := k.readDirectMessage(records[h.MessageID], key2)
	if err != nil || !bytes.Equal(reread, wire) {
		return nil, errDirect
	}
	return &directPreparedMessage{b, reread}, nil
}

// Admission and dependency release are independent monotonic facts. In
// particular an admitted ASK remains available for REPLY/continuation crypto.
// Releasing ciphertext leaves an immutable ID tombstone charged to record quota.
func (k *keyring) updateDirectMessage(p *directPreparedMessage, admitted, dependencyDone bool) error {
	if p == nil {
		return errDirect
	}
	unlock, err := k.lockDirectMessages()
	if err != nil {
		return err
	}
	defer unlock()
	records, key, err := k.readDirectMessages()
	if err != nil {
		return err
	}
	defer clear(key)
	id := p.binding.Header.MessageID
	r, ok := records[id]
	if !ok || r.Binding != p.binding || r.WireBytes == 0 {
		return errDirect
	}
	if r.Tombstone {
		return nil
	}
	if _, err = k.readDirectMessage(r, key); err != nil {
		return err
	}
	r.Admitted = r.Admitted || admitted
	r.DependencyDone = r.DependencyDone || dependencyDone
	r.Tombstone = r.Admitted && r.DependencyDone
	records[id] = r
	if err = k.writeDirectMessages(records, key); err != nil {
		return err
	}
	if r.Tombstone {
		if err = os.Remove(k.directMessagePath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return k.syncDirectMessages(k.directMessageDir())
	}
	return nil
}
