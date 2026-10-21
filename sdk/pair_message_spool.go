package sdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
)

const pairMessageSpoolCount = 256
const pairMessageSpoolBytes = 16 << 20

// pairMessageBinding and InputDigest must describe the trusted caller input,
// before encryption. Reserve before encrypting, and never encrypt a reserved ID
// again: a reservation without wire bytes is an unresolved failure.
type pairMessageBinding struct {
	PrincipalID string   `json:"principal_id"`
	GrantID     string   `json:"grant_id"`
	Generation  uint64   `json:"generation"`
	NetworkID   string   `json:"network_id"`
	MessageID   string   `json:"message_id"`
	InputDigest [32]byte `json:"input_digest"`
}

type pairMessageState struct {
	Binding    pairMessageBinding `json:"binding"`
	WireDigest [32]byte           `json:"wire_digest"`
	WireBytes  int                `json:"wire_bytes"`
	Retired    bool               `json:"retired"`
	Rejected   bool               `json:"rejected,omitempty"`
}

type pairMessageIndex struct {
	Records map[string]pairMessageState `json:"records"`
	MAC     []byte                      `json:"mac"`
}

type pairMessageFile struct {
	Wire []byte `json:"wire"`
	MAC  []byte `json:"mac"`
}

// Field order and concrete envelope/AAD encoding match SharingPairWireRequest.
// This is storage validation, not a send API or enrollment authority.
type pairMessageWire struct {
	Version              int                     `json:"version"`
	GrantID              string                  `json:"grantId"`
	Generation           int64                   `json:"generation"`
	NetworkID            string                  `json:"networkId"`
	ID                   string                  `json:"id"`
	ThreadID             string                  `json:"threadId"`
	CorrelationID        *string                 `json:"correlationId"`
	Kind                 string                  `json:"kind"`
	SenderPrincipalID    string                  `json:"senderPrincipalId"`
	RecipientPrincipalID string                  `json:"recipientPrincipalId"`
	Envelope             e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD                  e2ee.AAD                `json:"aad"`
}

func (b pairMessageBinding) valid() bool {
	id, err := uuid.Parse(b.MessageID)
	return err == nil && id.Version() == 7 && id.String() == b.MessageID && validPairPathID(b.PrincipalID) && validPairPathID(b.GrantID) && validPairPathID(b.NetworkID) && b.Generation > 0 && b.Generation <= uint64(^uint64(0)>>1) && b.InputDigest != ([32]byte{})
}

func (k *keyring) pairMessageDir(principal string) string {
	return filepath.Join(k.root, principal, "pair-messages")
}

func spoolMAC(key []byte, domain string, data []byte) []byte {
	return pendingPairMAC(key, "message-spool/"+domain, data)
}

// Complete local deletion or rollback is outside this store's guarantees.
// A surviving incomplete manifest/key fails closed rather than resetting IDs.
func (k *keyring) initPairMessageSpool(principal string) error {
	parent := filepath.Join(k.root, principal)
	if err := os.Mkdir(parent, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("sdk: invalid spool principal directory")
	}
	if err := k.syncPendingPairDir(k.root); err != nil {
		return err
	}
	dir := k.pairMessageDir(principal)
	err = os.Mkdir(dir, 0700)
	if errors.Is(err, os.ErrExist) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			return errors.New("sdk: invalid message spool directory")
		}
		_, _, err = k.readPairMessageIndex(principal)
		return err
	}
	if err != nil {
		return err
	}
	if err := k.syncPendingPairDir(parent); err != nil {
		return err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if err := k.writePairFileDurable(filepath.Join(dir, "auth.key"), key); err != nil {
		return err
	}
	return k.writePairMessageIndex(principal, map[string]pairMessageState{}, key)
}

func (k *keyring) writePairMessageIndex(principal string, records map[string]pairMessageState, key []byte) error {
	payload, err := json.Marshal(records)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(pairMessageIndex{records, spoolMAC(key, "index", payload)})
	if err != nil {
		return err
	}
	return k.writePairFileDurable(filepath.Join(k.pairMessageDir(principal), "index.json"), raw)
}

func (k *keyring) readPairMessageIndex(principal string) (map[string]pairMessageState, []byte, error) {
	dir := k.pairMessageDir(principal)
	key, err := readPrivatePairFile(filepath.Join(dir, "auth.key"))
	if err != nil {
		return nil, nil, err
	}
	if len(key) != 32 {
		return nil, nil, errors.New("sdk: invalid spool authentication key")
	}
	raw, err := readPrivatePairFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, nil, err
	}
	var index pairMessageIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, nil, err
	}
	payload, _ := json.Marshal(index.Records)
	if index.Records == nil || !hmac.Equal(index.MAC, spoolMAC(key, "index", payload)) {
		return nil, nil, errors.New("sdk: message spool index authentication failed")
	}
	count, total := 0, 0
	for id, state := range index.Records {
		if !state.Binding.valid() || state.Binding.PrincipalID != principal || state.Binding.MessageID != id || state.WireBytes < 0 || state.WireBytes > pairMessageSpoolBytes || (state.WireBytes == 0) != (state.WireDigest == ([32]byte{})) || state.Retired && state.WireBytes == 0 && !state.Rejected || state.Rejected && !state.Retired {
			return nil, nil, errors.New("sdk: corrupt message spool binding")
		}
		if !state.Retired {
			count++
			total += state.WireBytes
		}
	}
	if count > pairMessageSpoolCount || total > pairMessageSpoolBytes {
		return nil, nil, errors.New("sdk: corrupt message spool quota")
	}
	if err := k.syncPendingPairDir(dir); err != nil {
		return nil, nil, err
	}
	return index.Records, key, nil
}

// reservePairMessage returns existing=true for every prior reservation, including
// incomplete and retired records. Only existing=false permits fresh encryption.
func (k *keyring) reservePairMessage(b pairMessageBinding) (state pairMessageState, existing bool, err error) {
	if !b.valid() {
		return state, false, errors.New("sdk: invalid message spool binding")
	}
	unlock, err := k.lockPairMessages(b.PrincipalID)
	if err != nil {
		return state, false, err
	}
	defer unlock()
	records, key, err := k.readPairMessageIndex(b.PrincipalID)
	if err != nil {
		return state, false, err
	}
	if old, ok := records[b.MessageID]; ok {
		if old.Binding != b {
			return state, true, errors.New("sdk: message reservation conflict")
		}
		if old.WireBytes > 0 && !old.Retired {
			if _, err := k.readPairMessageWire(old, key); err != nil {
				return state, true, err
			}
		}
		return old, true, nil
	}
	count := 0
	for _, r := range records {
		if !r.Retired {
			count++
		}
	}
	if count >= pairMessageSpoolCount {
		return state, false, errors.New("sdk: message spool record limit")
	}
	if _, err := os.Lstat(k.pairMessagePath(b)); !errors.Is(err, os.ErrNotExist) {
		return state, false, errors.New("sdk: unreserved message spool wire")
	}
	state.Binding = b
	records[b.MessageID] = state
	err = k.writePairMessageIndex(b.PrincipalID, records, key)
	return state, false, err
}

// storePairMessage accepts only an earlier durable reservation. Repeated stores
// must contain identical canonical server bytes; no random encryption occurs here.
func (k *keyring) storePairMessage(b pairMessageBinding, wire []byte, digest [32]byte) (pairMessageState, error) {
	var zero pairMessageState
	if !b.valid() || len(wire) == 0 || len(wire) > pairMessageSpoolBytes || sha256.Sum256(wire) != digest {
		return zero, errors.New("sdk: invalid message wire digest")
	}
	var w pairMessageWire
	if err := json.Unmarshal(wire, &w); err != nil {
		return zero, err
	}
	canonical, _ := json.Marshal(w)
	if !bytes.Equal(canonical, wire) || w.Version != 1 || w.GrantID != b.GrantID || w.Generation != int64(b.Generation) || w.NetworkID != b.NetworkID || w.ID != b.MessageID || w.SenderPrincipalID != b.PrincipalID {
		return zero, errors.New("sdk: noncanonical or conflicting message wire")
	}
	unlock, err := k.lockPairMessages(b.PrincipalID)
	if err != nil {
		return zero, err
	}
	defer unlock()
	records, key, err := k.readPairMessageIndex(b.PrincipalID)
	if err != nil {
		return zero, err
	}
	old, ok := records[b.MessageID]
	if !ok || old.Binding != b {
		return zero, errors.New("sdk: message is not reserved")
	}
	if old.Rejected {
		return zero, errors.New("sdk: message reservation was rejected")
	}
	if old.WireBytes > 0 {
		if old.WireDigest != digest || old.WireBytes != len(wire) {
			return zero, errors.New("sdk: immutable message conflict")
		}
		if !old.Retired {
			stored, err := k.readPairMessageWire(old, key)
			if err != nil {
				return zero, err
			}
			if !bytes.Equal(stored, wire) {
				return zero, errors.New("sdk: immutable message bytes conflict")
			}
		}
		return old, nil
	}
	total := len(wire)
	for _, r := range records {
		if !r.Retired {
			total += r.WireBytes
		}
	}
	if total > pairMessageSpoolBytes {
		return zero, errors.New("sdk: message spool byte limit")
	}
	// Commit the digest/size first. Any crash or missing child then fails closed.
	old.WireDigest = digest
	old.WireBytes = len(wire)
	records[b.MessageID] = old
	if err := k.writePairMessageIndex(b.PrincipalID, records, key); err != nil {
		return zero, err
	}
	raw, _ := json.Marshal(pairMessageFile{wire, spoolMAC(key, "wire/"+b.MessageID, wire)})
	if err := k.writePairFileDurable(k.pairMessagePath(b), raw); err != nil {
		return zero, err
	}
	if _, err := k.readPairMessageWire(old, key); err != nil {
		return zero, err
	}
	return old, nil
}

func (k *keyring) pairMessagePath(b pairMessageBinding) string {
	return filepath.Join(k.pairMessageDir(b.PrincipalID), b.MessageID+".json")
}
func (k *keyring) readPairMessageWire(state pairMessageState, key []byte) ([]byte, error) {
	if state.Retired || state.WireBytes == 0 {
		return nil, errors.New("sdk: unresolved message has no retry wire")
	}
	raw, err := readPrivatePairFile(k.pairMessagePath(state.Binding))
	if err != nil {
		return nil, err
	}
	var f pairMessageFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if len(f.Wire) != state.WireBytes || sha256.Sum256(f.Wire) != state.WireDigest || !hmac.Equal(f.MAC, spoolMAC(key, "wire/"+state.Binding.MessageID, f.Wire)) {
		return nil, errors.New("sdk: corrupt message spool wire")
	}
	if err := k.syncPendingPairDir(k.pairMessageDir(state.Binding.PrincipalID)); err != nil {
		return nil, err
	}
	return f.Wire, nil
}

func (k *keyring) loadPairMessage(b pairMessageBinding) ([]byte, error) {
	if !b.valid() {
		return nil, errors.New("sdk: invalid message binding")
	}
	unlock, err := k.lockPairMessages(b.PrincipalID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	records, key, err := k.readPairMessageIndex(b.PrincipalID)
	if err != nil {
		return nil, err
	}
	state, ok := records[b.MessageID]
	if !ok || state.Binding != b {
		return nil, errors.New("sdk: message reservation mismatch")
	}
	return k.readPairMessageWire(state, key)
}

// unresolvedPairMessages includes incomplete reservations and errors on corrupt
// finalized records. No expiry, revocation, or HTTP response deletes a record.
func (k *keyring) unresolvedPairMessages(principal string) ([]pairMessageState, error) {
	if !validPairPathID(principal) {
		return nil, errors.New("sdk: invalid spool principal")
	}
	unlock, err := k.lockPairMessages(principal)
	if err != nil {
		return nil, err
	}
	defer unlock()
	records, key, err := k.readPairMessageIndex(principal)
	if err != nil {
		return nil, err
	}
	out := []pairMessageState{}
	for _, r := range records {
		if !r.Retired {
			if r.WireBytes > 0 {
				if _, err := k.readPairMessageWire(r, key); err != nil {
					return nil, fmt.Errorf("sdk: unresolved message %s: %w", r.Binding.MessageID, err)
				}
			}
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Binding.MessageID < out[j].Binding.MessageID })
	return out, nil
}

// retirePairMessage requires a sender-authorized durable admission receipt from
// the transport caller, scoped to this principal/grant/generation/network/ID.
// Pending (admitted) suffices; recipient acknowledgement is separate authority.
func (k *keyring) retirePairMessage(b pairMessageBinding, digest [32]byte, status string) error {
	if !b.valid() || (status != "pending" && status != "acknowledged") {
		return errors.New("sdk: invalid sender admission receipt")
	}
	unlock, err := k.lockPairMessages(b.PrincipalID)
	if err != nil {
		return err
	}
	defer unlock()
	records, key, err := k.readPairMessageIndex(b.PrincipalID)
	if err != nil {
		return err
	}
	state, ok := records[b.MessageID]
	if !ok || state.Binding != b || state.Rejected || state.WireBytes == 0 || state.WireDigest != digest {
		return errors.New("sdk: admission receipt binding mismatch")
	}
	if !state.Retired {
		if _, err := k.readPairMessageWire(state, key); err != nil {
			return err
		}
		state.Retired = true
		records[b.MessageID] = state
		if err := k.writePairMessageIndex(b.PrincipalID, records, key); err != nil {
			return err
		}
	}
	if err := os.Remove(k.pairMessagePath(b)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return k.syncPendingPairDir(k.pairMessageDir(b.PrincipalID))
}

// rejectPairMessage durably aborts a never-sent incomplete reservation, or a
// finalized request after the caller established definite non-admission.
// Only internal transport code may supply finalized=true.
func (k *keyring) rejectPairMessage(b pairMessageBinding, finalized bool) error {
	if !b.valid() {
		return errors.New("sdk: invalid message abort binding")
	}
	unlock, err := k.lockPairMessages(b.PrincipalID)
	if err != nil {
		return err
	}
	defer unlock()
	records, key, err := k.readPairMessageIndex(b.PrincipalID)
	if err != nil {
		return err
	}
	state, ok := records[b.MessageID]
	if !ok || state.Binding != b {
		return errors.New("sdk: message abort binding mismatch")
	}
	if state.Retired && !state.Rejected {
		return errors.New("sdk: admitted message cannot be rejected")
	}
	if state.WireBytes > 0 && !finalized && !state.Rejected {
		return errors.New("sdk: finalized message requires admission resolution")
	}
	state.Retired = true
	state.Rejected = true
	records[b.MessageID] = state
	if err := k.writePairMessageIndex(b.PrincipalID, records, key); err != nil {
		return err
	}
	if err := os.Remove(k.pairMessagePath(b)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return k.syncPendingPairDir(k.pairMessageDir(b.PrincipalID))
}
