package sdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ownerTextProjectMessageSpoolCount = 256
const ownerTextProjectMessageSpoolBytes = 16 << 20
const ownerTextProjectMessageMetadataBytes = 4 << 20

var ErrOwnerTextProjectMessageAdmitted = errors.New("sdk: owner text project message already admitted; retry is not permitted")
var ErrOwnerTextProjectMessageAbandoned = errors.New("sdk: owner text project message explicitly abandoned; retry is not permitted")

// OwnerTextProjectMessageReceipt binds admission to the exact durable wire.
type OwnerTextProjectMessageReceipt struct {
	MessageID      string     `json:"messageId"`
	AdmissionSeq   int64      `json:"admissionSeq"`
	RequestDigest  []byte     `json:"requestDigest"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"createdAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt"`
}

type ownerTextProjectMessageReservation struct {
	Header      OwnerTextProjectMessageHeader `json:"header"`
	InputDigest string                        `json:"inputDigest"`
	ExpiresAt   string                        `json:"expiresAt"`
}
type ownerTextProjectMessageRecord struct {
	Reservation   ownerTextProjectMessageReservation `json:"reservation"`
	State         string                             `json:"state"`
	WireDigest    string                             `json:"wireDigest"`
	AdmissionSeq  int64                              `json:"admissionSeq"`
	Wire          []byte                             `json:"wire"`
	LocalEvidence []byte                             `json:"localEvidence"`
	MAC           []byte                             `json:"mac"`
}

// Whole-store deletion or rollback is outside this spool's guarantees. A
// surviving incomplete reservation remains unusable rather than reencrypting.
func (k *keyring) ownerTextProjectMessageDir(principal string) string {
	return filepath.Join(k.root, principal, "owner-text-project-messages")
}
func (k *keyring) initOwnerTextProjectMessages(principal string) error {
	if !projectUUID(principal, false) {
		return errors.New("sdk: invalid owner text project spool principal")
	}
	parent := filepath.Join(k.root, principal)
	for _, dir := range []string{parent, k.ownerTextProjectMessageDir(principal)} {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			return errors.New("sdk: owner text project spool directory is not private")
		}
		if err = k.syncPendingPairDir(filepath.Dir(dir)); err != nil {
			return err
		}
	}
	return k.cleanupOwnerTextProjectMessageTemps(principal)
}
func (k *keyring) cleanupOwnerTextProjectMessageTemps(principal string) error {
	dir := k.ownerTextProjectMessageDir(principal)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	changed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".pending-") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return errors.New("sdk: unsafe owner text project spool temporary file")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		return k.syncPendingPairDir(dir)
	}
	return nil
}
func encodeOwnerTextProjectMessageRecord(record ownerTextProjectMessageRecord, private []byte) []byte {
	record.MAC = nil
	body, _ := json.Marshal(record)
	record.MAC = ownerTextProjectMessageMAC(private, body)
	raw, _ := json.Marshal(record)
	return raw
}
func (k *keyring) readOwnerTextProjectMessageRecord(principal string, private []byte, id string) (ownerTextProjectMessageRecord, error) {
	var record ownerTextProjectMessageRecord
	if !projectUUID(id, true) {
		return record, errors.New("sdk: invalid owner text project spool ID")
	}
	path := filepath.Join(k.ownerTextProjectMessageDir(principal), id+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if info.Size() > ownerTextProjectMessageSpoolBytes {
		return record, errors.New("sdk: oversized owner text project spool record")
	}
	raw, err := readPrivatePairFile(path)
	if err != nil {
		return record, err
	}
	if len(raw) > ownerTextProjectMessageSpoolBytes || json.Unmarshal(raw, &record) != nil {
		return record, errors.New("sdk: corrupt owner text project spool record")
	}
	mac := record.MAC
	record.MAC = nil
	body, _ := json.Marshal(record)
	if !hmac.Equal(mac, ownerTextProjectMessageMAC(private, body)) || record.Reservation.Header.ID != id || record.Reservation.Header.SenderPrincipalID != principal || !projectHexHash(record.Reservation.InputDigest) {
		return record, errors.New("sdk: owner text project spool authentication failed")
	}
	record.MAC = mac
	if !bytes.Equal(raw, encodeOwnerTextProjectMessageRecord(record, private)) {
		return record, errors.New("sdk: noncanonical owner text project spool record")
	}
	expiry, expiryErr := time.Parse(time.RFC3339Nano, record.Reservation.ExpiresAt)
	h := record.Reservation.Header
	if !validOwnerTextProjectReservedHeader(h) || expiryErr != nil || expiry.UTC().Format(time.RFC3339Nano) != record.Reservation.ExpiresAt || !projectUUID(h.ProjectID, false) || !projectUUID(h.NetworkID, false) || !projectHexHash(h.DescriptorHash) || h.PolicyHash == "" {
		return record, errors.New("sdk: invalid owner text project spool binding")
	}
	switch record.State {
	case "reserved":
		if len(record.Wire) != 0 || len(record.LocalEvidence) != 0 || record.WireDigest != "" || record.AdmissionSeq != 0 {
			return record, errors.New("sdk: corrupt owner text project reservation")
		}
	case "prepared":
		digest := sha256.Sum256(record.Wire)
		if len(record.Wire) == 0 || hex.EncodeToString(digest[:]) != record.WireDigest || record.AdmissionSeq != 0 || !hmac.Equal(record.LocalEvidence, ownerTextProjectLocalEvidence(private, record.Wire)) {
			return record, errors.New("sdk: corrupt prepared owner text project wire")
		}
	case "abandoned":
		if len(record.Wire) != 0 || (record.WireDigest == "" && len(record.LocalEvidence) != 0) || (record.WireDigest != "" && (!projectHexHash(record.WireDigest) || len(record.LocalEvidence) != sha256.Size)) || record.AdmissionSeq != 0 {
			return record, errors.New("sdk: corrupt abandoned owner text project tombstone")
		}
	case "admitted":
		if len(record.Wire) != 0 || !projectHexHash(record.WireDigest) || record.AdmissionSeq <= 0 || len(record.LocalEvidence) != sha256.Size {
			return record, errors.New("sdk: corrupt owner text project admission tombstone")
		}
	default:
		return record, errors.New("sdk: invalid owner text project spool state")
	}
	return record, nil
}

type ownerTextProjectMessageSpoolUsage struct {
	pending, pendingBytes, metadataBytes int
	pendingByProject                     map[string]int
}

func ownerTextProjectRecordMetadataBytes(record ownerTextProjectMessageRecord) int {
	record.Wire = nil
	// Reserve space for the digest and admission sequence before any wire exists,
	// so confirmed admission never needs additional metadata capacity.
	record.State = "abandoned"
	record.WireDigest = strings.Repeat("0", 64)
	record.AdmissionSeq = int64(^uint64(0) >> 1)
	record.LocalEvidence = make([]byte, sha256.Size)
	return len(encodeOwnerTextProjectMessageRecord(record, make([]byte, 32)))
}
func checkOwnerTextProjectSpoolBudget(usage ownerTextProjectMessageSpoolUsage) error {
	for _, count := range usage.pendingByProject {
		if count > ownerTextProjectMessageSpoolCount {
			return errors.New("sdk: owner text project message spool record limit for this project; reconcile uncertain sends with OwnerTextProjectMessageReceipt or explicitly forfeit retries with AbandonOwnerTextProjectMessage")
		}
	}
	if usage.pendingBytes > ownerTextProjectMessageSpoolBytes {
		return errors.New("sdk: owner text project message spool byte limit; reconcile uncertain sends with OwnerTextProjectMessageReceipt or explicitly forfeit retries with AbandonOwnerTextProjectMessage")
	}
	if usage.metadataBytes > ownerTextProjectMessageMetadataBytes {
		return errors.New("sdk: owner text project message spool metadata limit; live predecessor evidence is retained until pinned project expiry")
	}
	return nil
}
func (k *keyring) ownerTextProjectMessageUsage(principal string, private []byte) (ownerTextProjectMessageSpoolUsage, error) {
	usage := ownerTextProjectMessageSpoolUsage{pendingByProject: map[string]int{}}
	entries, err := os.ReadDir(k.ownerTextProjectMessageDir(principal))
	if err != nil {
		return usage, err
	}
	changed := false
	for _, entry := range entries {
		path := filepath.Join(k.ownerTextProjectMessageDir(principal), entry.Name())
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return usage, errors.New("sdk: unexpected owner text project spool entry")
		}
		record, err := k.readOwnerTextProjectMessageRecord(principal, private, strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return usage, err
		}
		expiry, _ := time.Parse(time.RFC3339Nano, record.Reservation.ExpiresAt)
		if (record.State == "admitted" || record.State == "abandoned") && !expiry.After(time.Now()) {
			if err = os.Remove(path); err != nil {
				return usage, err
			}
			changed = true
			continue
		}
		usage.metadataBytes += ownerTextProjectRecordMetadataBytes(record)
		if record.State == "reserved" || record.State == "prepared" {
			usage.pending++
			usage.pendingByProject[record.Reservation.Header.ProjectID]++
			info, err := entry.Info()
			if err != nil {
				return usage, err
			}
			usage.pendingBytes += int(info.Size())
		}
	}
	if changed {
		if err = k.syncPendingPairDir(k.ownerTextProjectMessageDir(principal)); err != nil {
			return usage, err
		}
	}
	return usage, checkOwnerTextProjectSpoolBudget(usage)
}
func (k *keyring) reserveOwnerTextProjectMessage(principal string, private []byte, reservation ownerTextProjectMessageReservation) error {
	expiry, expiryErr := time.Parse(time.RFC3339Nano, reservation.ExpiresAt)
	if !validOwnerTextProjectReservedHeader(reservation.Header) || !projectUUID(reservation.Header.ID, true) || reservation.Header.SenderPrincipalID != principal || !projectHexHash(reservation.InputDigest) || expiryErr != nil || expiry.UTC().Format(time.RFC3339Nano) != reservation.ExpiresAt || !projectUUID(reservation.Header.ProjectID, false) || !projectUUID(reservation.Header.NetworkID, false) || !projectHexHash(reservation.Header.DescriptorHash) || reservation.Header.PolicyHash == "" {
		return errors.New("sdk: invalid owner text project message reservation")
	}
	unlock, err := k.lockOwnerTextProjectMessages(principal)
	if err != nil {
		return err
	}
	defer unlock()
	usage, err := k.ownerTextProjectMessageUsage(principal, private)
	if err != nil {
		return err
	}
	record := ownerTextProjectMessageRecord{Reservation: reservation, State: "reserved"}
	raw := encodeOwnerTextProjectMessageRecord(record, private)
	usage.pending++
	usage.pendingByProject[reservation.Header.ProjectID]++
	usage.pendingBytes += len(raw)
	usage.metadataBytes += ownerTextProjectRecordMetadataBytes(record)
	if err = checkOwnerTextProjectSpoolBudget(usage); err != nil {
		return err
	}
	path := filepath.Join(k.ownerTextProjectMessageDir(principal), reservation.Header.ID+".json")
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("sdk: owner text project message ID is already reserved")
	}
	return k.writePairFileDurable(path, raw)
}
func (k *keyring) storeOwnerTextProjectMessage(principal string, private []byte, reservation ownerTextProjectMessageReservation, wire, evidence []byte) error {
	unlock, err := k.lockOwnerTextProjectMessages(principal)
	if err != nil {
		return err
	}
	defer unlock()
	record, err := k.readOwnerTextProjectMessageRecord(principal, private, reservation.Header.ID)
	if err != nil {
		return err
	}
	expected, _ := json.Marshal(reservation)
	existing, _ := json.Marshal(record.Reservation)
	if !bytes.Equal(expected, existing) || len(wire) == 0 || !hmac.Equal(evidence, ownerTextProjectLocalEvidence(private, wire)) {
		return errors.New("sdk: owner text project message reservation conflict")
	}
	if record.State == "admitted" {
		return ErrOwnerTextProjectMessageAdmitted
	}
	if record.State == "abandoned" {
		return ErrOwnerTextProjectMessageAbandoned
	}
	if len(record.Wire) != 0 {
		if !bytes.Equal(record.Wire, wire) || !bytes.Equal(record.LocalEvidence, evidence) {
			return errors.New("sdk: prepared owner text project wire is immutable")
		}
		return nil
	}
	usage, err := k.ownerTextProjectMessageUsage(principal, private)
	if err != nil {
		return err
	}
	oldBytes := len(encodeOwnerTextProjectMessageRecord(record, private))
	record.Wire = wire
	record.LocalEvidence = bytes.Clone(evidence)
	record.State = "prepared"
	digest := sha256.Sum256(wire)
	record.WireDigest = hex.EncodeToString(digest[:])
	raw := encodeOwnerTextProjectMessageRecord(record, private)
	usage.pendingBytes += len(raw) - oldBytes
	if err = checkOwnerTextProjectSpoolBudget(usage); err != nil {
		return err
	}
	return k.writePairFileDurable(filepath.Join(k.ownerTextProjectMessageDir(principal), reservation.Header.ID+".json"), raw)
}
func (k *keyring) loadOwnerTextProjectMessage(principal string, private []byte, id string) (ownerTextProjectMessageRecord, error) {
	unlock, err := k.lockOwnerTextProjectMessages(principal)
	if err != nil {
		return ownerTextProjectMessageRecord{}, err
	}
	defer unlock()
	record, err := k.readOwnerTextProjectMessageRecord(principal, private, id)
	if err != nil {
		return record, err
	}
	if record.State == "admitted" {
		return record, ErrOwnerTextProjectMessageAdmitted
	}
	if record.State == "abandoned" {
		return record, ErrOwnerTextProjectMessageAbandoned
	}
	if len(record.Wire) == 0 {
		return record, errors.New("sdk: unresolved owner text project message reservation has no retry wire")
	}
	if err = k.syncPendingPairDir(k.ownerTextProjectMessageDir(principal)); err != nil {
		return record, err
	}
	return record, nil
}

// loadOwnerTextProjectMessageBinding reads historical sender evidence without consulting
// active project authority. It never returns a reservation as admission proof.
func (k *keyring) loadOwnerTextProjectMessageBinding(principal string, private []byte, id string) (ownerTextProjectMessageRecord, error) {
	unlock, err := k.lockOwnerTextProjectMessages(principal)
	if err != nil {
		return ownerTextProjectMessageRecord{}, err
	}
	defer unlock()
	record, err := k.readOwnerTextProjectMessageRecord(principal, private, id)
	if err != nil {
		return record, err
	}
	if record.WireDigest == "" {
		return record, errors.New("sdk: unresolved owner text project reservation has no wire digest")
	}
	return record, k.syncPendingPairDir(k.ownerTextProjectMessageDir(principal))
}
func validateOwnerTextProjectRecordReceipt(receipt OwnerTextProjectMessageReceipt, record ownerTextProjectMessageRecord) error {
	digest, err := hex.DecodeString(record.WireDigest)
	if err != nil || len(digest) != 32 || receipt.MessageID != record.Reservation.Header.ID || !bytes.Equal(receipt.RequestDigest, digest) || receipt.AdmissionSeq <= 0 || receipt.CreatedAt.IsZero() || (receipt.Status != "pending" && receipt.Status != "acknowledged") || (record.State == "admitted" && receipt.AdmissionSeq != record.AdmissionSeq) {
		return errors.New("sdk: owner text project message receipt binding mismatch")
	}
	return nil
}
func (k *keyring) retireOwnerTextProjectMessage(principal string, private []byte, project, id string, receipt OwnerTextProjectMessageReceipt) error {
	unlock, err := k.lockOwnerTextProjectMessages(principal)
	if err != nil {
		return err
	}
	defer unlock()
	record, err := k.readOwnerTextProjectMessageRecord(principal, private, id)
	if err != nil {
		return err
	}
	if record.Reservation.Header.ProjectID != project || record.Reservation.Header.SenderPrincipalID != principal || record.State == "reserved" {
		return errors.New("sdk: owner text project admission binding mismatch")
	}
	if err = validateOwnerTextProjectRecordReceipt(receipt, record); err != nil {
		return err
	}
	if record.State == "admitted" {
		return k.syncPendingPairDir(k.ownerTextProjectMessageDir(principal))
	}
	record.State = "admitted"
	record.Wire = nil
	record.AdmissionSeq = receipt.AdmissionSeq
	return k.writePairFileDurable(filepath.Join(k.ownerTextProjectMessageDir(principal), id+".json"), encodeOwnerTextProjectMessageRecord(record, private))
}

// AbandonOwnerTextProjectMessage explicitly forfeits retries, even if the server
// never admitted the message. It discards retry ciphertext while retaining MACed
// ID/header/digest evidence, and the ID cannot be prepared again. This deliberate
// data-loss decision is allowed for active projects and never runs automatically.
func (c *Client) AbandonOwnerTextProjectMessage(project, id string) error {
	if c.kr == nil || !projectUUID(project, false) || !projectUUID(id, true) || !projectUUID(c.principalID.Load(), false) {
		return errors.New("sdk: invalid owner text project abandonment identity")
	}
	principal := c.principalID.Load()
	unlock, err := c.kr.lockOwnerTextProjectMessages(principal)
	if err != nil {
		return err
	}
	defer unlock()
	record, err := c.kr.readOwnerTextProjectMessageRecord(principal, c.identityPriv, id)
	if err != nil {
		return err
	}
	if record.Reservation.Header.ProjectID != project {
		return errors.New("sdk: owner text project abandonment binding mismatch")
	}
	if record.State == "admitted" {
		return ErrOwnerTextProjectMessageAdmitted
	}
	if record.State == "abandoned" {
		return c.kr.syncPendingPairDir(c.kr.ownerTextProjectMessageDir(principal))
	}
	record.State = "abandoned"
	record.Wire = nil
	return c.kr.writePairFileDurable(filepath.Join(c.kr.ownerTextProjectMessageDir(principal), id+".json"), encodeOwnerTextProjectMessageRecord(record, c.identityPriv))
}

func ownerTextProjectMessageMAC(private, data []byte) []byte {
	mac := hmac.New(sha256.New, private)
	mac.Write([]byte("pagnet/owner-text-project/spool/v1\x00"))
	mac.Write(data)
	return mac.Sum(nil)
}
func validOwnerTextProjectReservedHeader(h OwnerTextProjectMessageHeader) bool {
	created, err := time.Parse(time.RFC3339Nano, h.CreatedAt)
	if h.Version != 1 || h.Domain != ownerTextProjectMessageInfo || !projectUUID(h.ID, true) || !projectUUID(h.ThreadID, true) || !projectUUID(h.SenderPrincipalID, false) || !projectUUID(h.RecipientPrincipalID, false) || h.SenderPrincipalID == h.RecipientPrincipalID || err != nil || created.UTC().Format(time.RFC3339Nano) != h.CreatedAt {
		return false
	}
	if h.Kind == "ASK" {
		return h.ID == h.ThreadID && h.CorrelationID == nil
	}
	return h.Kind == "REPLY" && h.CorrelationID != nil && *h.CorrelationID == h.ThreadID && h.ID != h.ThreadID
}
