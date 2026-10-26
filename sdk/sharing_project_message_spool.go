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

const projectMessageSpoolCount = 256
const projectMessageSpoolBytes = 16 << 20
const projectMessageMetadataBytes = 4 << 20

var ErrSharingProjectMessageAdmitted = errors.New("sdk: project message already admitted; retry is not permitted")
var ErrSharingProjectMessageAbandoned = errors.New("sdk: project message explicitly abandoned; retry is not permitted")

type projectMessageReservation struct {
	Header      SharingProjectMessageHeader `json:"header"`
	InputDigest string                      `json:"inputDigest"`
	ExpiresAt   string                      `json:"expiresAt"`
}
type projectMessageRecord struct {
	Reservation  projectMessageReservation `json:"reservation"`
	State        string                    `json:"state"`
	WireDigest   string                    `json:"wireDigest"`
	AdmissionSeq int64                     `json:"admissionSeq"`
	Wire         []byte                    `json:"wire"`
	MAC          []byte                    `json:"mac"`
}

// Whole-store deletion or rollback is outside this spool's guarantees. A
// surviving incomplete reservation remains unusable rather than reencrypting.
func (k *keyring) projectMessageDir(principal string) string {
	return filepath.Join(k.root, principal, "project-messages")
}
func (k *keyring) initProjectMessages(principal string) error {
	if !projectUUID(principal, false) {
		return errors.New("sdk: invalid project spool principal")
	}
	parent := filepath.Join(k.root, principal)
	for _, dir := range []string{parent, k.projectMessageDir(principal)} {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			return errors.New("sdk: project spool directory is not private")
		}
		if err = k.syncPendingPairDir(filepath.Dir(dir)); err != nil {
			return err
		}
	}
	return k.cleanupProjectMessageTemps(principal)
}
func (k *keyring) cleanupProjectMessageTemps(principal string) error {
	dir := k.projectMessageDir(principal)
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
			return errors.New("sdk: unsafe project spool temporary file")
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
func encodeProjectMessageRecord(record projectMessageRecord, private []byte) []byte {
	record.MAC = nil
	body, _ := json.Marshal(record)
	record.MAC = projectMessageMAC(private, body)
	raw, _ := json.Marshal(record)
	return raw
}
func (k *keyring) readProjectMessageRecord(principal string, private []byte, id string) (projectMessageRecord, error) {
	var record projectMessageRecord
	if !projectUUID(id, true) {
		return record, errors.New("sdk: invalid project spool ID")
	}
	path := filepath.Join(k.projectMessageDir(principal), id+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if info.Size() > projectMessageSpoolBytes {
		return record, errors.New("sdk: oversized project spool record")
	}
	raw, err := readPrivatePairFile(path)
	if err != nil {
		return record, err
	}
	if len(raw) > projectMessageSpoolBytes || json.Unmarshal(raw, &record) != nil {
		return record, errors.New("sdk: corrupt project spool record")
	}
	mac := record.MAC
	record.MAC = nil
	body, _ := json.Marshal(record)
	if !hmac.Equal(mac, projectMessageMAC(private, body)) || record.Reservation.Header.ID != id || record.Reservation.Header.SenderPrincipalID != principal || !projectHexHash(record.Reservation.InputDigest) {
		return record, errors.New("sdk: project spool authentication failed")
	}
	record.MAC = mac
	if !bytes.Equal(raw, encodeProjectMessageRecord(record, private)) {
		return record, errors.New("sdk: noncanonical project spool record")
	}
	expiry, expiryErr := time.Parse(time.RFC3339Nano, record.Reservation.ExpiresAt)
	h := record.Reservation.Header
	if expiryErr != nil || expiry.UTC().Format(time.RFC3339Nano) != record.Reservation.ExpiresAt || !projectUUID(h.ProjectID, false) || !projectUUID(h.NetworkID, false) || !projectHexHash(h.DescriptorHash) || !projectHexHash(h.PolicyHash) {
		return record, errors.New("sdk: invalid project spool binding")
	}
	switch record.State {
	case "reserved":
		if len(record.Wire) != 0 || record.WireDigest != "" || record.AdmissionSeq != 0 {
			return record, errors.New("sdk: corrupt project reservation")
		}
	case "prepared":
		digest := sha256.Sum256(record.Wire)
		if len(record.Wire) == 0 || hex.EncodeToString(digest[:]) != record.WireDigest || record.AdmissionSeq != 0 {
			return record, errors.New("sdk: corrupt prepared project wire")
		}
	case "abandoned":
		if len(record.Wire) != 0 || (record.WireDigest != "" && !projectHexHash(record.WireDigest)) || record.AdmissionSeq != 0 {
			return record, errors.New("sdk: corrupt abandoned project tombstone")
		}
	case "admitted":
		if len(record.Wire) != 0 || !projectHexHash(record.WireDigest) || record.AdmissionSeq <= 0 {
			return record, errors.New("sdk: corrupt project admission tombstone")
		}
	default:
		return record, errors.New("sdk: invalid project spool state")
	}
	return record, nil
}

type projectMessageSpoolUsage struct {
	pending, pendingBytes, metadataBytes int
	pendingByProject                     map[string]int
}

func projectRecordMetadataBytes(record projectMessageRecord) int {
	record.Wire = nil
	// Reserve space for the digest and admission sequence before any wire exists,
	// so confirmed admission never needs additional metadata capacity.
	record.State = "abandoned"
	record.WireDigest = strings.Repeat("0", 64)
	record.AdmissionSeq = int64(^uint64(0) >> 1)
	return len(encodeProjectMessageRecord(record, make([]byte, 32)))
}
func checkProjectSpoolBudget(usage projectMessageSpoolUsage) error {
	for _, count := range usage.pendingByProject {
		if count > projectMessageSpoolCount {
			return errors.New("sdk: project message spool record limit for this project; reconcile uncertain sends with SharingProjectMessageReceipt or explicitly forfeit retries with AbandonSharingProjectMessage")
		}
	}
	if usage.pendingBytes > projectMessageSpoolBytes {
		return errors.New("sdk: project message spool byte limit; reconcile uncertain sends with SharingProjectMessageReceipt or explicitly forfeit retries with AbandonSharingProjectMessage")
	}
	if usage.metadataBytes > projectMessageMetadataBytes {
		return errors.New("sdk: project message spool metadata limit; live predecessor evidence is retained until pinned project expiry")
	}
	return nil
}
func (k *keyring) projectMessageUsage(principal string, private []byte) (projectMessageSpoolUsage, error) {
	usage := projectMessageSpoolUsage{pendingByProject: map[string]int{}}
	entries, err := os.ReadDir(k.projectMessageDir(principal))
	if err != nil {
		return usage, err
	}
	changed := false
	for _, entry := range entries {
		path := filepath.Join(k.projectMessageDir(principal), entry.Name())
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return usage, errors.New("sdk: unexpected project spool entry")
		}
		record, err := k.readProjectMessageRecord(principal, private, strings.TrimSuffix(entry.Name(), ".json"))
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
		usage.metadataBytes += projectRecordMetadataBytes(record)
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
		if err = k.syncPendingPairDir(k.projectMessageDir(principal)); err != nil {
			return usage, err
		}
	}
	return usage, checkProjectSpoolBudget(usage)
}
func (k *keyring) reserveProjectMessage(principal string, private []byte, reservation projectMessageReservation) error {
	expiry, expiryErr := time.Parse(time.RFC3339Nano, reservation.ExpiresAt)
	if !projectUUID(reservation.Header.ID, true) || reservation.Header.SenderPrincipalID != principal || !projectHexHash(reservation.InputDigest) || expiryErr != nil || expiry.UTC().Format(time.RFC3339Nano) != reservation.ExpiresAt || !projectUUID(reservation.Header.ProjectID, false) || !projectUUID(reservation.Header.NetworkID, false) || !projectHexHash(reservation.Header.DescriptorHash) || !projectHexHash(reservation.Header.PolicyHash) {
		return errors.New("sdk: invalid project message reservation")
	}
	unlock, err := k.lockProjectMessages(principal)
	if err != nil {
		return err
	}
	defer unlock()
	usage, err := k.projectMessageUsage(principal, private)
	if err != nil {
		return err
	}
	record := projectMessageRecord{Reservation: reservation, State: "reserved"}
	raw := encodeProjectMessageRecord(record, private)
	usage.pending++
	usage.pendingByProject[reservation.Header.ProjectID]++
	usage.pendingBytes += len(raw)
	usage.metadataBytes += projectRecordMetadataBytes(record)
	if err = checkProjectSpoolBudget(usage); err != nil {
		return err
	}
	path := filepath.Join(k.projectMessageDir(principal), reservation.Header.ID+".json")
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("sdk: project message ID is already reserved")
	}
	return k.writePairFileDurable(path, raw)
}
func (k *keyring) storeProjectMessage(principal string, private []byte, reservation projectMessageReservation, wire []byte) error {
	unlock, err := k.lockProjectMessages(principal)
	if err != nil {
		return err
	}
	defer unlock()
	record, err := k.readProjectMessageRecord(principal, private, reservation.Header.ID)
	if err != nil {
		return err
	}
	expected, _ := json.Marshal(reservation)
	existing, _ := json.Marshal(record.Reservation)
	if !bytes.Equal(expected, existing) || len(wire) == 0 {
		return errors.New("sdk: project message reservation conflict")
	}
	if record.State == "admitted" {
		return ErrSharingProjectMessageAdmitted
	}
	if record.State == "abandoned" {
		return ErrSharingProjectMessageAbandoned
	}
	if len(record.Wire) != 0 {
		if !bytes.Equal(record.Wire, wire) {
			return errors.New("sdk: prepared project wire is immutable")
		}
		return nil
	}
	usage, err := k.projectMessageUsage(principal, private)
	if err != nil {
		return err
	}
	oldBytes := len(encodeProjectMessageRecord(record, private))
	record.Wire = wire
	record.State = "prepared"
	digest := sha256.Sum256(wire)
	record.WireDigest = hex.EncodeToString(digest[:])
	raw := encodeProjectMessageRecord(record, private)
	usage.pendingBytes += len(raw) - oldBytes
	if err = checkProjectSpoolBudget(usage); err != nil {
		return err
	}
	return k.writePairFileDurable(filepath.Join(k.projectMessageDir(principal), reservation.Header.ID+".json"), raw)
}
func (k *keyring) loadProjectMessage(principal string, private []byte, id string) (projectMessageRecord, error) {
	unlock, err := k.lockProjectMessages(principal)
	if err != nil {
		return projectMessageRecord{}, err
	}
	defer unlock()
	record, err := k.readProjectMessageRecord(principal, private, id)
	if err != nil {
		return record, err
	}
	if record.State == "admitted" {
		return record, ErrSharingProjectMessageAdmitted
	}
	if record.State == "abandoned" {
		return record, ErrSharingProjectMessageAbandoned
	}
	if len(record.Wire) == 0 {
		return record, errors.New("sdk: unresolved project message reservation has no retry wire")
	}
	if err = k.syncPendingPairDir(k.projectMessageDir(principal)); err != nil {
		return record, err
	}
	return record, nil
}

// loadProjectMessageBinding reads historical sender evidence without consulting
// active project authority. It never returns a reservation as admission proof.
func (k *keyring) loadProjectMessageBinding(principal string, private []byte, id string) (projectMessageRecord, error) {
	unlock, err := k.lockProjectMessages(principal)
	if err != nil {
		return projectMessageRecord{}, err
	}
	defer unlock()
	record, err := k.readProjectMessageRecord(principal, private, id)
	if err != nil {
		return record, err
	}
	if record.WireDigest == "" {
		return record, errors.New("sdk: unresolved project reservation has no wire digest")
	}
	return record, k.syncPendingPairDir(k.projectMessageDir(principal))
}
func validateProjectRecordReceipt(receipt SharingProjectMessageReceipt, record projectMessageRecord) error {
	digest, err := hex.DecodeString(record.WireDigest)
	if err != nil || len(digest) != 32 || receipt.MessageID != record.Reservation.Header.ID || !bytes.Equal(receipt.RequestDigest, digest) || receipt.AdmissionSeq <= 0 || receipt.CreatedAt.IsZero() || (receipt.Status != "pending" && receipt.Status != "acknowledged") || (record.State == "admitted" && receipt.AdmissionSeq != record.AdmissionSeq) {
		return errors.New("sdk: project message receipt binding mismatch")
	}
	return nil
}
func (k *keyring) retireProjectMessage(principal string, private []byte, project, id string, receipt SharingProjectMessageReceipt) error {
	unlock, err := k.lockProjectMessages(principal)
	if err != nil {
		return err
	}
	defer unlock()
	record, err := k.readProjectMessageRecord(principal, private, id)
	if err != nil {
		return err
	}
	if record.Reservation.Header.ProjectID != project || record.Reservation.Header.SenderPrincipalID != principal || record.State == "reserved" {
		return errors.New("sdk: project admission binding mismatch")
	}
	if err = validateProjectRecordReceipt(receipt, record); err != nil {
		return err
	}
	if record.State == "admitted" {
		return k.syncPendingPairDir(k.projectMessageDir(principal))
	}
	record.State = "admitted"
	record.Wire = nil
	record.AdmissionSeq = receipt.AdmissionSeq
	return k.writePairFileDurable(filepath.Join(k.projectMessageDir(principal), id+".json"), encodeProjectMessageRecord(record, private))
}

// AbandonSharingProjectMessage explicitly forfeits retries, even if the server
// never admitted the message. It discards retry ciphertext while retaining MACed
// ID/header/digest evidence, and the ID cannot be prepared again. This deliberate
// data-loss decision is allowed for active projects and never runs automatically.
func (c *Client) AbandonSharingProjectMessage(project, id string) error {
	if c.kr == nil || !projectUUID(project, false) || !projectUUID(id, true) || !projectUUID(c.principalID.Load(), false) {
		return errors.New("sdk: invalid project abandonment identity")
	}
	principal := c.principalID.Load()
	unlock, err := c.kr.lockProjectMessages(principal)
	if err != nil {
		return err
	}
	defer unlock()
	record, err := c.kr.readProjectMessageRecord(principal, c.identityPriv, id)
	if err != nil {
		return err
	}
	if record.Reservation.Header.ProjectID != project {
		return errors.New("sdk: project abandonment binding mismatch")
	}
	if record.State == "admitted" {
		return ErrSharingProjectMessageAdmitted
	}
	if record.State == "abandoned" {
		return c.kr.syncPendingPairDir(c.kr.projectMessageDir(principal))
	}
	record.State = "abandoned"
	record.Wire = nil
	return c.kr.writePairFileDurable(filepath.Join(c.kr.projectMessageDir(principal), id+".json"), encodeProjectMessageRecord(record, c.identityPriv))
}
