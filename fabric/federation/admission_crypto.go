package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

const admissionVersion = "pagnet.fabric.federation-admission.v1"
const admissionChunkBytes = 32 << 10
const admissionCipherLimit = 34 << 10
const admissionValueLimit = 48 << 10

type AdmissionLedger struct {
	config AdmissionConfig
	root   registry.AuthorityIdentity
}
type admissionConfiguration struct {
	Verification VerifyLimits         `json:"verification"`
	Version      string               `json:"version"`
	Key          durable.KeyReference `json:"key"`
	Limits       AdmissionLimits      `json:"limits"`
	Invocations  uint64               `json:"invocations,string"`
	Bytes        uint64               `json:"bytes,string"`
}
type admissionManifest struct {
	ExpiresAt       string           `json:"expiresAt"`
	Deadline        string           `json:"deadline,omitempty"`
	Operation       fabric.Operation `json:"operation"`
	Version         string           `json:"version"`
	Facts           AdmissionFacts   `json:"facts"`
	BundleBytes     uint32           `json:"bundleBytes"`
	Chunks          uint32           `json:"chunks"`
	AttemptID       string           `json:"attemptId,omitempty"`
	Association     *Association     `json:"association,omitempty"`
	CancelRequested bool             `json:"cancelRequested"`
	Cursor          ConsumerCursor   `json:"cursor"`
}
type admissionCipher struct {
	Ciphertext []byte `json:"ciphertext"`
}

func admissionKey(id string) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityFederationInvocation, ID: id}
}
func invocationKey(p fabric.Principal, id string) string {
	raw, _ := json.Marshal(struct {
		Purpose    string
		Principal  fabric.Principal
		Invocation string
	}{admissionVersion, p, id})
	sum := sha256.Sum256(raw)
	return "invocation:" + hex.EncodeToString(sum[:])
}
func chunkKey(id string, i uint32) string {
	raw, _ := json.Marshal(struct {
		ID    string
		Chunk uint32
	}{id, i})
	sum := sha256.Sum256(raw)
	return "chunk:" + hex.EncodeToString(sum[:])
}
func (l *AdmissionLedger) aad(id string, revision uint64) []byte {
	raw, _ := json.Marshal(struct {
		Purpose  string
		Root     registry.AuthorityIdentity
		Key      durable.KeyReference
		ID       string
		Revision uint64
	}{admissionVersion, l.root, l.config.Protector.Reference(), id, revision})
	return raw
}
func missingAuthority(e error) bool {
	var structured *fabric.Error
	return errors.As(e, &structured) && structured.Code == fabric.CodeNotFound
}
func (l *AdmissionLedger) readRaw(tx *registry.AuthorityTx, id string) (registry.AuthorityRecord, []byte, error) {
	row, e := tx.Get(admissionKey(id))
	if e != nil {
		return row, nil, e
	}
	if row.Retired || registry.VerifyAuthorityRecord(l.root, row) != nil || len(row.Value) > admissionValueLimit {
		return row, nil, authError()
	}
	var cipher admissionCipher
	if fabric.DecodeJSONWithLimits(row.Value, &cipher, fabric.WireLimits{MaxBytes: admissionValueLimit, MaxDepth: 4, MaxMembers: 8}) != nil || len(cipher.Ciphertext) == 0 || len(cipher.Ciphertext) > admissionCipherLimit {
		return row, nil, authError()
	}
	plain, e := l.config.Protector.Open(l.aad(id, row.Revision), cipher.Ciphertext)
	if e != nil || len(plain) > admissionChunkBytes {
		clear(plain)
		return row, nil, authError()
	}
	return row, plain, nil
}
func (l *AdmissionLedger) read(tx *registry.AuthorityTx, id string, out any) (registry.AuthorityRecord, error) {
	row, plain, e := l.readRaw(tx, id)
	if e != nil {
		return row, e
	}
	defer clear(plain)
	if fabric.DecodeJSONWithLimits(plain, out, fabric.WireLimits{MaxBytes: admissionChunkBytes, MaxDepth: 32, MaxMembers: 4096}) != nil {
		return row, authError()
	}
	return row, nil
}
func (l *AdmissionLedger) sealRaw(id string, revision uint64, plain []byte) ([]byte, error) {
	if len(plain) == 0 || len(plain) > admissionChunkBytes {
		return nil, protocolError()
	}
	ciphertext, e := l.config.Protector.Seal(l.aad(id, revision), plain)
	if e != nil {
		return nil, e
	}
	defer clear(ciphertext)
	if len(ciphertext) == 0 || len(ciphertext) > admissionCipherLimit {
		return nil, protocolError()
	}
	raw, e := json.Marshal(admissionCipher{ciphertext})
	if e != nil || len(raw) > admissionValueLimit {
		return nil, protocolError()
	}
	return raw, nil
}
func (l *AdmissionLedger) casRaw(tx *registry.AuthorityTx, id string, expected uint64, plain []byte) (registry.AuthorityRecord, int, error) {
	raw, e := l.sealRaw(id, expected+1, plain)
	if e != nil {
		return registry.AuthorityRecord{}, 0, e
	}
	defer clear(raw)
	row, e := tx.CAS(admissionKey(id), expected, raw, false)
	return row, len(raw), e
}
func (l *AdmissionLedger) cas(tx *registry.AuthorityTx, id string, expected uint64, value any) (registry.AuthorityRecord, int, error) {
	plain, e := json.Marshal(value)
	if e != nil {
		return registry.AuthorityRecord{}, 0, e
	}
	defer clear(plain)
	return l.casRaw(tx, id, expected, plain)
}
func sameRoot(a, b registry.AuthorityIdentity) bool {
	return a.Namespace == b.Namespace && a.StoreID == b.StoreID && a.KeyRevision == b.KeyRevision && a.Owner == b.Owner && bytes.Equal(a.PublicKey, b.PublicKey)
}
func (l *AdmissionLedger) withOwner(ctx context.Context, f func(context.Context, *registry.AuthorityTx) error) error {
	if ctx == nil || l == nil || l.config.Owner == nil {
		return authError()
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = bounded
	owner, e := l.config.Owner(ctx)
	if e != nil {
		return e
	}
	return l.config.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{MaxOperations: 4096}, func(tx *registry.AuthorityTx) error { return f(ctx, tx) })
}
