package e2ee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	OwnerMailboxHPKEInfo             = "pagnet/owner-mailbox/keys/v1"
	OwnerMailboxMaxPlaintext         = 64 * 1024
	OwnerMailboxSequenceLimit uint64 = 1 << 20
	OwnerMailboxClientToHost  byte   = 0
	OwnerMailboxHostToClient  byte   = 1
)

// OwnerMailboxDescriptor is the immutable, public context of a personal mailbox
// session. IDs are canonical lowercase UUIDs. Generation is in [1, MaxInt64];
// timestamps are browser-safe Unix seconds with an exact 900 second lifetime.
type OwnerMailboxDescriptor struct {
	TenantID             string    `json:"tenantId"`
	OwnerUserID          string    `json:"ownerUserId"`
	InstallationID       string    `json:"installationId"`
	ServiceID            string    `json:"serviceId"`
	HostID               string    `json:"hostId"`
	SessionID            string    `json:"sessionId"`
	RunnerID             string    `json:"runnerId"`
	RunnerEpoch          time.Time `json:"runnerEpoch"`
	HostCredentialID     string    `json:"hostCredentialId"`
	Generation           uint64    `json:"generation"`
	BrowserX25519Pub     []byte    `json:"browserX25519Pub"`
	HostX25519Pub        []byte    `json:"hostX25519Pub"`
	HostEd25519Pub       []byte    `json:"hostEd25519Pub"`
	IssuedAtUnixSeconds  uint64    `json:"issuedAtUnixSeconds"`
	ExpiresAtUnixSeconds uint64    `json:"expiresAtUnixSeconds"`
}

func ownerMailboxField(dst, field []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(field)))
	return append(dst, field...)
}

// EncodeOwnerMailboxDescriptor returns the v1 descriptor bytes B. The fixed
// scope and domains are protocol constants, never caller supplied values.
func EncodeOwnerMailboxDescriptor(d OwnerMailboxDescriptor) ([]byte, error) {
	ids := []string{d.TenantID, d.OwnerUserID, d.InstallationID, d.ServiceID, d.HostID, d.SessionID, d.RunnerID, d.HostCredentialID}
	for _, id := range ids {
		parsed, err := uuid.Parse(id)
		if !utf8.ValidString(id) || err != nil || parsed.String() != id {
			return nil, errors.New("e2ee: invalid owner mailbox UUID")
		}
	}
	if d.Generation == 0 || d.Generation > math.MaxInt64 {
		return nil, errors.New("e2ee: invalid owner mailbox generation")
	}
	if d.RunnerEpoch.IsZero() || d.RunnerEpoch.Year() < 0 || d.RunnerEpoch.Year() > 9999 {
		return nil, errors.New("e2ee: invalid owner mailbox runner epoch")
	}
	const maxSafeInteger = 1<<53 - 1
	if d.ExpiresAtUnixSeconds > maxSafeInteger || d.IssuedAtUnixSeconds > maxSafeInteger-900 || d.ExpiresAtUnixSeconds != d.IssuedAtUnixSeconds+900 {
		return nil, errors.New("e2ee: invalid owner mailbox lifetime")
	}
	for _, key := range [][]byte{d.BrowserX25519Pub, d.HostX25519Pub, d.HostEd25519Pub} {
		if len(key) != 32 {
			return nil, errors.New("e2ee: invalid owner mailbox public key length")
		}
	}
	b := []byte("pagnet/owner-mailbox/session/v1\x00")
	fields := []string{"personal", d.TenantID, d.OwnerUserID, d.InstallationID, d.ServiceID, d.HostID, d.SessionID, d.RunnerID,
		d.RunnerEpoch.UTC().Format("2006-01-02T15:04:05.000000000Z"), d.HostCredentialID, strconv.FormatUint(d.Generation, 10)}
	for _, field := range fields {
		b = ownerMailboxField(b, []byte(field))
	}
	for _, key := range [][]byte{d.BrowserX25519Pub, d.HostX25519Pub, d.HostEd25519Pub} {
		b = ownerMailboxField(b, key)
	}
	b = binary.BigEndian.AppendUint64(b, d.IssuedAtUnixSeconds)
	return binary.BigEndian.AppendUint64(b, d.ExpiresAtUnixSeconds), nil
}

// OwnerMailboxKeys holds independently sampled directional AES-256 keys.
// Callers must keep them secret and enforce sequence uniqueness per direction.
type OwnerMailboxKeys struct {
	ClientToHost [32]byte
	HostToClient [32]byte
}

// OwnerMailboxBootstrap carries the HPKE encapsulation and host signature.
type OwnerMailboxBootstrap struct {
	Enc        []byte `json:"enc"`
	Ciphertext []byte `json:"ct"`
	Signature  []byte `json:"signature"`
}

// OwnerMailboxBootstrapTranscript returns the exact Ed25519 transcript T.
func OwnerMailboxBootstrapTranscript(d OwnerMailboxDescriptor, enc, ct []byte) ([]byte, error) {
	b, err := EncodeOwnerMailboxDescriptor(d)
	if err != nil {
		return nil, err
	}
	if len(enc) != 32 || len(ct) != 80 {
		return nil, errors.New("e2ee: invalid owner mailbox HPKE lengths")
	}
	t := ownerMailboxField([]byte("pagnet/owner-mailbox/bootstrap-signature/v1\x00"), b)
	t = ownerMailboxField(t, enc)
	return ownerMailboxField(t, ct), nil
}

// CreateOwnerMailboxBootstrap samples fresh directional keys, seals them to the
// browser, and signs the transcript with the descriptor's host Ed25519 key.
func CreateOwnerMailboxBootstrap(d OwnerMailboxDescriptor, signer ed25519.PrivateKey) (OwnerMailboxBootstrap, OwnerMailboxKeys, error) {
	var bootstrap OwnerMailboxBootstrap
	var keys OwnerMailboxKeys
	b, err := EncodeOwnerMailboxDescriptor(d)
	if err != nil {
		return bootstrap, keys, err
	}
	if len(signer) != ed25519.PrivateKeySize || !bytes.Equal(signer.Public().(ed25519.PublicKey), d.HostEd25519Pub) {
		return bootstrap, keys, errors.New("e2ee: owner mailbox signer mismatch")
	}
	plaintext := make([]byte, 64)
	if _, err := rand.Read(plaintext); err != nil {
		return bootstrap, keys, err
	}
	enc, ct, err := HPKEWrap(d.BrowserX25519Pub, []byte(OwnerMailboxHPKEInfo), b, plaintext)
	if err != nil {
		return bootstrap, keys, err
	}
	t, err := OwnerMailboxBootstrapTranscript(d, enc, ct)
	if err != nil {
		return bootstrap, keys, err
	}
	copy(keys.ClientToHost[:], plaintext[:32])
	copy(keys.HostToClient[:], plaintext[32:])
	return OwnerMailboxBootstrap{Enc: enc, Ciphertext: ct, Signature: ed25519.Sign(signer, t)}, keys, nil
}

// VerifyOwnerMailboxBootstrap checks the host signature before unwrapping the
// keys. The caller must authenticate the descriptor's host key and identities
// and check expiration against its clock before accepting the session.
func VerifyOwnerMailboxBootstrap(d OwnerMailboxDescriptor, bootstrap OwnerMailboxBootstrap, browserPrivateKey []byte) (OwnerMailboxKeys, error) {
	var keys OwnerMailboxKeys
	t, err := OwnerMailboxBootstrapTranscript(d, bootstrap.Enc, bootstrap.Ciphertext)
	if err != nil {
		return keys, err
	}
	if !ed25519.Verify(ed25519.PublicKey(d.HostEd25519Pub), t, bootstrap.Signature) {
		return keys, errors.New("e2ee: invalid owner mailbox bootstrap signature")
	}
	b, _ := EncodeOwnerMailboxDescriptor(d)
	plaintext, err := HPKEUnwrap(browserPrivateKey, bootstrap.Enc, []byte(OwnerMailboxHPKEInfo), b, bootstrap.Ciphertext)
	if err != nil {
		return keys, fmt.Errorf("e2ee: owner mailbox unwrap: %w", err)
	}
	if len(plaintext) != 64 {
		return keys, errors.New("e2ee: invalid owner mailbox key material")
	}
	copy(keys.ClientToHost[:], plaintext[:32])
	copy(keys.HostToClient[:], plaintext[32:])
	return keys, nil
}

// OwnerMailboxFrameAAD binds a frame to B, direction, and explicit sequence.
func OwnerMailboxFrameAAD(d OwnerMailboxDescriptor, direction byte, seq uint64) ([]byte, error) {
	b, err := EncodeOwnerMailboxDescriptor(d)
	if err != nil {
		return nil, err
	}
	if direction > OwnerMailboxHostToClient || seq >= OwnerMailboxSequenceLimit {
		return nil, errors.New("e2ee: invalid owner mailbox frame direction or sequence")
	}
	hash := sha256.Sum256(b)
	aad := append([]byte("pagnet/owner-mailbox/frame/v1\x00"), hash[:]...)
	aad = append(aad, direction)
	return binary.BigEndian.AppendUint64(aad, seq), nil
}

func ownerMailboxFrameCipher(key []byte, seq uint64) (cipher.AEAD, []byte, error) {
	if len(key) != 32 {
		return nil, nil, errors.New("e2ee: invalid owner mailbox frame key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return aead, nonce, err
}

// SealOwnerMailboxFrame seals one frame. The caller must never reuse a sequence
// with the same directional key, including across reconnects.
func SealOwnerMailboxFrame(d OwnerMailboxDescriptor, key []byte, direction byte, seq uint64, plaintext []byte) ([]byte, error) {
	aad, err := OwnerMailboxFrameAAD(d, direction, seq)
	if err != nil {
		return nil, err
	}
	if len(plaintext) > OwnerMailboxMaxPlaintext {
		return nil, errors.New("e2ee: owner mailbox frame too large")
	}
	aead, nonce, err := ownerMailboxFrameCipher(key, seq)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// OpenOwnerMailboxFrame authenticates one frame. Replay rejection and expected
// sequence tracking belong to the caller's session state.
func OpenOwnerMailboxFrame(d OwnerMailboxDescriptor, key []byte, direction byte, seq uint64, ciphertext []byte) ([]byte, error) {
	aad, err := OwnerMailboxFrameAAD(d, direction, seq)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < 16 || len(ciphertext) > OwnerMailboxMaxPlaintext+16 {
		return nil, errors.New("e2ee: invalid owner mailbox ciphertext size")
	}
	aead, nonce, err := ownerMailboxFrameCipher(key, seq)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
