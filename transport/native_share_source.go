package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

const NativeShareSourceVersion = 1
const NativeShareSourceChallengeInfo = "pagnet/native-share-source/challenge/v1/"
const NativeShareSourceMaxBodyBytes = 4096

// NativeShareSourceChallengeContext binds a challenge to the exact retained
// enrollment and command. Current expiry and replay checks remain caller duties.
type NativeShareSourceChallengeContext struct {
	Version               int       `json:"version"`
	EnrollmentID          domain.ID `json:"enrollmentId"`
	CommandID             domain.ID `json:"commandId"`
	EnrollmentDigest      string    `json:"enrollmentDigest"`
	DescriptorFingerprint string    `json:"descriptorFingerprint"`
	ChallengeID           domain.ID `json:"challengeId"`
	ExpiresAt             string    `json:"expiresAt"`
}

const NativeShareSourceProveProtocol = "native-share-source-prove-v1"
const MsgNativeShareSourceProve = "host.native_share_source_prove"

type NativeShareSourceProvePayload struct {
	NativeShareSourceChallengeContext
	Challenge CryptoHPKEWrap `json:"challenge"`
}

type NativeShareSourceProvedPayload struct {
	NativeShareSourceChallengeContext
	Challenge []byte `json:"challenge"`
	Signature []byte `json:"signature"`
}

var errNativeShareSource = errors.New("transport: invalid native share source proof")

func (c NativeShareSourceChallengeContext) CanonicalBytes() ([]byte, error) {
	if c.Version != NativeShareSourceVersion || !nativeShareBindingID(c.EnrollmentID) || !nativeShareBindingID(c.CommandID) || !nativeShareBindingID(c.ChallengeID) || !nativeShareBindingHex(c.EnrollmentDigest) || !nativeShareBindingHex(c.DescriptorFingerprint) || !nativeShareBindingTime(c.ExpiresAt) {
		return nil, errNativeShareSource
	}
	return json.Marshal(c)
}

// ChallengeAAD excludes the ciphertext. Use with NativeShareSourceChallengeInfo
// and a fresh random 32-byte plaintext in the existing HPKE base suite.
func (c NativeShareSourceChallengeContext) ChallengeAAD() ([]byte, error) {
	raw, err := c.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	return append([]byte("pagnet/native-share-source/challenge-aad/v1/"), raw...), nil
}

func (p NativeShareSourceProvePayload) CanonicalBytes() ([]byte, error) {
	if _, err := p.NativeShareSourceChallengeContext.CanonicalBytes(); err != nil {
		return nil, err
	}
	if len(p.Challenge.Enc) != 32 || len(p.Challenge.Ciphertext) != 48 {
		return nil, errNativeShareSource
	}
	return json.Marshal(p)
}

func (p NativeShareSourceProvedPayload) SignatureBytes() ([]byte, error) {
	if _, err := p.NativeShareSourceChallengeContext.CanonicalBytes(); err != nil {
		return nil, err
	}
	if len(p.Challenge) != 32 {
		return nil, errNativeShareSource
	}
	raw, err := json.Marshal(struct {
		NativeShareSourceChallengeContext
		Challenge []byte `json:"challenge"`
	}{p.NativeShareSourceChallengeContext, p.Challenge})
	return append([]byte("pagnet/native-share-source/proved/v1/"), raw...), err
}

func (p NativeShareSourceProvedPayload) ChallengeHash() (string, error) {
	aad, err := p.ChallengeAAD()
	if err != nil {
		return "", err
	}
	if len(p.Challenge) != 32 {
		return "", errNativeShareSource
	}
	raw := append([]byte("pagnet/native-share-source/challenge-hash/v1/"), aad...)
	digest := sha256.Sum256(append(raw, p.Challenge...))
	return hex.EncodeToString(digest[:]), nil
}

func (p NativeShareSourceProvedPayload) ReceiptDigest() (string, error) {
	raw, err := p.CanonicalBytes()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("pagnet/native-share-source/proof-receipt/v1/"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

func (p NativeShareSourceProvedPayload) CanonicalBytes() ([]byte, error) {
	if _, err := p.SignatureBytes(); err != nil {
		return nil, err
	}
	if len(p.Signature) != ed25519.SignatureSize {
		return nil, errNativeShareSource
	}
	return json.Marshal(p)
}

// Verify requires the independently retained request and challenge hash, and the
// fingerprint and dedicated signer from the retained verified holder descriptor.
// It grants no authority to activate or access a source.
func (p NativeShareSourceProvedPayload) Verify(expected NativeShareSourceProvePayload, expectedHash, expectedDescriptorFingerprint string, trustedSigner ed25519.PublicKey, now time.Time) error {
	if _, err := expected.CanonicalBytes(); err != nil {
		return err
	}
	raw, err := p.SignatureBytes()
	if err != nil {
		return err
	}
	hash, err := p.ChallengeHash()
	if err != nil {
		return err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil || now.IsZero() || !now.Before(expiresAt) || p.NativeShareSourceChallengeContext != expected.NativeShareSourceChallengeContext || !nativeShareBindingHex(expectedHash) || hash != expectedHash || !nativeShareBindingHex(expectedDescriptorFingerprint) || p.DescriptorFingerprint != expectedDescriptorFingerprint || len(trustedSigner) != ed25519.PublicKeySize || !ed25519.Verify(trustedSigner, raw, p.Signature) {
		return errNativeShareSource
	}
	return nil
}

// nativeShareSourceObject rejects ambiguous wire objects before Go's permissive
// struct decoder can accept duplicate keys or case-insensitive field aliases.
func nativeShareSourceObject(raw []byte, fields ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errNativeShareSource
	}
	values := make(map[string]json.RawMessage, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, errNativeShareSource
		}
		name, ok := token.(string)
		if !ok || values[name] != nil {
			return nil, errNativeShareSource
		}
		found := false
		for _, field := range fields {
			found = found || name == field
		}
		var value json.RawMessage
		if !found || decoder.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return nil, errNativeShareSource
		}
		values[name] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(values) != len(fields) {
		return nil, errNativeShareSource
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errNativeShareSource
	}
	return values, nil
}

func nativeShareSourceDecode(raw []byte, proved bool, target any) error {
	if len(raw) > NativeShareSourceMaxBodyBytes {
		return errNativeShareSource
	}
	fields := []string{"version", "enrollmentId", "commandId", "enrollmentDigest", "descriptorFingerprint", "challengeId", "expiresAt", "challenge"}
	if proved {
		fields = append(fields, "signature")
	}
	values, err := nativeShareSourceObject(raw, fields...)
	if err != nil {
		return err
	}
	byteFields := []json.RawMessage{values["challenge"], values["signature"]}
	if !proved {
		wrap, err := nativeShareSourceObject(values["challenge"], "enc", "ciphertext")
		if err != nil {
			return err
		}
		byteFields = []json.RawMessage{wrap["enc"], wrap["ciphertext"]}
	}
	for _, raw := range byteFields {
		var encoded string
		if json.Unmarshal(raw, &encoded) != nil {
			return errNativeShareSource
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
			return errNativeShareSource
		}
	}
	return json.Unmarshal(raw, target)
}

func DecodeNativeShareSourceProvePayload(raw []byte) (NativeShareSourceProvePayload, error) {
	var p NativeShareSourceProvePayload
	if err := nativeShareSourceDecode(raw, false, &p); err != nil {
		return p, err
	}
	_, err := p.CanonicalBytes()
	return p, err
}

func DecodeNativeShareSourceProvedPayload(raw []byte) (NativeShareSourceProvedPayload, error) {
	var p NativeShareSourceProvedPayload
	if err := nativeShareSourceDecode(raw, true, &p); err != nil {
		return p, err
	}
	_, err := p.CanonicalBytes()
	return p, err
}
