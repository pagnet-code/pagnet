package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

const NativeShareEpochSourceInfo = "pagnet/native-share-epoch/source/hpke/v1/"

var errNativeShareEpochSource = errors.New("transport: invalid native share epoch source envelope")

// NativeShareEpochSourceContext is independently pinned source authority. Subject
// binds the exact source host, admission, runner epoch and boot. Connection and
// credential fields bind its live incarnation; none is inferred from the wire.
// HolderX25519 must be a dedicated source holder, distinct from the recipient.
// It confers no authority to install, activate or persist an epoch.
type NativeShareEpochSourceContext struct {
	Subject               NativeShareBindingSubject `json:"subject"`
	ConnectedAt           string                    `json:"connectedAt"`
	HostCredentialID      string                    `json:"hostCredentialId"`
	OwnershipScope        string                    `json:"ownershipScope"`
	ConnectionID          string                    `json:"connectionId"`
	AuthorityConnectionID string                    `json:"authorityConnectionId"`
	HolderID              domain.ID                 `json:"holderId"`
	HolderX25519          string                    `json:"holderX25519"`
	SigningKey            string                    `json:"signingKey"`
	ProposalID            domain.ID                 `json:"proposalId"`
	GrantID               domain.ID                 `json:"grantId"`
	BindingID             domain.ID                 `json:"bindingId"`
}

func (s NativeShareEpochSourceContext) CanonicalBytes() ([]byte, error) {
	if _, err := s.Subject.CanonicalBytes(); err != nil {
		return nil, errNativeShareEpochSource
	}
	if !nativeShareBindingTime(s.ConnectedAt) || !nativeShareOpaque(s.HostCredentialID) || !nativeShareOpaque(s.OwnershipScope) || !nativeShareOpaque(s.ConnectionID) || !nativeShareOpaque(s.AuthorityConnectionID) || !nativeShareBindingHex(s.HolderX25519) || !nativeShareBindingHex(s.SigningKey) {
		return nil, errNativeShareEpochSource
	}
	for _, id := range []domain.ID{s.HolderID, s.ProposalID, s.GrantID, s.BindingID} {
		if !nativeShareBindingID(id) {
			return nil, errNativeShareEpochSource
		}
	}
	return json.Marshal(s)
}

// NativeShareEpochSourceMetadata binds the full selected-recipient context and
// the digest of its signed package, as well as the independent source holder.
// RecipientPackageDigest is SHA-256 of the canonical JSON signed package.
type NativeShareEpochSourceMetadata struct {
	Recipient              NativeShareEpochMetadata      `json:"recipient"`
	Source                 NativeShareEpochSourceContext `json:"source"`
	RecipientPackageDigest string                        `json:"recipientPackageDigest"`
}

func (m NativeShareEpochSourceMetadata) AAD() ([]byte, error) {
	if _, err := m.Recipient.AAD(); err != nil {
		return nil, errNativeShareEpochSource
	}
	if _, err := m.Source.CanonicalBytes(); err != nil {
		return nil, err
	}
	if !nativeShareBindingHex(m.RecipientPackageDigest) || m.Source.HolderID == m.Recipient.HolderID || m.Source.HolderX25519 == m.Recipient.HolderX25519 {
		return nil, errNativeShareEpochSource
	}
	raw, err := json.Marshal(m)
	return append([]byte("pagnet/native-share-epoch/source/aad/v1/"), raw...), err
}

// NativeShareEpochPackageDigest identifies the complete signed recipient package.
// It validates structure only; callers must independently verify its signature.
func NativeShareEpochPackageDigest(p NativeShareEpochPackage) (string, error) {
	if _, err := p.SignatureBytes(); err != nil {
		return "", err
	}
	if len(p.Signature) != ed25519.SignatureSize {
		return "", errNativeShareEpochSource
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

type NativeShareEpochSourceEnvelope struct {
	Metadata  NativeShareEpochSourceMetadata `json:"metadata"`
	Wrapped   CryptoHPKEWrap                 `json:"wrapped"`
	Signature []byte                         `json:"signature"`
}

func (p NativeShareEpochSourceEnvelope) SignatureBytes() ([]byte, error) {
	if _, err := p.Metadata.AAD(); err != nil {
		return nil, err
	}
	if len(p.Wrapped.Enc) != 32 || len(p.Wrapped.Ciphertext) != 48 {
		return nil, errNativeShareEpochSource
	}
	raw, err := json.Marshal(struct {
		Metadata NativeShareEpochSourceMetadata `json:"metadata"`
		Wrapped  CryptoHPKEWrap                 `json:"wrapped"`
	}{p.Metadata, p.Wrapped})
	return append([]byte("pagnet/native-share-epoch/source/signature/v1/"), raw...), err
}

// Verify requires full expected metadata and a source signing key from trusted
// state. Previous-epoch currency, authorization, liveness and replay prevention
// remain caller duties. It proves no possession of the encrypted epoch key.
func (p NativeShareEpochSourceEnvelope) Verify(expected NativeShareEpochSourceMetadata, trustedSource ed25519.PublicKey, now time.Time) error {
	raw, err := p.SignatureBytes()
	if err != nil {
		return err
	}
	deadline, _ := time.Parse(time.RFC3339Nano, p.Metadata.Recipient.Deadline)
	if p.Metadata != expected || now.IsZero() || !now.Before(deadline) || len(trustedSource) != ed25519.PublicKeySize || hex.EncodeToString(trustedSource) != expected.Source.SigningKey || !ed25519.Verify(trustedSource, raw, p.Signature) {
		return errNativeShareEpochSource
	}
	return nil
}

func DecodeNativeShareEpochSourceEnvelope(raw []byte, expected NativeShareEpochSourceMetadata, trustedSource ed25519.PublicKey, now time.Time) (NativeShareEpochSourceEnvelope, error) {
	var p NativeShareEpochSourceEnvelope
	if !strictNativeShareEpochSourceJSON(raw) || json.Unmarshal(raw, &p) != nil {
		return NativeShareEpochSourceEnvelope{}, errNativeShareEpochSource
	}
	if err := p.Verify(expected, trustedSource, now); err != nil {
		return NativeShareEpochSourceEnvelope{}, err
	}
	return p, nil
}

// Walk the exact schema before struct decoding: encoding/json otherwise permits
// duplicate names, case aliases and null members. Every member is required.
func strictNativeShareEpochSourceJSON(raw []byte) bool {
	if len(raw) > 16<<10 {
		return false
	}
	schemas := map[string]map[string]bool{
		"":                        {"metadata": true, "wrapped": true, "signature": true},
		"metadata":                {"recipient": true, "source": true, "recipientPackageDigest": true},
		"metadata.recipient":      {"version": true, "operationId": true, "tenantId": true, "networkId": true, "previousEpochId": true, "epochId": true, "epochPossessionVerifier": true, "proposalRevision": true, "grantGeneration": true, "bindingDigest": true, "holderId": true, "holderX25519": true, "commandId": true, "commandConnectionId": true, "authorityConnectionId": true, "deadline": true},
		"metadata.source":         {"subject": true, "connectedAt": true, "hostCredentialId": true, "ownershipScope": true, "connectionId": true, "authorityConnectionId": true, "holderId": true, "holderX25519": true, "signingKey": true, "proposalId": true, "grantId": true, "bindingId": true},
		"metadata.source.subject": {"serverUrl": true, "tenantId": true, "accountId": true, "hostId": true, "nativeAdmissionId": true, "runnerId": true, "runnerEpoch": true, "bootId": true, "profileFingerprint": true},
		"wrapped":                 {"enc": true, "ciphertext": true},
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var object func(string) bool
	object = func(path string) bool {
		token, err := d.Token()
		if err != nil || token != json.Delim('{') {
			return false
		}
		seen := make(map[string]bool)
		for d.More() {
			token, err = d.Token()
			name, ok := token.(string)
			if err != nil || !ok || seen[name] || !schemas[path][name] {
				return false
			}
			seen[name] = true
			child := name
			if path != "" {
				child = path + "." + name
			}
			if _, nested := schemas[child]; nested {
				if !object(child) {
					return false
				}
			} else {
				token, err = d.Token()
				if err != nil || token == nil {
					return false
				}
				if _, ok := token.(json.Delim); ok {
					return false
				}
			}
		}
		token, err = d.Token()
		return err == nil && token == json.Delim('}') && len(seen) == len(schemas[path])
	}
	if !object("") {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
