package transport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

const NativeShareEpochVersion = 1
const NativeShareEpochInfo = "pagnet/native-share-epoch/hpke/v1/"

var errNativeShareEpoch = errors.New("transport: invalid native share epoch package")

// NativeShareEpochMetadata is independently retained authorization context for
// one prospective target-network epoch. It grants no installation authority.
// Connection identifiers are exact opaque identifiers captured by the caller.
// EpochPossessionVerifier is a 32-byte Ed25519 public key in lowercase hex.
type NativeShareEpochMetadata struct {
	Version                 int       `json:"version"`
	OperationID             domain.ID `json:"operationId"`
	TenantID                domain.ID `json:"tenantId"`
	NetworkID               domain.ID `json:"networkId"`
	PreviousEpochID         domain.ID `json:"previousEpochId"`
	EpochID                 domain.ID `json:"epochId"`
	EpochPossessionVerifier string    `json:"epochPossessionVerifier"`
	ProposalRevision        uint64    `json:"proposalRevision,string"`
	GrantGeneration         uint64    `json:"grantGeneration,string"`
	BindingDigest           string    `json:"bindingDigest"`
	HolderID                domain.ID `json:"holderId"`
	HolderX25519            string    `json:"holderX25519"`
	CommandID               domain.ID `json:"commandId"`
	CommandConnectionID     string    `json:"commandConnectionId"`
	AuthorityConnectionID   string    `json:"authorityConnectionId"`
	Deadline                string    `json:"deadline"`
}

// AAD has a fixed field order and domain separator; all fields are authenticated.
func (m NativeShareEpochMetadata) AAD() ([]byte, error) {
	if m.Version != NativeShareEpochVersion || m.ProposalRevision == 0 || m.GrantGeneration == 0 || m.EpochID == m.PreviousEpochID || !nativeShareBindingHex(m.EpochPossessionVerifier) || !nativeShareBindingHex(m.BindingDigest) || !nativeShareBindingHex(m.HolderX25519) || !nativeShareBindingTime(m.Deadline) || !nativeShareOpaque(m.CommandConnectionID) || !nativeShareOpaque(m.AuthorityConnectionID) {
		return nil, errNativeShareEpoch
	}
	for _, id := range []domain.ID{m.OperationID, m.TenantID, m.NetworkID, m.PreviousEpochID, m.EpochID, m.HolderID, m.CommandID} {
		if !nativeShareBindingID(id) {
			return nil, errNativeShareEpoch
		}
	}
	raw, err := json.Marshal(m)
	return append([]byte("pagnet/native-share-epoch/aad/v1/"), raw...), err
}

type NativeShareEpochPackage struct {
	Metadata  NativeShareEpochMetadata `json:"metadata"`
	Wrapped   CryptoHPKEWrap           `json:"wrapped"`
	Signature []byte                   `json:"signature"`
}

// SignatureBytes covers both canonical metadata and the exact HPKE ciphertext.
// There is deliberately no claimed signer key in the package.
func (p NativeShareEpochPackage) SignatureBytes() ([]byte, error) {
	if _, err := p.Metadata.AAD(); err != nil {
		return nil, err
	}
	if len(p.Wrapped.Enc) != 32 || len(p.Wrapped.Ciphertext) != 48 {
		return nil, errNativeShareEpoch
	}
	raw, err := json.Marshal(struct {
		Metadata NativeShareEpochMetadata `json:"metadata"`
		Wrapped  CryptoHPKEWrap           `json:"wrapped"`
	}{p.Metadata, p.Wrapped})
	return append([]byte("pagnet/native-share-epoch/signature/v1/"), raw...), err
}

// Verify validates the source signature against caller-pinned expected metadata
// and a trusted source key. It does not prove that EpochPossessionVerifier was
// derived from the encrypted epoch key.
// Replay prevention and checking that PreviousEpochID is still committed remain
// caller duties, as do current authorization and connection liveness checks.
func (p NativeShareEpochPackage) Verify(expected NativeShareEpochMetadata, trustedSource ed25519.PublicKey, now time.Time) error {
	raw, err := p.SignatureBytes()
	if err != nil {
		return err
	}
	deadline, _ := time.Parse(time.RFC3339Nano, p.Metadata.Deadline)
	if p.Metadata != expected || now.IsZero() || !now.Before(deadline) || len(trustedSource) != ed25519.PublicKeySize || !ed25519.Verify(trustedSource, raw, p.Signature) {
		return errNativeShareEpoch
	}
	return nil
}

// DecodeNativeShareEpochPackage rejects unknown fields, trailing data and
// oversized inputs, then verifies against authority supplied outside the wire.
func DecodeNativeShareEpochPackage(raw []byte, expected NativeShareEpochMetadata, trustedSource ed25519.PublicKey, now time.Time) (NativeShareEpochPackage, error) {
	var p NativeShareEpochPackage
	if len(raw) > 16<<10 || !strictNativeShareEpochJSON(raw) {
		return p, errNativeShareEpoch
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return NativeShareEpochPackage{}, errNativeShareEpoch
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return NativeShareEpochPackage{}, errNativeShareEpoch
	}
	if err := p.Verify(expected, trustedSource, now); err != nil {
		return NativeShareEpochPackage{}, err
	}
	return p, nil
}

// Every wire member is nonnullable. Walk tokens before struct decoding because
// encoding/json otherwise accepts duplicate names and case-insensitive aliases.
func strictNativeShareEpochJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	schemas := map[string]map[string]bool{
		"":         {"metadata": true, "wrapped": true, "signature": true},
		"metadata": {"version": true, "operationId": true, "tenantId": true, "networkId": true, "previousEpochId": true, "epochId": true, "epochPossessionVerifier": true, "proposalRevision": true, "grantGeneration": true, "bindingDigest": true, "holderId": true, "holderX25519": true, "commandId": true, "commandConnectionId": true, "authorityConnectionId": true, "deadline": true},
		"wrapped":  {"enc": true, "ciphertext": true},
	}
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
			if path == "" && (name == "metadata" || name == "wrapped") {
				if !object(name) {
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
