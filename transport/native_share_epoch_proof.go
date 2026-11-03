package transport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

var errNativeShareEpochProof = errors.New("transport: invalid native share epoch proof")

// NativeShareEpochProofChallenge binds a fresh possession proof to retained stage context.
type NativeShareEpochProofChallenge struct {
	Version     int                      `json:"version"`
	BindingID   domain.ID                `json:"bindingId"`
	StageDigest string                   `json:"stageDigest"`
	Metadata    NativeShareEpochMetadata `json:"metadata"`
	CommandID   domain.ID                `json:"commandId"`
	ChallengeID domain.ID                `json:"challengeId"`
	Nonce       []byte                   `json:"nonce"`
	ExpiresAt   string                   `json:"expiresAt"`
}

func (c NativeShareEpochProofChallenge) CanonicalBytes() ([]byte, error) {
	if c.Version != NativeShareEpochVersion || !nativeShareBindingID(c.BindingID) || !nativeShareBindingID(c.CommandID) || !nativeShareBindingID(c.ChallengeID) || !nativeShareBindingHex(c.StageDigest) || len(c.Nonce) != 32 || !nativeShareBindingTime(c.ExpiresAt) || c.CommandID == c.Metadata.CommandID {
		return nil, errNativeShareEpochProof
	}
	if _, err := c.Metadata.AAD(); err != nil {
		return nil, errNativeShareEpochProof
	}
	expires, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	deadline, _ := time.Parse(time.RFC3339Nano, c.Metadata.Deadline)
	if expires.After(deadline) {
		return nil, errNativeShareEpochProof
	}
	raw, err := json.Marshal(c)
	return append([]byte("pagnet/native-share-epoch/proof-challenge/v1/"), raw...), err
}

func (c NativeShareEpochProofChallenge) Validate(now time.Time) error {
	if _, err := c.CanonicalBytes(); err != nil {
		return err
	}
	expires, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if now.IsZero() || !now.Before(expires) || expires.After(now.Add(5*time.Minute)) {
		return errNativeShareEpochProof
	}
	return nil
}

type NativeShareEpochProof struct {
	Challenge      NativeShareEpochProofChallenge `json:"challenge"`
	EpochSignature []byte                         `json:"epochSignature"`
	HostSignature  []byte                         `json:"hostSignature"`
}

// SignatureBytes binds the host signature to both the challenge and epoch proof.
func (p NativeShareEpochProof) SignatureBytes() ([]byte, error) {
	if _, err := p.Challenge.CanonicalBytes(); err != nil {
		return nil, err
	}
	if len(p.EpochSignature) != ed25519.SignatureSize {
		return nil, errNativeShareEpochProof
	}
	raw, err := json.Marshal(struct {
		Challenge      NativeShareEpochProofChallenge `json:"challenge"`
		EpochSignature []byte                         `json:"epochSignature"`
	}{p.Challenge, p.EpochSignature})
	return append([]byte("pagnet/native-share-epoch/proof-host/v1/"), raw...), err
}

func (p NativeShareEpochProof) Verify(expected NativeShareEpochProofChallenge, epochKey, hostKey ed25519.PublicKey, now time.Time) error {
	if err := p.Challenge.Validate(now); err != nil {
		return err
	}
	challenge, err := p.Challenge.CanonicalBytes()
	if err != nil {
		return err
	}
	want, err := expected.CanonicalBytes()
	if err != nil || !bytes.Equal(challenge, want) || len(epochKey) != ed25519.PublicKeySize || hex.EncodeToString(epochKey) != expected.Metadata.EpochPossessionVerifier || len(hostKey) != ed25519.PublicKeySize || !ed25519.Verify(epochKey, challenge, p.EpochSignature) {
		return errNativeShareEpochProof
	}
	host, err := p.SignatureBytes()
	if err != nil || !ed25519.Verify(hostKey, host, p.HostSignature) {
		return errNativeShareEpochProof
	}
	return nil
}

func DecodeNativeShareEpochProofChallenge(raw []byte) (NativeShareEpochProofChallenge, error) {
	var c NativeShareEpochProofChallenge
	if !strictNativeShareEpochProofJSON(raw, false) || json.Unmarshal(raw, &c) != nil {
		return NativeShareEpochProofChallenge{}, errNativeShareEpochProof
	}
	if _, err := c.CanonicalBytes(); err != nil {
		return NativeShareEpochProofChallenge{}, err
	}
	return c, nil
}

func DecodeNativeShareEpochProof(raw []byte) (NativeShareEpochProof, error) {
	var p NativeShareEpochProof
	if !strictNativeShareEpochProofJSON(raw, true) || json.Unmarshal(raw, &p) != nil {
		return NativeShareEpochProof{}, errNativeShareEpochProof
	}
	if _, err := p.SignatureBytes(); err != nil || len(p.HostSignature) != ed25519.SignatureSize {
		return NativeShareEpochProof{}, errNativeShareEpochProof
	}
	return p, nil
}

// Check exact field names, presence and nonnull scalar values before decoding.
func strictNativeShareEpochProofJSON(raw []byte, proof bool) bool {
	if len(raw) > 16<<10 {
		return false
	}
	challenge := map[string]bool{"version": true, "bindingId": true, "stageDigest": true, "metadata": true, "commandId": true, "challengeId": true, "nonce": true, "expiresAt": true}
	metadata := map[string]bool{"version": true, "operationId": true, "tenantId": true, "networkId": true, "previousEpochId": true, "epochId": true, "epochPossessionVerifier": true, "proposalRevision": true, "grantGeneration": true, "bindingDigest": true, "holderId": true, "holderX25519": true, "commandId": true, "commandConnectionId": true, "authorityConnectionId": true, "deadline": true}
	schemas := map[string]map[string]bool{"": challenge, "metadata": metadata}
	if proof {
		schemas = map[string]map[string]bool{"": {"challenge": true, "epochSignature": true, "hostSignature": true}, "challenge": challenge, "challenge.metadata": metadata}
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
			if schemas[child] != nil {
				if !object(child) {
					return false
				}
				continue
			}
			token, err = d.Token()
			if err != nil || token == nil {
				return false
			}
			if _, ok := token.(json.Delim); ok {
				return false
			}
			if name == "nonce" || name == "epochSignature" || name == "hostSignature" {
				value, ok := token.(string)
				if !ok {
					return false
				}
				decoded, err := base64.StdEncoding.Strict().DecodeString(value)
				if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
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
