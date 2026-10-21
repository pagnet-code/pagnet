package sdk

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
)

const pairSuite = "X25519-HKDF-SHA256-AES-256-GCM-Auth"

// Field order matches the server's SharingPairDescriptor canonical encoding.
// The expected descriptor must come from the caller's trusted consent snapshot
// and pinned public keys, not from decoding the received descriptor itself.
type pairDescriptor struct {
	Version              int        `json:"version"`
	Suite                string     `json:"suite"`
	GrantID              string     `json:"grantId"`
	Generation           int64      `json:"generation"`
	InvitationID         string     `json:"invitationId"`
	NetworkID            string     `json:"networkId"`
	OwningTenantID       string     `json:"owningTenantId"`
	IssuerTenantID       string     `json:"issuerTenantId"`
	IssuerPrincipalID    string     `json:"issuerPrincipalId"`
	RecipientTenantID    string     `json:"recipientTenantId"`
	RecipientPrincipalID string     `json:"recipientPrincipalId"`
	IssuerPublicKey      string     `json:"issuerPublicKey"`
	RecipientPublicKey   string     `json:"recipientPublicKey"`
	EpochID              string     `json:"epochId"`
	ExpiresAt            string     `json:"expiresAt"`
	Permissions          []string   `json:"permissions"`
	Limits               pairLimits `json:"limits"`
}

type pairLimits struct {
	MaxMessageWireBytes  int `json:"maxMessageWireBytes"`
	MaxMessagesPerMinute int `json:"maxMessagesPerMinute"`
	MaxMessagesPerDay    int `json:"maxMessagesPerDay"`
	MaxWireBytesPerDay   int `json:"maxWireBytesPerDay"`
	MaxInFlight          int `json:"maxInFlight"`
	MaxTurnsPerThread    int `json:"maxTurnsPerThread"`
}

func (l pairLimits) valid() bool {
	return l.MaxMessageWireBytes >= 1024 && l.MaxMessageWireBytes <= 65536 && l.MaxMessagesPerMinute >= 1 && l.MaxMessagesPerMinute <= 10 && l.MaxMessagesPerDay >= 1 && l.MaxMessagesPerDay <= 200 && l.MaxWireBytesPerDay >= l.MaxMessageWireBytes && l.MaxWireBytesPerDay <= 8388608 && l.MaxInFlight >= 1 && l.MaxInFlight <= 2 && l.MaxTurnsPerThread >= 1 && l.MaxTurnsPerThread <= 16
}

func pairKey(encoded string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != encoded {
		return nil, errors.New("sdk: invalid pinned pair public key")
	}
	return key, nil
}

func validatePairDescriptor(raw []byte, expected pairDescriptor, now time.Time) (pairDescriptor, []byte, []byte, error) {
	var d pairDescriptor
	invalid := errors.New("sdk: invalid pair descriptor")
	if len(raw) == 0 || len(raw) > 4096 || json.Unmarshal(raw, &d) != nil {
		return d, nil, nil, invalid
	}
	canonical, _ := json.Marshal(d)
	trusted, _ := json.Marshal(expected)
	if !bytes.Equal(raw, canonical) || !bytes.Equal(raw, trusted) {
		return d, nil, nil, invalid
	}
	epoch, err := uuid.Parse(d.EpochID)
	expiry, expiryErr := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if d.Version != 1 || d.Suite != pairSuite || d.Generation < 1 || err != nil || epoch.Version() != 7 || epoch.String() != d.EpochID || expiryErr != nil || expiry.UTC().Format(time.RFC3339Nano) != d.ExpiresAt || !expiry.After(now) || !d.Limits.valid() || len(d.Permissions) != 1 || d.Permissions[0] != "communicate" || d.OwningTenantID != d.IssuerTenantID || d.IssuerPrincipalID == d.RecipientPrincipalID {
		return d, nil, nil, invalid
	}
	for _, id := range []string{d.GrantID, d.InvitationID, d.NetworkID, d.OwningTenantID, d.IssuerTenantID, d.IssuerPrincipalID, d.RecipientTenantID, d.RecipientPrincipalID} {
		if !validPairPathID(id) {
			return d, nil, nil, invalid
		}
	}
	issuer, err := pairKey(d.IssuerPublicKey)
	if err != nil {
		return d, nil, nil, err
	}
	recipient, err := pairKey(d.RecipientPublicKey)
	return d, issuer, recipient, err
}

// pairEpochPackage is a local immutable publication container, not a REST DTO.
// Transport adapters must map its fields to the server's eventual wire DTO.
type pairEpochPackage struct {
	EpochID    string
	Descriptor []byte
	Enc        []byte
	Ciphertext []byte
}

type pairIssuerMaterial struct {
	Package           pairEpochPackage
	ReadinessVerifier []byte
}

func pairPrivateMatches(private, public []byte) bool {
	key, err := ecdh.X25519().NewPrivateKey(private)
	return err == nil && bytes.Equal(key.PublicKey().Bytes(), public)
}

func pairReadinessKey(p pendingPairEpoch) ([]byte, error) {
	return hkdf.Key(sha256.New, p.EpochKey, p.DescriptorHash[:], "pagnet/sdk-pair/readiness/v1", 32)
}

func pairPending(d pairDescriptor, raw, epochKey, issuer, recipient []byte) pendingPairEpoch {
	return pendingPairEpoch{GrantID: d.GrantID, Generation: uint64(d.Generation), NetworkID: d.NetworkID, EpochID: d.EpochID, Descriptor: raw, DescriptorHash: sha256.Sum256(raw), EpochKey: epochKey, IssuerFingerprint: sha256.Sum256(issuer), RecipientFingerprint: sha256.Sum256(recipient)}
}

func (k *keyring) prepareIssuerPairEpoch(raw []byte, expected pairDescriptor, private, epochKey []byte, now time.Time) (pairIssuerMaterial, error) {
	var out pairIssuerMaterial
	d, issuer, recipient, err := validatePairDescriptor(raw, expected, now)
	if err != nil {
		return out, err
	}
	if len(epochKey) != 32 || !pairPrivateMatches(private, issuer) {
		return out, errors.New("sdk: invalid issuer pair key")
	}
	p := pairPending(d, raw, epochKey, issuer, recipient)
	enc, ciphertext, err := e2ee.HPKEWrapAuth(recipient, private, []byte("pagnet/sdk-pair/epoch-wrap/v1"), p.DescriptorHash[:], epochKey)
	if err != nil {
		return out, err
	}
	p.Publication, err = json.Marshal(pairEpochPackage{d.EpochID, raw, enc, ciphertext})
	if err != nil {
		return out, err
	}
	p, err = k.storePendingPairEpoch(p)
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(p.Publication, &out.Package); err != nil {
		return out, err
	}
	out.ReadinessVerifier, err = pairReadinessKey(p)
	return out, err
}

func (k *keyring) prepareRecipientPairEpoch(raw []byte, expected pairDescriptor, private, enc, ciphertext []byte, now time.Time) error {
	d, issuer, recipient, err := validatePairDescriptor(raw, expected, now)
	if err != nil {
		return err
	}
	if !pairPrivateMatches(private, recipient) || len(enc) != 32 || len(ciphertext) != 48 {
		return errors.New("sdk: invalid recipient pair package")
	}
	hash := sha256.Sum256(raw)
	epochKey, err := e2ee.HPKEUnwrapAuth(private, issuer, enc, []byte("pagnet/sdk-pair/epoch-wrap/v1"), hash[:], ciphertext)
	if err != nil {
		return err
	}
	if len(epochKey) != 32 {
		return errors.New("sdk: invalid pair epoch key length")
	}
	_, err = k.storePendingPairEpoch(pairPending(d, raw, epochKey, issuer, recipient))
	return err
}

// Field order matches SharingPairProofTranscript; exact received bytes are MACed.
type pairProofTranscript struct {
	Domain         string `json:"domain"`
	ChallengeID    string `json:"challengeId"`
	Nonce          string `json:"nonce"`
	GrantID        string `json:"grantId"`
	Generation     int64  `json:"generation"`
	DescriptorHash string `json:"descriptorHash"`
	EpochID        string `json:"epochId"`
	PrincipalID    string `json:"principalId"`
	EndpointID     string `json:"endpointId"`
	CredentialID   string `json:"credentialId"`
}

type pairProofChallenge struct {
	ID         string
	Transcript []byte
	ExpiresAt  time.Time
}

type pairProofActor struct{ PrincipalID, EndpointID, CredentialID string }

func (k *keyring) pendingPairReadinessProof(expected pairDescriptor, challenge pairProofChallenge, actor pairProofActor, now time.Time) ([]byte, error) {
	p, err := k.loadPendingPairEpoch(expected.GrantID, uint64(expected.Generation))
	if err != nil {
		return nil, err
	}
	d, issuer, recipient, err := validatePairDescriptor(p.Descriptor, expected, now)
	if err != nil {
		return nil, err
	}
	if p.IssuerFingerprint != sha256.Sum256(issuer) || p.RecipientFingerprint != sha256.Sum256(recipient) {
		return nil, errors.New("sdk: pair key fingerprint mismatch")
	}
	var t pairProofTranscript
	invalid := errors.New("sdk: invalid pair proof challenge")
	if len(challenge.Transcript) > 4096 || json.Unmarshal(challenge.Transcript, &t) != nil {
		return nil, invalid
	}
	canonical, _ := json.Marshal(t)
	nonce, nonceErr := pairKey(t.Nonce)
	if !bytes.Equal(canonical, challenge.Transcript) || !challenge.ExpiresAt.After(now) || !validPairPathID(challenge.ID) || t.Domain != "pagnet/sdk-pair/proof/v1" || t.ChallengeID != challenge.ID || nonceErr != nil || len(nonce) != 32 || t.GrantID != d.GrantID || t.Generation != d.Generation || t.DescriptorHash != base64.RawURLEncoding.EncodeToString(p.DescriptorHash[:]) || t.EpochID != d.EpochID || t.PrincipalID != actor.PrincipalID || t.EndpointID != actor.EndpointID || t.CredentialID != actor.CredentialID || !validPairPathID(actor.EndpointID) || !validPairPathID(actor.CredentialID) || (actor.PrincipalID != d.IssuerPrincipalID && actor.PrincipalID != d.RecipientPrincipalID) {
		return nil, invalid
	}
	readiness, err := pairReadinessKey(p)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, readiness)
	mac.Write(challenge.Transcript)
	return mac.Sum(nil), nil
}
