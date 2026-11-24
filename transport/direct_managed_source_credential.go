package transport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

const (
	MsgDirectManagedSourceCredential            = "host.direct_managed_source_credential"
	DirectManagedSourceCredentialProtocol       = "direct_managed_source_credential_v1"
	DirectManagedSourceCredentialSuite          = "X25519-HKDF-SHA256-HMAC-SHA256"
	DirectManagedSourceCredentialInstallFailure = "direct_managed_source_credential_install_failed"
	directManagedSourceCredentialDomain         = "pagnet/direct-managed-source-credential/"
)

// DirectManagedSourceCredentialPoPReceipt binds canonical proof evidence. It does not
// assert that a server accepted the proof.
type DirectManagedSourceCredentialPoPReceipt struct {
	ChallengeID    domain.ID `json:"challengeId"`
	TranscriptHash string    `json:"transcriptHash"`
	ProofDigest    string    `json:"proofDigest"`
}

// DirectManagedSourceCredentialIssue carries public installation evidence only. The
// caller authenticates the issuer and compares all retained authorization,
// budget, channel and host state before using the derivation helpers. The issuer
// supplies a fresh random nonce and server key per issue; these pure helpers
// cannot establish global uniqueness.
type DirectManagedSourceCredentialIssue struct {
	ProtocolVersion       string                                  `json:"protocolVersion"`
	Suite                 string                                  `json:"suite"`
	CredentialID          domain.ID                               `json:"credentialId"`
	ChannelGeneration     uint64                                  `json:"channelGeneration"`
	Nonce                 string                                  `json:"nonce"`
	ServerEphemeralX25519 string                                  `json:"serverEphemeralX25519"`
	IssuedAt              time.Time                               `json:"issuedAt"`
	InstallExpiresAt      time.Time                               `json:"installExpiresAt"`
	CredentialExpiresAt   time.Time                               `json:"credentialExpiresAt"`
	PoP                   DirectManagedSourcePoPChallenge         `json:"pop"`
	PoPReceipt            DirectManagedSourceCredentialPoPReceipt `json:"popReceipt"`
	BudgetExpiresAt       time.Time                               `json:"budgetExpiresAt"`
}

func (p DirectManagedSourceCredentialIssue) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourceCredentialProtocol || p.Suite != DirectManagedSourceCredentialSuite || !nativeShareBindingID(p.CredentialID) || p.ChannelGeneration != 1 || !nativeShareBindingHex(p.Nonce) || !nativeShareBindingHex(p.PoPReceipt.ProofDigest) || !nativeShareBindingHex(p.PoPReceipt.TranscriptHash) {
		return nil, errDirectManagedSourceBinding
	}
	pop, err := p.PoP.CanonicalBytes()
	var ownedPoP DirectManagedSourcePoPChallenge
	if err != nil || len(pop) > 64*1024 || json.Unmarshal(pop, &ownedPoP) != nil {
		return nil, errDirectManagedSourceBinding
	}
	p.PoP = ownedPoP
	if p.ServerEphemeralX25519 == p.PoP.ServerEphemeralX25519 || !directManagedSourceCredentialPublicKey(p.ServerEphemeralX25519) || !directManagedSourceCredentialPublicKey(p.PoP.ServerEphemeralX25519) || !directManagedSourceCredentialPublicKey(p.PoP.ACK.Reservation.X25519) {
		return nil, errDirectManagedSourceBinding
	}
	if p.PoPReceipt.ChallengeID != p.PoP.ChallengeID || p.PoPReceipt.TranscriptHash != managedEndpointDigest("pagnet/direct-managed-source-host-custody-pop/transcript/v1/", pop) {
		return nil, errDirectManagedSourceBinding
	}
	for _, v := range []time.Time{p.IssuedAt, p.InstallExpiresAt, p.CredentialExpiresAt, p.BudgetExpiresAt} {
		if v.IsZero() || v.Year() < 1 || v.Year() > 9999 {
			return nil, errDirectManagedSourceBinding
		}
	}
	if p.IssuedAt.Before(p.PoP.IssuedAt) || !p.IssuedAt.Before(p.PoP.ExpiresAt) || !p.IssuedAt.Before(p.BudgetExpiresAt) || !p.InstallExpiresAt.Equal(p.PoP.ExpiresAt) || !p.CredentialExpiresAt.Equal(p.PoP.ExpiresAt) || !p.CredentialExpiresAt.Equal(p.PoP.Prepare.Subject.ExpiresAt) || p.CredentialExpiresAt.After(p.BudgetExpiresAt) {
		return nil, errDirectManagedSourceBinding
	}
	p.IssuedAt = p.IssuedAt.UTC()
	p.InstallExpiresAt = p.InstallExpiresAt.UTC()
	p.CredentialExpiresAt = p.CredentialExpiresAt.UTC()
	p.BudgetExpiresAt = p.BudgetExpiresAt.UTC()
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > 96*1024 {
		return nil, errDirectManagedSourceBinding
	}
	return raw, nil
}

func DecodeDirectManagedSourceCredentialIssue(raw []byte) (DirectManagedSourceCredentialIssue, error) {
	var p DirectManagedSourceCredentialIssue
	if !managedEndpointCanonicalDecode(raw, &p, 96*1024) {
		return DirectManagedSourceCredentialIssue{}, errDirectManagedSourceBinding
	}
	return p, nil
}

// NewDirectManagedSourceCredentialIssue binds a canonical challenge and proof without
// authenticating the proof or asserting its acceptance. Callers must verify the
// PoP separately before issuing credentials. The remaining public fields come
// from p; the protocol, suite, PoP and receipt are filled by this constructor.
func NewDirectManagedSourceCredentialIssue(p DirectManagedSourceCredentialIssue, pop DirectManagedSourcePoPChallenge, proof DirectManagedSourcePoPProof) (DirectManagedSourceCredentialIssue, error) {
	raw, err := pop.CanonicalBytes()
	proofRaw, proofErr := proof.CanonicalBytes()
	if err != nil || proofErr != nil || proof.ChallengeID != pop.ChallengeID || proof.TranscriptHash != managedEndpointDigest("pagnet/direct-managed-source-host-custody-pop/transcript/v1/", raw) {
		return DirectManagedSourceCredentialIssue{}, errDirectManagedSourceBinding
	}
	p.ProtocolVersion = DirectManagedSourceCredentialProtocol
	p.Suite = DirectManagedSourceCredentialSuite
	p.PoP = pop
	p.PoPReceipt = DirectManagedSourceCredentialPoPReceipt{proof.ChallengeID, proof.TranscriptHash, managedEndpointDigest("", proofRaw)}
	canonical, err := p.CanonicalBytes()
	if err != nil {
		return DirectManagedSourceCredentialIssue{}, err
	}
	// Own canonical nested evidence rather than retaining caller aliases.
	var owned DirectManagedSourceCredentialIssue
	if json.Unmarshal(canonical, &owned) != nil {
		return DirectManagedSourceCredentialIssue{}, errDirectManagedSourceBinding
	}
	return owned, nil
}

func directManagedSourceCredentialPublicKey(value string) bool {
	if !nativeShareBindingHex(value) {
		return false
	}
	raw, _ := hex.DecodeString(value)
	return directManagedSourceUsableX25519(raw)
}

type DirectManagedSourceCredentialACK struct {
	ProtocolVersion  string    `json:"protocolVersion"`
	Suite            string    `json:"suite"`
	CredentialID     domain.ID `json:"credentialId"`
	TranscriptHash   string    `json:"transcriptHash"`
	HostConfirmation string    `json:"hostConfirmation"`
}

func (p DirectManagedSourceCredentialACK) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourceCredentialProtocol || p.Suite != DirectManagedSourceCredentialSuite || !nativeShareBindingID(p.CredentialID) || !nativeShareBindingHex(p.TranscriptHash) || !nativeShareBindingHex(p.HostConfirmation) {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}
func DecodeDirectManagedSourceCredentialACK(raw []byte) (DirectManagedSourceCredentialACK, error) {
	var p DirectManagedSourceCredentialACK
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return DirectManagedSourceCredentialACK{}, errDirectManagedSourceBinding
	}
	return p, nil
}

type DirectManagedSourceCredentialFailureACK struct {
	ProtocolVersion string    `json:"protocolVersion"`
	CredentialID    domain.ID `json:"credentialId"`
	Error           string    `json:"error"`
}

func (p DirectManagedSourceCredentialFailureACK) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourceCredentialProtocol || !nativeShareBindingID(p.CredentialID) || p.Error != DirectManagedSourceCredentialInstallFailure {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}
func DecodeDirectManagedSourceCredentialFailureACK(raw []byte) (DirectManagedSourceCredentialFailureACK, error) {
	var p DirectManagedSourceCredentialFailureACK
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return DirectManagedSourceCredentialFailureACK{}, errDirectManagedSourceBinding
	}
	return p, nil
}

func (p DirectManagedSourceCredentialIssue) transcriptHash(now time.Time) ([]byte, error) {
	raw, err := p.CanonicalBytes()
	if err != nil || now.Before(p.IssuedAt) || !now.Before(p.InstallExpiresAt) {
		return nil, errDirectManagedSourceBinding
	}
	sum := sha256.Sum256(append([]byte(directManagedSourceCredentialDomain+"transcript/v1/"), raw...))
	return sum[:], nil
}

// DeriveDirectManagedSourceCredentialVerifier returns public hashes only. Callers
// retain the credential ID and transcript independently, compare verifier
// digests in constant time, and enforce single use and current authority.
// The caller owns and clears serverPrivate; Go crypto copies cannot be wiped.
func DeriveDirectManagedSourceCredentialVerifier(p DirectManagedSourceCredentialIssue, serverPrivate []byte, now time.Time) (transcriptHash, credentialHash, installVerifier string, err error) {
	transcript, err := p.transcriptHash(now)
	if err != nil {
		return "", "", "", err
	}
	secret, confirmation, err := directManagedSourceCredentialDerive(p, serverPrivate, p.ServerEphemeralX25519, p.PoP.ACK.Reservation.X25519, transcript)
	if err != nil {
		return "", "", "", err
	}
	defer clear(secret)
	defer clear(confirmation)
	transcriptHash = hex.EncodeToString(transcript)
	credentialHash, _ = DirectManagedSourceCredentialHash(transcriptHash, secret)
	return transcriptHash, credentialHash, directManagedSourceCredentialInstallVerifier(transcript, confirmation), nil
}

// DeriveDirectManagedSourceCredentialHost returns the credential secret and public
// installation ACK. The caller owns and clears the returned secret and input
// hostPrivate. This helper grants no activation or channel authority.
func DeriveDirectManagedSourceCredentialHost(p DirectManagedSourceCredentialIssue, hostPrivate []byte, now time.Time) ([]byte, DirectManagedSourceCredentialACK, error) {
	transcript, err := p.transcriptHash(now)
	if err != nil {
		return nil, DirectManagedSourceCredentialACK{}, err
	}
	secret, confirmation, err := directManagedSourceCredentialDerive(p, hostPrivate, p.PoP.ACK.Reservation.X25519, p.ServerEphemeralX25519, transcript)
	if err != nil {
		return nil, DirectManagedSourceCredentialACK{}, err
	}
	defer clear(confirmation)
	return secret, DirectManagedSourceCredentialACK{DirectManagedSourceCredentialProtocol, DirectManagedSourceCredentialSuite, p.CredentialID, hex.EncodeToString(transcript), hex.EncodeToString(confirmation)}, nil
}

func directManagedSourceCredentialDerive(p DirectManagedSourceCredentialIssue, key []byte, expected, peer string, transcript []byte) (secret, confirmation []byte, err error) {
	private, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil || hex.EncodeToString(private.PublicKey().Bytes()) != expected {
		return nil, nil, errDirectManagedSourceBinding
	}
	publicBytes, _ := hex.DecodeString(peer)
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return nil, nil, errDirectManagedSourceBinding
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, nil, errDirectManagedSourceBinding
	}
	defer clear(shared)
	if len(shared) != 32 || bytes.Equal(shared, make([]byte, 32)) {
		return nil, nil, errDirectManagedSourceBinding
	}
	salt, err := hex.DecodeString(p.Nonce)
	if err != nil || len(salt) != 32 {
		return nil, nil, errDirectManagedSourceBinding
	}
	secret, err = hkdf.Key(sha256.New, shared, salt, directManagedSourceCredentialDomain+"credential-secret/v1/"+string(transcript), 32)
	if err != nil {
		return nil, nil, errDirectManagedSourceBinding
	}
	installKey, err := hkdf.Key(sha256.New, shared, salt, directManagedSourceCredentialDomain+"install-key/v1/"+string(transcript), 32)
	if err != nil {
		clear(secret)
		return nil, nil, errDirectManagedSourceBinding
	}
	defer clear(installKey)
	mac := hmac.New(sha256.New, installKey)
	mac.Write([]byte(directManagedSourceCredentialDomain + "host-install/v1/"))
	mac.Write(transcript)
	return secret, mac.Sum(nil), nil
}

// DirectManagedSourceCredentialHash binds a 32-byte credential secret to its canonical
// lowercase transcript digest. It does not authenticate either input.
func DirectManagedSourceCredentialHash(transcriptHash string, secret []byte) (string, error) {
	if !nativeShareBindingHex(transcriptHash) || len(secret) != 32 {
		return "", errDirectManagedSourceBinding
	}
	transcript, _ := hex.DecodeString(transcriptHash)
	hash := sha256.New()
	hash.Write([]byte(directManagedSourceCredentialDomain + "credential-hash/v1/"))
	hash.Write(transcript)
	hash.Write(secret)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// DecodeDirectManagedSourceCredentialACKVerifier strictly decodes an ACK and derives
// its public verifier digest. The caller must match the retained credential ID
// and transcript and compare the expected digest in constant time.
func DecodeDirectManagedSourceCredentialACKVerifier(raw []byte) (DirectManagedSourceCredentialACK, string, error) {
	p, err := DecodeDirectManagedSourceCredentialACK(raw)
	if err != nil {
		return DirectManagedSourceCredentialACK{}, "", err
	}
	transcript, _ := hex.DecodeString(p.TranscriptHash)
	confirmation, _ := hex.DecodeString(p.HostConfirmation)
	defer clear(confirmation)
	return p, directManagedSourceCredentialInstallVerifier(transcript, confirmation), nil
}
func directManagedSourceCredentialInstallVerifier(transcript, confirmation []byte) string {
	hash := sha256.New()
	hash.Write([]byte(directManagedSourceCredentialDomain + "install-verifier/v1/"))
	hash.Write(transcript)
	hash.Write(confirmation)
	return hex.EncodeToString(hash.Sum(nil))
}
