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
	MsgDirectManagedSourceCredentialV2            = "host.direct_managed_source_credential"
	DirectManagedSourceCredentialProtocolV2       = "direct_managed_source_credential_v2"
	DirectManagedSourceCredentialSuiteV2          = "X25519-HKDF-SHA256-HMAC-SHA256"
	DirectManagedSourceCredentialInstallFailureV2 = "direct_managed_source_credential_install_failed"
	directManagedSourceCredentialDomainV2         = "pagnet/direct-managed-source-credential/"
)

// DirectManagedSourceCredentialPoPReceiptV2 binds canonical proof evidence. It does not
// assert that a server accepted the proof.
type DirectManagedSourceCredentialPoPReceiptV2 struct {
	ChallengeID    domain.ID `json:"challengeId"`
	TranscriptHash string    `json:"transcriptHash"`
	ProofDigest    string    `json:"proofDigest"`
}

// NewDirectManagedSourceCredentialPoPReceiptV2 binds canonical V2 proof bytes
// using the V2 proof domain. It does not authenticate or accept the proof.
func NewDirectManagedSourceCredentialPoPReceiptV2(proof DirectManagedSourcePoPProofV2) (DirectManagedSourceCredentialPoPReceiptV2, error) {
	raw, err := proof.CanonicalBytes()
	if err != nil {
		return DirectManagedSourceCredentialPoPReceiptV2{}, err
	}
	return DirectManagedSourceCredentialPoPReceiptV2{proof.ChallengeID, proof.TranscriptHash, managedEndpointDigest("pagnet/direct-managed-source-host-custody-pop/proof/v2/", raw)}, nil
}

// DirectManagedSourceCredentialIssueV2 carries public installation evidence only. The
// caller authenticates the issuer and compares all retained authorization,
// budget, channel and host state before using the derivation helpers. The issuer
// supplies a fresh random nonce and server key per issue; these pure helpers
// cannot establish global uniqueness.
type DirectManagedSourceCredentialIssueV2 struct {
	ProtocolVersion       string                                    `json:"protocolVersion"`
	Suite                 string                                    `json:"suite"`
	CredentialID          domain.ID                                 `json:"credentialId"`
	ChannelGeneration     string                                    `json:"channelGeneration"`
	Nonce                 string                                    `json:"nonce"`
	ServerEphemeralX25519 string                                    `json:"serverEphemeralX25519"`
	IssuedAt              time.Time                                 `json:"issuedAt"`
	InstallExpiresAt      time.Time                                 `json:"installExpiresAt"`
	CredentialExpiresAt   time.Time                                 `json:"credentialExpiresAt"`
	PoP                   DirectManagedSourcePoPChallengeV2         `json:"pop"`
	PoPReceipt            DirectManagedSourceCredentialPoPReceiptV2 `json:"popReceipt"`
	BudgetExpiresAt       time.Time                                 `json:"budgetExpiresAt"`
}

func (p DirectManagedSourceCredentialIssueV2) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourceCredentialProtocolV2 || p.Suite != DirectManagedSourceCredentialSuiteV2 || !nativeShareBindingID(p.CredentialID) || !directManagedSourceGenerationV2(p.ChannelGeneration) || !nativeShareBindingHex(p.Nonce) || !nativeShareBindingHex(p.PoPReceipt.ProofDigest) || !nativeShareBindingHex(p.PoPReceipt.TranscriptHash) {
		return nil, errDirectManagedSourceBinding
	}
	pop, err := p.PoP.CanonicalBytes()
	var ownedPoP DirectManagedSourcePoPChallengeV2
	if err != nil || len(pop) > 64*1024 || json.Unmarshal(pop, &ownedPoP) != nil {
		return nil, errDirectManagedSourceBinding
	}
	p.PoP = ownedPoP
	if p.ServerEphemeralX25519 == p.PoP.ServerEphemeralX25519 || !directManagedSourceCredentialPublicKey(p.ServerEphemeralX25519) || !directManagedSourceCredentialPublicKey(p.PoP.ServerEphemeralX25519) || !directManagedSourceCredentialPublicKey(p.PoP.ACK.Reservation.X25519) {
		return nil, errDirectManagedSourceBinding
	}
	if p.PoPReceipt.ChallengeID != p.PoP.ChallengeID || p.PoPReceipt.TranscriptHash != managedEndpointDigest("pagnet/direct-managed-source-host-custody-pop/transcript/v2/", pop) {
		return nil, errDirectManagedSourceBinding
	}
	for _, v := range []time.Time{p.IssuedAt, p.InstallExpiresAt, p.CredentialExpiresAt, p.BudgetExpiresAt} {
		if v.IsZero() || v.Year() < 1 || v.Year() > 9999 {
			return nil, errDirectManagedSourceBinding
		}
	}
	// Enrollment bounds installation; authorization and the accepted budget bound
	// credential use independently of the short-lived enrollment challenge.
	subject := p.PoP.Prepare.Subject
	if p.ChannelGeneration != subject.BindingGeneration || p.CredentialID == subject.PreviousCredentialID ||
		p.IssuedAt.Before(p.PoP.IssuedAt) || !p.IssuedAt.Before(p.PoP.ExpiresAt) ||
		!p.IssuedAt.Before(p.InstallExpiresAt) || p.InstallExpiresAt.After(subject.EnrollmentExpiresAt) ||
		p.InstallExpiresAt.After(p.CredentialExpiresAt) || p.CredentialExpiresAt.After(subject.AuthorizationExpiresAt) ||
		p.CredentialExpiresAt.After(p.BudgetExpiresAt) {
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

func DecodeDirectManagedSourceCredentialIssueV2(raw []byte) (DirectManagedSourceCredentialIssueV2, error) {
	var p DirectManagedSourceCredentialIssueV2
	if !managedEndpointCanonicalDecode(raw, &p, 96*1024) {
		return DirectManagedSourceCredentialIssueV2{}, errDirectManagedSourceBinding
	}
	return p, nil
}

// NewDirectManagedSourceCredentialIssueV2 binds a canonical challenge and proof without
// authenticating the proof or asserting its acceptance. Callers must verify the
// PoP separately before issuing credentials. The remaining public fields come
// from p; the protocol, suite, PoP and receipt are filled by this constructor.
func NewDirectManagedSourceCredentialIssueV2(p DirectManagedSourceCredentialIssueV2, pop DirectManagedSourcePoPChallengeV2, proof DirectManagedSourcePoPProofV2) (DirectManagedSourceCredentialIssueV2, error) {
	raw, err := pop.CanonicalBytes()
	receipt, proofErr := NewDirectManagedSourceCredentialPoPReceiptV2(proof)
	if err != nil || proofErr != nil || proof.ChallengeID != pop.ChallengeID || proof.TranscriptHash != managedEndpointDigest("pagnet/direct-managed-source-host-custody-pop/transcript/v2/", raw) {
		return DirectManagedSourceCredentialIssueV2{}, errDirectManagedSourceBinding
	}
	p.ProtocolVersion = DirectManagedSourceCredentialProtocolV2
	p.Suite = DirectManagedSourceCredentialSuiteV2
	p.PoP = pop
	p.PoPReceipt = receipt
	canonical, err := p.CanonicalBytes()
	if err != nil {
		return DirectManagedSourceCredentialIssueV2{}, err
	}
	// Own canonical nested evidence rather than retaining caller aliases.
	var owned DirectManagedSourceCredentialIssueV2
	if json.Unmarshal(canonical, &owned) != nil {
		return DirectManagedSourceCredentialIssueV2{}, errDirectManagedSourceBinding
	}
	return owned, nil
}

type DirectManagedSourceCredentialACKV2 struct {
	ProtocolVersion  string    `json:"protocolVersion"`
	Suite            string    `json:"suite"`
	CredentialID     domain.ID `json:"credentialId"`
	TranscriptHash   string    `json:"transcriptHash"`
	HostConfirmation string    `json:"hostConfirmation"`
}

func (p DirectManagedSourceCredentialACKV2) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourceCredentialProtocolV2 || p.Suite != DirectManagedSourceCredentialSuiteV2 || !nativeShareBindingID(p.CredentialID) || !nativeShareBindingHex(p.TranscriptHash) || !nativeShareBindingHex(p.HostConfirmation) {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}
func DecodeDirectManagedSourceCredentialACKV2(raw []byte) (DirectManagedSourceCredentialACKV2, error) {
	var p DirectManagedSourceCredentialACKV2
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return DirectManagedSourceCredentialACKV2{}, errDirectManagedSourceBinding
	}
	return p, nil
}

type DirectManagedSourceCredentialFailureACKV2 struct {
	ProtocolVersion string    `json:"protocolVersion"`
	CredentialID    domain.ID `json:"credentialId"`
	Error           string    `json:"error"`
}

func (p DirectManagedSourceCredentialFailureACKV2) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourceCredentialProtocolV2 || !nativeShareBindingID(p.CredentialID) || p.Error != DirectManagedSourceCredentialInstallFailureV2 {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}
func DecodeDirectManagedSourceCredentialFailureACKV2(raw []byte) (DirectManagedSourceCredentialFailureACKV2, error) {
	var p DirectManagedSourceCredentialFailureACKV2
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return DirectManagedSourceCredentialFailureACKV2{}, errDirectManagedSourceBinding
	}
	return p, nil
}

func (p DirectManagedSourceCredentialIssueV2) transcriptHash(now time.Time) ([]byte, error) {
	raw, err := p.CanonicalBytes()
	if err != nil || now.Before(p.IssuedAt) || !now.Before(p.InstallExpiresAt) {
		return nil, errDirectManagedSourceBinding
	}
	sum := sha256.Sum256(append([]byte(directManagedSourceCredentialDomainV2+"transcript/v2/"), raw...))
	return sum[:], nil
}

// DeriveDirectManagedSourceCredentialVerifierV2 returns public hashes only. Callers
// retain the credential ID and transcript independently, compare verifier
// digests in constant time, and enforce single use and current authority.
// The caller owns and clears serverPrivate; Go crypto copies cannot be wiped.
func DeriveDirectManagedSourceCredentialVerifierV2(p DirectManagedSourceCredentialIssueV2, serverPrivate []byte, now time.Time) (transcriptHash, credentialHash, installVerifier string, err error) {
	transcript, err := p.transcriptHash(now)
	if err != nil {
		return "", "", "", err
	}
	secret, confirmation, err := directManagedSourceCredentialDeriveV2(p, serverPrivate, p.ServerEphemeralX25519, p.PoP.ACK.Reservation.X25519, transcript)
	if err != nil {
		return "", "", "", err
	}
	defer clear(secret)
	defer clear(confirmation)
	transcriptHash = hex.EncodeToString(transcript)
	credentialHash, _ = DirectManagedSourceCredentialHashV2(transcriptHash, secret)
	return transcriptHash, credentialHash, directManagedSourceCredentialInstallVerifierV2(transcript, confirmation), nil
}

// DeriveDirectManagedSourceCredentialHostV2 returns the credential secret and public
// installation ACK. The caller owns and clears the returned secret and input
// hostPrivate. This helper grants no activation or channel authority.
func DeriveDirectManagedSourceCredentialHostV2(p DirectManagedSourceCredentialIssueV2, hostPrivate []byte, now time.Time) ([]byte, DirectManagedSourceCredentialACKV2, error) {
	transcript, err := p.transcriptHash(now)
	if err != nil {
		return nil, DirectManagedSourceCredentialACKV2{}, err
	}
	secret, confirmation, err := directManagedSourceCredentialDeriveV2(p, hostPrivate, p.PoP.ACK.Reservation.X25519, p.ServerEphemeralX25519, transcript)
	if err != nil {
		return nil, DirectManagedSourceCredentialACKV2{}, err
	}
	defer clear(confirmation)
	return secret, DirectManagedSourceCredentialACKV2{DirectManagedSourceCredentialProtocolV2, DirectManagedSourceCredentialSuiteV2, p.CredentialID, hex.EncodeToString(transcript), hex.EncodeToString(confirmation)}, nil
}

func directManagedSourceCredentialDeriveV2(p DirectManagedSourceCredentialIssueV2, key []byte, expected, peer string, transcript []byte) (secret, confirmation []byte, err error) {
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
	secret, err = hkdf.Key(sha256.New, shared, salt, directManagedSourceCredentialDomainV2+"credential-secret/v2/"+string(transcript), 32)
	if err != nil {
		return nil, nil, errDirectManagedSourceBinding
	}
	installKey, err := hkdf.Key(sha256.New, shared, salt, directManagedSourceCredentialDomainV2+"install-key/v2/"+string(transcript), 32)
	if err != nil {
		clear(secret)
		return nil, nil, errDirectManagedSourceBinding
	}
	defer clear(installKey)
	mac := hmac.New(sha256.New, installKey)
	mac.Write([]byte(directManagedSourceCredentialDomainV2 + "host-install/v2/"))
	mac.Write(transcript)
	return secret, mac.Sum(nil), nil
}

// DirectManagedSourceCredentialHashV2 binds a 32-byte credential secret to its canonical
// lowercase transcript digest. It does not authenticate either input.
func DirectManagedSourceCredentialHashV2(transcriptHash string, secret []byte) (string, error) {
	if !nativeShareBindingHex(transcriptHash) || len(secret) != 32 {
		return "", errDirectManagedSourceBinding
	}
	transcript, _ := hex.DecodeString(transcriptHash)
	hash := sha256.New()
	hash.Write([]byte(directManagedSourceCredentialDomainV2 + "credential-hash/v2/"))
	hash.Write(transcript)
	hash.Write(secret)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// DecodeDirectManagedSourceCredentialACKVerifierV2 strictly decodes an ACK and derives
// its public verifier digest. The caller must match the retained credential ID
// and transcript and compare the expected digest in constant time.
func DecodeDirectManagedSourceCredentialACKVerifierV2(raw []byte) (DirectManagedSourceCredentialACKV2, string, error) {
	p, err := DecodeDirectManagedSourceCredentialACKV2(raw)
	if err != nil {
		return DirectManagedSourceCredentialACKV2{}, "", err
	}
	transcript, _ := hex.DecodeString(p.TranscriptHash)
	confirmation, _ := hex.DecodeString(p.HostConfirmation)
	defer clear(confirmation)
	return p, directManagedSourceCredentialInstallVerifierV2(transcript, confirmation), nil
}
func directManagedSourceCredentialInstallVerifierV2(transcript, confirmation []byte) string {
	hash := sha256.New()
	hash.Write([]byte(directManagedSourceCredentialDomainV2 + "install-verifier/v2/"))
	hash.Write(transcript)
	hash.Write(confirmation)
	return hex.EncodeToString(hash.Sum(nil))
}
