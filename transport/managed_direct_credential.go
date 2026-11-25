package transport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

const (
	MsgManagedDirectCredential            = "host.managed_direct_credential"
	ManagedDirectCredentialProtocol       = "managed_direct_credential_v1"
	ManagedDirectCredentialSuite          = "X25519-HKDF-SHA256-HMAC-SHA256"
	ManagedDirectCredentialInstallFailure = "managed_direct_credential_install_failed"
	managedDirectCredentialDomain         = "pagnet/managed-direct-credential/"
)

// ManagedDirectCredentialPoPReceipt binds canonical proof evidence. It does not
// assert that a server accepted the proof.
type ManagedDirectCredentialPoPReceipt struct {
	ChallengeID    domain.ID `json:"challengeId"`
	TranscriptHash string    `json:"transcriptHash"`
	ProofDigest    string    `json:"proofDigest"`
}

// ManagedDirectCredentialBudgetReference retains accepted terms by digest only.
type ManagedDirectCredentialBudgetReference struct {
	AgreementID      domain.ID `json:"agreementId"`
	AcceptedRevision uint64    `json:"acceptedRevision"`
	TermsDigest      string    `json:"termsDigest"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

// ManagedDirectCredentialIssue carries public installation evidence only. The
// caller authenticates the issuer and compares all retained authorization,
// budget, channel and host state before using the derivation helpers. The issuer
// supplies a fresh random nonce and server key per issue; these pure helpers
// cannot establish global uniqueness.
type ManagedDirectCredentialIssue struct {
	ProtocolVersion       string                                 `json:"protocolVersion"`
	Suite                 string                                 `json:"suite"`
	CredentialID          domain.ID                              `json:"credentialId"`
	ChannelGeneration     uint64                                 `json:"channelGeneration"`
	Nonce                 string                                 `json:"nonce"`
	ServerEphemeralX25519 string                                 `json:"serverEphemeralX25519"`
	IssuedAt              time.Time                              `json:"issuedAt"`
	InstallExpiresAt      time.Time                              `json:"installExpiresAt"`
	CredentialExpiresAt   time.Time                              `json:"credentialExpiresAt"`
	PoP                   ManagedEndpointPoPChallenge            `json:"pop"`
	PoPReceipt            ManagedDirectCredentialPoPReceipt      `json:"popReceipt"`
	Budget                ManagedDirectCredentialBudgetReference `json:"budget"`
}

func (p ManagedDirectCredentialIssue) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != ManagedDirectCredentialProtocol || p.Suite != ManagedDirectCredentialSuite || !nativeShareBindingID(p.CredentialID) || p.ChannelGeneration == 0 || !nativeShareBindingID(p.Budget.AgreementID) || p.Budget.AcceptedRevision < 2 || !nativeShareBindingHex(p.Budget.TermsDigest) || !nativeShareBindingHex(p.PoPReceipt.ProofDigest) || !nativeShareBindingHex(p.PoPReceipt.TranscriptHash) {
		return nil, errManagedEndpointBinding
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(p.Nonce)
	if err != nil || len(nonce) != 32 || base64.StdEncoding.EncodeToString(nonce) != p.Nonce {
		return nil, errManagedEndpointBinding
	}
	pop, err := p.PoP.CanonicalBytes()
	var ownedPoP ManagedEndpointPoPChallenge
	if err != nil || len(pop) > 64*1024 || json.Unmarshal(pop, &ownedPoP) != nil {
		return nil, errManagedEndpointBinding
	}
	p.PoP = ownedPoP
	if p.ServerEphemeralX25519 == p.PoP.ServerEphemeralX25519 || !managedDirectCredentialPublicKey(p.ServerEphemeralX25519) || !managedDirectCredentialPublicKey(p.PoP.ServerEphemeralX25519) || !managedDirectCredentialPublicKey(p.PoP.ACK.Reservation.X25519) {
		return nil, errManagedEndpointBinding
	}
	if p.PoPReceipt.ChallengeID != p.PoP.ChallengeID || p.PoPReceipt.TranscriptHash != managedEndpointDigest("pagnet/managed-endpoint-host-custody-pop/transcript/v1/", pop) {
		return nil, errManagedEndpointBinding
	}
	for _, v := range []time.Time{p.IssuedAt, p.InstallExpiresAt, p.CredentialExpiresAt, p.Budget.ExpiresAt} {
		if v.IsZero() || v.Year() < 1 || v.Year() > 9999 {
			return nil, errManagedEndpointBinding
		}
	}
	if p.IssuedAt.Before(p.PoP.IssuedAt) || !p.IssuedAt.Before(p.InstallExpiresAt) || p.InstallExpiresAt.Sub(p.IssuedAt) > 5*time.Minute || p.InstallExpiresAt.After(p.PoP.ExpiresAt) || p.InstallExpiresAt.After(p.CredentialExpiresAt) {
		return nil, errManagedEndpointBinding
	}
	for _, expiry := range []time.Time{p.PoP.Prepare.Subject.ExpiresAt, p.PoP.Authorization.ExpiresAt, p.PoP.Authorization.GrantExpiresAt, p.Budget.ExpiresAt} {
		if p.CredentialExpiresAt.After(expiry) {
			return nil, errManagedEndpointBinding
		}
	}
	p.IssuedAt = p.IssuedAt.UTC()
	p.InstallExpiresAt = p.InstallExpiresAt.UTC()
	p.CredentialExpiresAt = p.CredentialExpiresAt.UTC()
	p.Budget.ExpiresAt = p.Budget.ExpiresAt.UTC()
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > 96*1024 {
		return nil, errManagedEndpointBinding
	}
	return raw, nil
}

func DecodeManagedDirectCredentialIssue(raw []byte) (ManagedDirectCredentialIssue, error) {
	var p ManagedDirectCredentialIssue
	if !managedEndpointCanonicalDecode(raw, &p, 96*1024) {
		return ManagedDirectCredentialIssue{}, errManagedEndpointBinding
	}
	return p, nil
}

// NewManagedDirectCredentialIssue binds a canonical challenge and proof without
// authenticating the proof or asserting its acceptance. Callers must verify the
// PoP separately before issuing credentials. The remaining public fields come
// from p; the protocol, suite, PoP and receipt are filled by this constructor.
func NewManagedDirectCredentialIssue(p ManagedDirectCredentialIssue, pop ManagedEndpointPoPChallenge, proof ManagedEndpointPoPProof) (ManagedDirectCredentialIssue, error) {
	raw, err := pop.CanonicalBytes()
	proofRaw, proofErr := proof.CanonicalBytes()
	if err != nil || proofErr != nil || proof.ChallengeID != pop.ChallengeID || proof.TranscriptHash != managedEndpointDigest("pagnet/managed-endpoint-host-custody-pop/transcript/v1/", raw) {
		return ManagedDirectCredentialIssue{}, errManagedEndpointBinding
	}
	p.ProtocolVersion = ManagedDirectCredentialProtocol
	p.Suite = ManagedDirectCredentialSuite
	p.PoP = pop
	p.PoPReceipt = ManagedDirectCredentialPoPReceipt{proof.ChallengeID, proof.TranscriptHash, managedEndpointDigest("", proofRaw)}
	canonical, err := p.CanonicalBytes()
	if err != nil {
		return ManagedDirectCredentialIssue{}, err
	}
	// Own the nested slices and pointers rather than retaining caller aliases.
	var owned ManagedDirectCredentialIssue
	if json.Unmarshal(canonical, &owned) != nil {
		return ManagedDirectCredentialIssue{}, errManagedEndpointBinding
	}
	return owned, nil
}

// A fixed public probe rejects all low-order points as well as noncanonical
// RFC7748 encodings. No caller secret participates in structural validation.
func managedDirectCredentialPublicKey(value string) bool {
	if !nativeShareBindingHex(value) {
		return false
	}
	raw, _ := hex.DecodeString(value)
	if !managedEndpointCanonicalX25519(raw) {
		return false
	}
	public, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return false
	}
	probeBytes := [32]byte{1}
	probe, _ := ecdh.X25519().NewPrivateKey(probeBytes[:])
	shared, err := probe.ECDH(public)
	defer clear(shared)
	return err == nil && len(shared) == 32 && !bytes.Equal(shared, make([]byte, 32))
}

type ManagedDirectCredentialACK struct {
	ProtocolVersion  string    `json:"protocolVersion"`
	Suite            string    `json:"suite"`
	CredentialID     domain.ID `json:"credentialId"`
	TranscriptHash   string    `json:"transcriptHash"`
	HostConfirmation string    `json:"hostConfirmation"`
}

func (p ManagedDirectCredentialACK) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != ManagedDirectCredentialProtocol || p.Suite != ManagedDirectCredentialSuite || !nativeShareBindingID(p.CredentialID) || !nativeShareBindingHex(p.TranscriptHash) || !nativeShareBindingHex(p.HostConfirmation) {
		return nil, errManagedEndpointBinding
	}
	return json.Marshal(p)
}
func DecodeManagedDirectCredentialACK(raw []byte) (ManagedDirectCredentialACK, error) {
	var p ManagedDirectCredentialACK
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return ManagedDirectCredentialACK{}, errManagedEndpointBinding
	}
	return p, nil
}

type ManagedDirectCredentialFailureACK struct {
	ProtocolVersion string    `json:"protocolVersion"`
	CredentialID    domain.ID `json:"credentialId"`
	Error           string    `json:"error"`
}

func (p ManagedDirectCredentialFailureACK) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != ManagedDirectCredentialProtocol || !nativeShareBindingID(p.CredentialID) || p.Error != ManagedDirectCredentialInstallFailure {
		return nil, errManagedEndpointBinding
	}
	return json.Marshal(p)
}
func DecodeManagedDirectCredentialFailureACK(raw []byte) (ManagedDirectCredentialFailureACK, error) {
	var p ManagedDirectCredentialFailureACK
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return ManagedDirectCredentialFailureACK{}, errManagedEndpointBinding
	}
	return p, nil
}

func (p ManagedDirectCredentialIssue) transcriptHash(now time.Time) ([]byte, error) {
	raw, err := p.CanonicalBytes()
	if err != nil || now.Before(p.IssuedAt) || !now.Before(p.InstallExpiresAt) {
		return nil, errManagedEndpointBinding
	}
	sum := sha256.Sum256(append([]byte(managedDirectCredentialDomain+"transcript/v1/"), raw...))
	return sum[:], nil
}

// DeriveManagedDirectCredentialVerifier returns public hashes only. Callers
// retain the credential ID and transcript independently, compare verifier
// digests in constant time, and enforce single use and current authority.
// The caller owns and clears serverPrivate; Go crypto copies cannot be wiped.
func DeriveManagedDirectCredentialVerifier(p ManagedDirectCredentialIssue, serverPrivate []byte, now time.Time) (transcriptHash, credentialHash, installVerifier string, err error) {
	transcript, err := p.transcriptHash(now)
	if err != nil {
		return "", "", "", err
	}
	secret, confirmation, err := managedDirectCredentialDerive(p, serverPrivate, p.ServerEphemeralX25519, p.PoP.ACK.Reservation.X25519, transcript)
	if err != nil {
		return "", "", "", err
	}
	defer clear(secret)
	defer clear(confirmation)
	transcriptHash = hex.EncodeToString(transcript)
	credentialHash, _ = ManagedDirectCredentialHash(transcriptHash, secret)
	return transcriptHash, credentialHash, managedDirectCredentialInstallVerifier(transcript, confirmation), nil
}

// DeriveManagedDirectCredentialHost returns the credential secret and public
// installation ACK. The caller owns and clears the returned secret and input
// hostPrivate. This helper grants no activation or channel authority.
func DeriveManagedDirectCredentialHost(p ManagedDirectCredentialIssue, hostPrivate []byte, now time.Time) ([]byte, ManagedDirectCredentialACK, error) {
	transcript, err := p.transcriptHash(now)
	if err != nil {
		return nil, ManagedDirectCredentialACK{}, err
	}
	secret, confirmation, err := managedDirectCredentialDerive(p, hostPrivate, p.PoP.ACK.Reservation.X25519, p.ServerEphemeralX25519, transcript)
	if err != nil {
		return nil, ManagedDirectCredentialACK{}, err
	}
	defer clear(confirmation)
	return secret, ManagedDirectCredentialACK{ManagedDirectCredentialProtocol, ManagedDirectCredentialSuite, p.CredentialID, hex.EncodeToString(transcript), hex.EncodeToString(confirmation)}, nil
}

func managedDirectCredentialDerive(p ManagedDirectCredentialIssue, key []byte, expected, peer string, transcript []byte) (secret, confirmation []byte, err error) {
	private, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil || hex.EncodeToString(private.PublicKey().Bytes()) != expected {
		return nil, nil, errManagedEndpointBinding
	}
	publicBytes, _ := hex.DecodeString(peer)
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return nil, nil, errManagedEndpointBinding
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, nil, errManagedEndpointBinding
	}
	defer clear(shared)
	if len(shared) != 32 || bytes.Equal(shared, make([]byte, 32)) {
		return nil, nil, errManagedEndpointBinding
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(p.Nonce)
	if err != nil || len(salt) != 32 {
		return nil, nil, errManagedEndpointBinding
	}
	secret, err = hkdf.Key(sha256.New, shared, salt, managedDirectCredentialDomain+"credential-secret/v1/"+string(transcript), 32)
	if err != nil {
		return nil, nil, errManagedEndpointBinding
	}
	installKey, err := hkdf.Key(sha256.New, shared, salt, managedDirectCredentialDomain+"install-key/v1/"+string(transcript), 32)
	if err != nil {
		clear(secret)
		return nil, nil, errManagedEndpointBinding
	}
	defer clear(installKey)
	mac := hmac.New(sha256.New, installKey)
	mac.Write([]byte(managedDirectCredentialDomain + "host-install/v1/"))
	mac.Write(transcript)
	return secret, mac.Sum(nil), nil
}

// ManagedDirectCredentialHash binds a 32-byte credential secret to its canonical
// lowercase transcript digest. It does not authenticate either input.
func ManagedDirectCredentialHash(transcriptHash string, secret []byte) (string, error) {
	if !nativeShareBindingHex(transcriptHash) || len(secret) != 32 {
		return "", errManagedEndpointBinding
	}
	transcript, _ := hex.DecodeString(transcriptHash)
	hash := sha256.New()
	hash.Write([]byte(managedDirectCredentialDomain + "credential-hash/v1/"))
	hash.Write(transcript)
	hash.Write(secret)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// DecodeManagedDirectCredentialACKVerifier strictly decodes an ACK and derives
// its public verifier digest. The caller must match the retained credential ID
// and transcript and compare the expected digest in constant time.
func DecodeManagedDirectCredentialACKVerifier(raw []byte) (ManagedDirectCredentialACK, string, error) {
	p, err := DecodeManagedDirectCredentialACK(raw)
	if err != nil {
		return ManagedDirectCredentialACK{}, "", err
	}
	transcript, _ := hex.DecodeString(p.TranscriptHash)
	confirmation, _ := hex.DecodeString(p.HostConfirmation)
	defer clear(confirmation)
	return p, managedDirectCredentialInstallVerifier(transcript, confirmation), nil
}
func managedDirectCredentialInstallVerifier(transcript, confirmation []byte) string {
	hash := sha256.New()
	hash.Write([]byte(managedDirectCredentialDomain + "install-verifier/v1/"))
	hash.Write(transcript)
	hash.Write(confirmation)
	return hex.EncodeToString(hash.Sum(nil))
}
