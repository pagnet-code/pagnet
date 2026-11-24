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
	MsgDirectManagedSourcePoP      = "host.direct_managed_source_pop"
	DirectManagedSourcePoPProtocol = "direct_managed_source_host_custody_pop_v1"
	DirectManagedSourcePoPSuite    = "X25519-HKDF-SHA256-HMAC-SHA256"
	DirectManagedSourcePoPFailure  = "direct_managed_source_pop_failed"
	directManagedSourcePoPKDF      = "pagnet/direct-managed-source-host-custody-pop/kdf/v1/"
	directManagedSourcePoPConfirm  = "pagnet/direct-managed-source-host-custody-pop/host-confirm/v1/"
	directManagedSourcePoPVerifier = "pagnet/direct-managed-source-host-custody-pop/verifier/v1/"
)

// DirectManagedSourcePrepareReceiptReference identifies the canonical complete ACK;
// receiptDigest is plain SHA256 of its canonical bytes, without a domain prefix.
type DirectManagedSourcePrepareReceiptReference struct {
	BindingID     domain.ID `json:"bindingId"`
	CommandID     domain.ID `json:"commandId"`
	ReceiptDigest string    `json:"receiptDigest"`
}

func (p DirectManagedSourcePrepareReceiptReference) CanonicalBytes() ([]byte, error) {
	if !nativeShareBindingID(p.BindingID) || !nativeShareBindingID(p.CommandID) || !nativeShareBindingHex(p.ReceiptDigest) {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}

func DecodeDirectManagedSourcePrepareReceiptReference(raw []byte) (DirectManagedSourcePrepareReceiptReference, error) {
	var p DirectManagedSourcePrepareReceiptReference
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return DirectManagedSourcePrepareReceiptReference{}, errDirectManagedSourceBinding
	}
	return p, nil
}

func NewDirectManagedSourcePrepareReceiptReference(ack DirectManagedSourcePrepareACK) (DirectManagedSourcePrepareReceiptReference, error) {
	raw, err := ack.CanonicalBytes()
	if err != nil {
		return DirectManagedSourcePrepareReceiptReference{}, err
	}
	return DirectManagedSourcePrepareReceiptReference{ack.Reservation.Subject.ID, ack.CommandID, managedEndpointDigest("", raw)}, nil
}

// DirectManagedSourcePoPChallenge is the MsgDirectManagedSourcePoP payload. It binds
// complete Prepare evidence and immutable
// consent. The reservation includes the configured origin, installation key and
// complete binding subject/host incarnation. The server generates a fresh
// challenge ID, 32-byte nonce and ephemeral key for every challenge. This pure
// type cannot establish freshness or authenticate the server; callers must do so.
type DirectManagedSourcePoPChallenge struct {
	ProtocolVersion       string                                     `json:"protocolVersion"`
	Suite                 string                                     `json:"suite"`
	ChallengeID           domain.ID                                  `json:"challengeId"`
	Nonce                 string                                     `json:"nonce"`
	ServerEphemeralX25519 string                                     `json:"serverEphemeralX25519"`
	IssuedAt              time.Time                                  `json:"issuedAt"`
	ExpiresAt             time.Time                                  `json:"expiresAt"`
	Prepare               DirectManagedSourcePrepareCommand          `json:"prepare"`
	ACK                   DirectManagedSourcePrepareACK              `json:"ack"`
	Receipt               DirectManagedSourcePrepareReceiptReference `json:"receipt"`
	SourceBindingDigest   string                                     `json:"sourceBindingDigest"`
}

func (p DirectManagedSourcePoPChallenge) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePoPProtocol || p.Suite != DirectManagedSourcePoPSuite || !nativeShareBindingID(p.ChallengeID) || !nativeShareBindingHex(p.Nonce) || !nativeShareBindingHex(p.ServerEphemeralX25519) {
		return nil, errDirectManagedSourceBinding
	}
	// Reject noncanonical RFC7748 field encodings, including high-bit aliases.
	pub, _ := hex.DecodeString(p.ServerEphemeralX25519)
	if !directManagedSourceUsableX25519(pub) {
		return nil, errDirectManagedSourceBinding
	}
	command, err := p.Prepare.CanonicalBytes()
	if err != nil || json.Unmarshal(command, &p.Prepare) != nil {
		return nil, errDirectManagedSourceBinding
	}
	ack, err := p.ACK.CanonicalBytes()
	if err != nil {
		return nil, errDirectManagedSourceBinding
	}
	if _, err = DecodeDirectManagedSourcePrepareACK(ack, p.Prepare); err != nil || json.Unmarshal(ack, &p.ACK) != nil {
		return nil, errDirectManagedSourceBinding
	}
	reference, err := NewDirectManagedSourcePrepareReceiptReference(p.ACK)
	digest, digestErr := p.Prepare.Subject.Digest()
	if err != nil || digestErr != nil || p.Receipt != reference || p.SourceBindingDigest != digest {
		return nil, errDirectManagedSourceBinding
	}
	for _, v := range []time.Time{p.IssuedAt, p.ExpiresAt} {
		if v.IsZero() || v.Year() < 1 || v.Year() > 9999 {
			return nil, errDirectManagedSourceBinding
		}
	}
	if !p.IssuedAt.Before(p.ExpiresAt) || p.ExpiresAt.Sub(p.IssuedAt) > 5*time.Minute || p.IssuedAt.Before(p.Prepare.Subject.CreatedAt) || p.ExpiresAt.After(p.Prepare.Subject.ExpiresAt) {
		return nil, errDirectManagedSourceBinding
	}
	p.IssuedAt = p.IssuedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	return json.Marshal(p)
}

func DecodeDirectManagedSourcePoPChallenge(raw []byte) (DirectManagedSourcePoPChallenge, error) {
	var p DirectManagedSourcePoPChallenge
	if !managedEndpointCanonicalDecode(raw, &p, 64*1024) {
		return DirectManagedSourcePoPChallenge{}, errDirectManagedSourceBinding
	}
	return p, nil
}

func (p DirectManagedSourcePoPChallenge) transcriptHash(now time.Time) ([]byte, error) {
	raw, err := p.CanonicalBytes()
	if err != nil || now.Before(p.IssuedAt) || !now.Before(p.ExpiresAt) {
		return nil, errDirectManagedSourceBinding
	}
	sum := sha256.Sum256(append([]byte("pagnet/direct-managed-source-host-custody-pop/transcript/v1/"), raw...))
	return sum[:], nil
}

type DirectManagedSourcePoPProof struct {
	ProtocolVersion  string    `json:"protocolVersion"`
	Suite            string    `json:"suite"`
	ChallengeID      domain.ID `json:"challengeId"`
	TranscriptHash   string    `json:"transcriptHash"`
	HostConfirmation string    `json:"hostConfirmation"`
}

func (p DirectManagedSourcePoPProof) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePoPProtocol || p.Suite != DirectManagedSourcePoPSuite || !nativeShareBindingID(p.ChallengeID) || !nativeShareBindingHex(p.TranscriptHash) || !nativeShareBindingHex(p.HostConfirmation) {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}
func DecodeDirectManagedSourcePoPProof(raw []byte) (DirectManagedSourcePoPProof, error) {
	var p DirectManagedSourcePoPProof
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return DirectManagedSourcePoPProof{}, errDirectManagedSourceBinding
	}
	return p, nil
}

// DirectManagedSourcePoPFailureACK carries only the fixed failure code and challenge
// identity; diagnostic details must not enter the wire acknowledgment.
type DirectManagedSourcePoPFailureACK struct {
	ProtocolVersion string    `json:"protocolVersion"`
	ChallengeID     domain.ID `json:"challengeId"`
	Error           string    `json:"error"`
}

func (p DirectManagedSourcePoPFailureACK) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePoPProtocol || !nativeShareBindingID(p.ChallengeID) || p.Error != DirectManagedSourcePoPFailure {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}

func DecodeDirectManagedSourcePoPFailureACK(raw []byte, challengeID domain.ID) (DirectManagedSourcePoPFailureACK, error) {
	var p DirectManagedSourcePoPFailureACK
	if !managedEndpointCanonicalDecode(raw, &p, 1024) || p.ChallengeID != challengeID {
		return DirectManagedSourcePoPFailureACK{}, errDirectManagedSourceBinding
	}
	return p, nil
}

// ConfirmDirectManagedSourceHostCustody proves possession of the reserved host key,
// never execution of a process or possession of any network epoch key. Inputs
// must have been authenticated and compared with independently retained state.
func ConfirmDirectManagedSourceHostCustody(p DirectManagedSourcePoPChallenge, hostPrivate []byte, now time.Time) (DirectManagedSourcePoPProof, error) {
	transcript, err := p.transcriptHash(now)
	if err != nil {
		return DirectManagedSourcePoPProof{}, err
	}
	private, err := ecdh.X25519().NewPrivateKey(hostPrivate)
	if err != nil || hex.EncodeToString(private.PublicKey().Bytes()) != p.ACK.Reservation.X25519 {
		return DirectManagedSourcePoPProof{}, errDirectManagedSourceBinding
	}
	publicBytes, _ := hex.DecodeString(p.ServerEphemeralX25519)
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return DirectManagedSourcePoPProof{}, errDirectManagedSourceBinding
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return DirectManagedSourcePoPProof{}, errDirectManagedSourceBinding
	}
	defer clear(shared)
	confirmation, err := directManagedSourcePoPConfirmation(shared, p.Nonce, transcript)
	if err != nil {
		return DirectManagedSourcePoPProof{}, err
	}
	return DirectManagedSourcePoPProof{DirectManagedSourcePoPProtocol, DirectManagedSourcePoPSuite, p.ChallengeID, hex.EncodeToString(transcript), hex.EncodeToString(confirmation)}, nil
}

// DeriveDirectManagedSourcePoPVerifier derives the expected transcript hash and
// verifier digest for a live challenge. It returns lowercase SHA256 hex digests,
// never the host confirmation, shared secret, or derived key. The challenge must
// be authenticated and compared with independently retained state by the caller.
// The caller owns serverPrivate and must wipe it when no longer needed; internal
// copies made by Go's crypto implementation are not guaranteed to be zeroized.
func DeriveDirectManagedSourcePoPVerifier(p DirectManagedSourcePoPChallenge, serverPrivate []byte, now time.Time) (transcriptHash string, verifierDigest string, err error) {
	transcript, err := p.transcriptHash(now)
	if err != nil {
		return "", "", err
	}
	private, err := ecdh.X25519().NewPrivateKey(serverPrivate)
	if err != nil || hex.EncodeToString(private.PublicKey().Bytes()) != p.ServerEphemeralX25519 {
		return "", "", errDirectManagedSourceBinding
	}
	publicBytes, _ := hex.DecodeString(p.ACK.Reservation.X25519)
	if !managedEndpointCanonicalX25519(publicBytes) {
		return "", "", errDirectManagedSourceBinding
	}
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return "", "", errDirectManagedSourceBinding
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return "", "", errDirectManagedSourceBinding
	}
	defer clear(shared)
	confirmation, err := directManagedSourcePoPConfirmation(shared, p.Nonce, transcript)
	if err != nil {
		return "", "", err
	}
	defer clear(confirmation)
	return hex.EncodeToString(transcript), directManagedSourcePoPVerifierDigest(transcript, confirmation), nil
}

// DecodeDirectManagedSourcePoPProofVerifier strictly decodes a canonical proof and
// derives its verifier digest. This does not authenticate the proof. The caller
// must match its ChallengeID and TranscriptHash with retained challenge state and
// compare the returned digest with DeriveDirectManagedSourcePoPVerifier's digest in
// constant time, for example with crypto/subtle.ConstantTimeCompare.
func DecodeDirectManagedSourcePoPProofVerifier(raw []byte) (DirectManagedSourcePoPProof, string, error) {
	proof, err := DecodeDirectManagedSourcePoPProof(raw)
	if err != nil {
		return DirectManagedSourcePoPProof{}, "", err
	}
	transcript, _ := hex.DecodeString(proof.TranscriptHash)
	confirmation, _ := hex.DecodeString(proof.HostConfirmation)
	defer clear(confirmation)
	return proof, directManagedSourcePoPVerifierDigest(transcript, confirmation), nil
}

func directManagedSourcePoPVerifierDigest(transcript, confirmation []byte) string {
	hash := sha256.New()
	hash.Write([]byte(directManagedSourcePoPVerifier))
	hash.Write(transcript)
	hash.Write(confirmation)
	return hex.EncodeToString(hash.Sum(nil))
}

func directManagedSourcePoPConfirmation(shared []byte, nonce string, transcript []byte) ([]byte, error) {
	if len(shared) != 32 || bytes.Equal(shared, make([]byte, 32)) || len(transcript) != 32 {
		return nil, errDirectManagedSourceBinding
	}
	salt, err := hex.DecodeString(nonce)
	if err != nil || len(salt) != 32 {
		return nil, errDirectManagedSourceBinding
	}
	key, err := hkdf.Key(sha256.New, shared, salt, directManagedSourcePoPKDF+string(transcript), 32)
	if err != nil {
		return nil, errDirectManagedSourceBinding
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(directManagedSourcePoPConfirm))
	mac.Write(transcript)
	return mac.Sum(nil), nil
}
