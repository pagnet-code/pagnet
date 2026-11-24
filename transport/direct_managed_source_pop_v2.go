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
	MsgDirectManagedSourcePoPV2      = "host.direct_managed_source_pop"
	DirectManagedSourcePoPProtocolV2 = "direct_managed_source_host_custody_pop_v2"
	DirectManagedSourcePoPSuiteV2    = "X25519-HKDF-SHA256-HMAC-SHA256"
	DirectManagedSourcePoPFailureV2  = "direct_managed_source_pop_failed"
	directManagedSourcePoPKDFV2      = "pagnet/direct-managed-source-host-custody-pop/kdf/v2/"
	directManagedSourcePoPConfirmV2  = "pagnet/direct-managed-source-host-custody-pop/host-confirm/v2/"
	directManagedSourcePoPVerifierV2 = "pagnet/direct-managed-source-host-custody-pop/verifier/v2/"
)

// DirectManagedSourcePrepareReceiptReferenceV2 identifies the canonical complete ACK;
// receiptDigest uses the v2 receipt domain over the canonical complete ACK.
type DirectManagedSourcePrepareReceiptReferenceV2 struct {
	ProtocolVersion string    `json:"protocolVersion"`
	BindingID       domain.ID `json:"bindingId"`
	CommandID       domain.ID `json:"commandId"`
	ReceiptDigest   string    `json:"receiptDigest"`
}

func (p DirectManagedSourcePrepareReceiptReferenceV2) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePrepareProtocolV2 || !nativeShareBindingID(p.BindingID) || !nativeShareBindingID(p.CommandID) || !nativeShareBindingHex(p.ReceiptDigest) {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}

func DecodeDirectManagedSourcePrepareReceiptReferenceV2(raw []byte) (DirectManagedSourcePrepareReceiptReferenceV2, error) {
	var p DirectManagedSourcePrepareReceiptReferenceV2
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return DirectManagedSourcePrepareReceiptReferenceV2{}, errDirectManagedSourceBinding
	}
	return p, nil
}

func NewDirectManagedSourcePrepareReceiptReferenceV2(ack DirectManagedSourcePrepareACKV2) (DirectManagedSourcePrepareReceiptReferenceV2, error) {
	raw, err := ack.CanonicalBytes()
	if err != nil {
		return DirectManagedSourcePrepareReceiptReferenceV2{}, err
	}
	return DirectManagedSourcePrepareReceiptReferenceV2{DirectManagedSourcePrepareProtocolV2, ack.Reservation.Subject.ID, ack.CommandID, managedEndpointDigest("pagnet/direct-managed-source-prepare/receipt/v2/", raw)}, nil
}

// DirectManagedSourcePoPChallengeV2 is the MsgDirectManagedSourcePoPV2 payload. It binds
// complete Prepare evidence and immutable
// consent. The reservation includes the configured origin, installation key and
// complete binding subject/host incarnation. The server generates a fresh
// challenge ID, 32-byte nonce and ephemeral key for every challenge. This pure
// type cannot establish freshness or authenticate the server; callers must do so.
type DirectManagedSourcePoPChallengeV2 struct {
	ProtocolVersion       string                                       `json:"protocolVersion"`
	Suite                 string                                       `json:"suite"`
	ChallengeID           domain.ID                                    `json:"challengeId"`
	Nonce                 string                                       `json:"nonce"`
	ServerEphemeralX25519 string                                       `json:"serverEphemeralX25519"`
	IssuedAt              time.Time                                    `json:"issuedAt"`
	ExpiresAt             time.Time                                    `json:"expiresAt"`
	Prepare               DirectManagedSourcePrepareCommandV2          `json:"prepare"`
	ACK                   DirectManagedSourcePrepareACKV2              `json:"ack"`
	Receipt               DirectManagedSourcePrepareReceiptReferenceV2 `json:"receipt"`
	SourceBindingDigest   string                                       `json:"sourceBindingDigest"`
}

func (p DirectManagedSourcePoPChallengeV2) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePoPProtocolV2 || p.Suite != DirectManagedSourcePoPSuiteV2 || !nativeShareBindingID(p.ChallengeID) || !nativeShareBindingHex(p.Nonce) || !nativeShareBindingHex(p.ServerEphemeralX25519) {
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
	if _, err = DecodeDirectManagedSourcePrepareACKV2(ack, p.Prepare); err != nil || json.Unmarshal(ack, &p.ACK) != nil {
		return nil, errDirectManagedSourceBinding
	}
	reference, err := NewDirectManagedSourcePrepareReceiptReferenceV2(p.ACK)
	digest, digestErr := p.Prepare.Subject.Digest()
	if err != nil || digestErr != nil || p.Receipt != reference || p.SourceBindingDigest != digest {
		return nil, errDirectManagedSourceBinding
	}
	for _, v := range []time.Time{p.IssuedAt, p.ExpiresAt} {
		if v.IsZero() || v.Year() < 1 || v.Year() > 9999 {
			return nil, errDirectManagedSourceBinding
		}
	}
	if !p.IssuedAt.Before(p.ExpiresAt) || p.ExpiresAt.Sub(p.IssuedAt) > 5*time.Minute || p.IssuedAt.Before(p.Prepare.Subject.CreatedAt) || p.ExpiresAt.After(p.Prepare.Subject.EnrollmentExpiresAt) {
		return nil, errDirectManagedSourceBinding
	}
	p.IssuedAt = p.IssuedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	return json.Marshal(p)
}

func DecodeDirectManagedSourcePoPChallengeV2(raw []byte) (DirectManagedSourcePoPChallengeV2, error) {
	var p DirectManagedSourcePoPChallengeV2
	if !managedEndpointCanonicalDecode(raw, &p, 64*1024) {
		return DirectManagedSourcePoPChallengeV2{}, errDirectManagedSourceBinding
	}
	return p, nil
}

func (p DirectManagedSourcePoPChallengeV2) transcriptHash(now time.Time) ([]byte, error) {
	raw, err := p.CanonicalBytes()
	if err != nil || now.Before(p.IssuedAt) || !now.Before(p.ExpiresAt) {
		return nil, errDirectManagedSourceBinding
	}
	sum := sha256.Sum256(append([]byte("pagnet/direct-managed-source-host-custody-pop/transcript/v2/"), raw...))
	return sum[:], nil
}

type DirectManagedSourcePoPProofV2 struct {
	ProtocolVersion  string    `json:"protocolVersion"`
	Suite            string    `json:"suite"`
	ChallengeID      domain.ID `json:"challengeId"`
	TranscriptHash   string    `json:"transcriptHash"`
	HostConfirmation string    `json:"hostConfirmation"`
}

func (p DirectManagedSourcePoPProofV2) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePoPProtocolV2 || p.Suite != DirectManagedSourcePoPSuiteV2 || !nativeShareBindingID(p.ChallengeID) || !nativeShareBindingHex(p.TranscriptHash) || !nativeShareBindingHex(p.HostConfirmation) {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}
func DecodeDirectManagedSourcePoPProofV2(raw []byte) (DirectManagedSourcePoPProofV2, error) {
	var p DirectManagedSourcePoPProofV2
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return DirectManagedSourcePoPProofV2{}, errDirectManagedSourceBinding
	}
	return p, nil
}

// DirectManagedSourcePoPFailureACKV2 carries only the fixed failure code and challenge
// identity; diagnostic details must not enter the wire acknowledgment.
type DirectManagedSourcePoPFailureACKV2 struct {
	ProtocolVersion string    `json:"protocolVersion"`
	ChallengeID     domain.ID `json:"challengeId"`
	Error           string    `json:"error"`
}

func (p DirectManagedSourcePoPFailureACKV2) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePoPProtocolV2 || !nativeShareBindingID(p.ChallengeID) || p.Error != DirectManagedSourcePoPFailureV2 {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}

func DecodeDirectManagedSourcePoPFailureACKV2(raw []byte, challengeID domain.ID) (DirectManagedSourcePoPFailureACKV2, error) {
	var p DirectManagedSourcePoPFailureACKV2
	if !managedEndpointCanonicalDecode(raw, &p, 1024) || p.ChallengeID != challengeID {
		return DirectManagedSourcePoPFailureACKV2{}, errDirectManagedSourceBinding
	}
	return p, nil
}

// ConfirmDirectManagedSourceHostCustodyV2 proves possession of the reserved host key,
// never execution of a process or possession of any network epoch key. Inputs
// must have been authenticated and compared with independently retained state.
func ConfirmDirectManagedSourceHostCustodyV2(p DirectManagedSourcePoPChallengeV2, hostPrivate []byte, now time.Time) (DirectManagedSourcePoPProofV2, error) {
	transcript, err := p.transcriptHash(now)
	if err != nil {
		return DirectManagedSourcePoPProofV2{}, err
	}
	private, err := ecdh.X25519().NewPrivateKey(hostPrivate)
	if err != nil || hex.EncodeToString(private.PublicKey().Bytes()) != p.ACK.Reservation.X25519 {
		return DirectManagedSourcePoPProofV2{}, errDirectManagedSourceBinding
	}
	publicBytes, _ := hex.DecodeString(p.ServerEphemeralX25519)
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return DirectManagedSourcePoPProofV2{}, errDirectManagedSourceBinding
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return DirectManagedSourcePoPProofV2{}, errDirectManagedSourceBinding
	}
	defer clear(shared)
	confirmation, err := directManagedSourcePoPConfirmationV2(shared, p.Nonce, transcript)
	if err != nil {
		return DirectManagedSourcePoPProofV2{}, err
	}
	return DirectManagedSourcePoPProofV2{DirectManagedSourcePoPProtocolV2, DirectManagedSourcePoPSuiteV2, p.ChallengeID, hex.EncodeToString(transcript), hex.EncodeToString(confirmation)}, nil
}

// DeriveDirectManagedSourcePoPVerifierV2 derives the expected transcript hash and
// verifier digest for a live challenge. It returns lowercase SHA256 hex digests,
// never the host confirmation, shared secret, or derived key. The challenge must
// be authenticated and compared with independently retained state by the caller.
// The caller owns serverPrivate and must wipe it when no longer needed; internal
// copies made by Go's crypto implementation are not guaranteed to be zeroized.
func DeriveDirectManagedSourcePoPVerifierV2(p DirectManagedSourcePoPChallengeV2, serverPrivate []byte, now time.Time) (transcriptHash string, verifierDigest string, err error) {
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
	confirmation, err := directManagedSourcePoPConfirmationV2(shared, p.Nonce, transcript)
	if err != nil {
		return "", "", err
	}
	defer clear(confirmation)
	return hex.EncodeToString(transcript), directManagedSourcePoPVerifierDigestV2(transcript, confirmation), nil
}

// DecodeDirectManagedSourcePoPProofVerifierV2 strictly decodes a canonical proof and
// derives its verifier digest. This does not authenticate the proof. The caller
// must match its ChallengeID and TranscriptHash with retained challenge state and
// compare the returned digest with DeriveDirectManagedSourcePoPVerifierV2's digest in
// constant time, for example with crypto/subtle.ConstantTimeCompare.
func DecodeDirectManagedSourcePoPProofVerifierV2(raw []byte) (DirectManagedSourcePoPProofV2, string, error) {
	proof, err := DecodeDirectManagedSourcePoPProofV2(raw)
	if err != nil {
		return DirectManagedSourcePoPProofV2{}, "", err
	}
	transcript, _ := hex.DecodeString(proof.TranscriptHash)
	confirmation, _ := hex.DecodeString(proof.HostConfirmation)
	defer clear(confirmation)
	return proof, directManagedSourcePoPVerifierDigestV2(transcript, confirmation), nil
}

func directManagedSourcePoPVerifierDigestV2(transcript, confirmation []byte) string {
	hash := sha256.New()
	hash.Write([]byte(directManagedSourcePoPVerifierV2))
	hash.Write(transcript)
	hash.Write(confirmation)
	return hex.EncodeToString(hash.Sum(nil))
}

func directManagedSourcePoPConfirmationV2(shared []byte, nonce string, transcript []byte) ([]byte, error) {
	if len(shared) != 32 || bytes.Equal(shared, make([]byte, 32)) || len(transcript) != 32 {
		return nil, errDirectManagedSourceBinding
	}
	salt, err := hex.DecodeString(nonce)
	if err != nil || len(salt) != 32 {
		return nil, errDirectManagedSourceBinding
	}
	key, err := hkdf.Key(sha256.New, shared, salt, directManagedSourcePoPKDFV2+string(transcript), 32)
	if err != nil {
		return nil, errDirectManagedSourceBinding
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(directManagedSourcePoPConfirmV2))
	mac.Write(transcript)
	return mac.Sum(nil), nil
}
