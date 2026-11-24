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
	ManagedEndpointPoPProtocol = "managed_endpoint_host_custody_pop_v1"
	ManagedEndpointPoPSuite    = "X25519-HKDF-SHA256-HMAC-SHA256"
	managedEndpointPoPKDF      = "pagnet/managed-endpoint-host-custody-pop/kdf/v1/"
	managedEndpointPoPConfirm  = "pagnet/managed-endpoint-host-custody-pop/host-confirm/v1/"
	managedEndpointPoPVerifier = "pagnet/managed-endpoint-host-custody-pop/verifier/v1/"
)

// ManagedEndpointPrepareReceiptReference identifies the canonical complete ACK;
// receiptDigest is plain SHA256 of its canonical bytes, without a domain prefix.
type ManagedEndpointPrepareReceiptReference struct {
	BindingIntentID domain.ID `json:"bindingIntentId"`
	CommandID       domain.ID `json:"commandId"`
	ReceiptDigest   string    `json:"receiptDigest"`
}

func (p ManagedEndpointPrepareReceiptReference) CanonicalBytes() ([]byte, error) {
	if !nativeShareBindingID(p.BindingIntentID) || !nativeShareBindingID(p.CommandID) || !nativeShareBindingHex(p.ReceiptDigest) {
		return nil, errManagedEndpointBinding
	}
	return json.Marshal(p)
}

func DecodeManagedEndpointPrepareReceiptReference(raw []byte) (ManagedEndpointPrepareReceiptReference, error) {
	var p ManagedEndpointPrepareReceiptReference
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return ManagedEndpointPrepareReceiptReference{}, errManagedEndpointBinding
	}
	return p, nil
}

func NewManagedEndpointPrepareReceiptReference(ack ManagedEndpointPrepareACK) (ManagedEndpointPrepareReceiptReference, error) {
	raw, err := ack.CanonicalBytes()
	if err != nil {
		return ManagedEndpointPrepareReceiptReference{}, err
	}
	return ManagedEndpointPrepareReceiptReference{ack.Reservation.Subject.ID, ack.CommandID, managedEndpointDigest("", raw)}, nil
}

// ManagedEndpointPoPChallenge binds complete Prepare evidence and immutable
// consent. The reservation includes the configured origin, installation key and
// complete binding subject/host incarnation. The server generates a fresh
// challenge ID, 32-byte nonce and ephemeral key for every challenge. This pure
// type cannot establish freshness or authenticate the server; callers must do so.
type ManagedEndpointPoPChallenge struct {
	ProtocolVersion       string                                 `json:"protocolVersion"`
	Suite                 string                                 `json:"suite"`
	ChallengeID           domain.ID                              `json:"challengeId"`
	Nonce                 string                                 `json:"nonce"`
	ServerEphemeralX25519 string                                 `json:"serverEphemeralX25519"`
	IssuedAt              time.Time                              `json:"issuedAt"`
	ExpiresAt             time.Time                              `json:"expiresAt"`
	Prepare               ManagedEndpointPrepareCommand          `json:"prepare"`
	ACK                   ManagedEndpointPrepareACK              `json:"ack"`
	Receipt               ManagedEndpointPrepareReceiptReference `json:"receipt"`
	Authorization         DirectAuthorizationSnapshotV1          `json:"authorization"`
	AuthorizationDigest   string                                 `json:"authorizationDigest"`
}

func (p ManagedEndpointPoPChallenge) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != ManagedEndpointPoPProtocol || p.Suite != ManagedEndpointPoPSuite || !nativeShareBindingID(p.ChallengeID) || !nativeShareBindingHex(p.Nonce) || !nativeShareBindingHex(p.ServerEphemeralX25519) {
		return nil, errManagedEndpointBinding
	}
	// Reject noncanonical RFC7748 field encodings, including high-bit aliases.
	pub, _ := hex.DecodeString(p.ServerEphemeralX25519)
	if !managedEndpointCanonicalX25519(pub) {
		return nil, errManagedEndpointBinding
	}
	command, err := p.Prepare.CanonicalBytes()
	if err != nil || json.Unmarshal(command, &p.Prepare) != nil {
		return nil, errManagedEndpointBinding
	}
	ack, err := p.ACK.CanonicalBytes()
	if err != nil {
		return nil, errManagedEndpointBinding
	}
	if _, err = DecodeManagedEndpointPrepareACK(ack, p.Prepare); err != nil || json.Unmarshal(ack, &p.ACK) != nil {
		return nil, errManagedEndpointBinding
	}
	reference, err := NewManagedEndpointPrepareReceiptReference(p.ACK)
	digest, digestErr := p.Authorization.Digest()
	if err != nil || digestErr != nil || p.Receipt != reference || p.AuthorizationDigest != digest || p.Authorization.DirectIntentID != p.Prepare.Subject.DirectIntentID || p.Authorization.Target.PrincipalID != p.Prepare.Subject.PrincipalID || p.Authorization.InviteeTenantID != p.Prepare.Subject.TenantID || p.Authorization.InviteeAccountID != p.Prepare.Subject.AccountID {
		return nil, errManagedEndpointBinding
	}
	for _, v := range []time.Time{p.IssuedAt, p.ExpiresAt} {
		if v.IsZero() || v.Year() < 1 || v.Year() > 9999 {
			return nil, errManagedEndpointBinding
		}
	}
	if !p.IssuedAt.Before(p.ExpiresAt) || p.ExpiresAt.Sub(p.IssuedAt) > 5*time.Minute || p.IssuedAt.Before(p.Prepare.Subject.CreatedAt) || p.IssuedAt.Before(p.Authorization.CreatedAt) || p.ExpiresAt.After(p.Prepare.Subject.ExpiresAt) || p.ExpiresAt.After(p.Authorization.ExpiresAt) {
		return nil, errManagedEndpointBinding
	}
	p.IssuedAt = p.IssuedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	auth, _ := p.Authorization.CanonicalBytes()
	var authorization DirectAuthorizationSnapshotV1
	if json.Unmarshal(auth, &authorization) != nil {
		return nil, errManagedEndpointBinding
	}
	p.Authorization = authorization
	return json.Marshal(p)
}

func managedEndpointCanonicalX25519(pub []byte) bool {
	if len(pub) != 32 {
		return false
	}
	// p = 2^255 - 19, little endian. Public encodings must be below p.
	for i := 31; i >= 0; i-- {
		bound := byte(255)
		if i == 31 {
			bound = 127
		}
		if i == 0 {
			bound = 237
		}
		if pub[i] < bound {
			return true
		}
		if pub[i] > bound {
			return false
		}
	}
	return false
}

func DecodeManagedEndpointPoPChallenge(raw []byte) (ManagedEndpointPoPChallenge, error) {
	var p ManagedEndpointPoPChallenge
	if !managedEndpointCanonicalDecode(raw, &p, 64*1024) {
		return ManagedEndpointPoPChallenge{}, errManagedEndpointBinding
	}
	return p, nil
}

func (p ManagedEndpointPoPChallenge) transcriptHash(now time.Time) ([]byte, error) {
	raw, err := p.CanonicalBytes()
	if err != nil || now.Before(p.IssuedAt) || !now.Before(p.ExpiresAt) {
		return nil, errManagedEndpointBinding
	}
	sum := sha256.Sum256(append([]byte("pagnet/managed-endpoint-host-custody-pop/transcript/v1/"), raw...))
	return sum[:], nil
}

type ManagedEndpointPoPProof struct {
	ProtocolVersion  string    `json:"protocolVersion"`
	Suite            string    `json:"suite"`
	ChallengeID      domain.ID `json:"challengeId"`
	TranscriptHash   string    `json:"transcriptHash"`
	HostConfirmation string    `json:"hostConfirmation"`
}

func (p ManagedEndpointPoPProof) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != ManagedEndpointPoPProtocol || p.Suite != ManagedEndpointPoPSuite || !nativeShareBindingID(p.ChallengeID) || !nativeShareBindingHex(p.TranscriptHash) || !nativeShareBindingHex(p.HostConfirmation) {
		return nil, errManagedEndpointBinding
	}
	return json.Marshal(p)
}
func DecodeManagedEndpointPoPProof(raw []byte) (ManagedEndpointPoPProof, error) {
	var p ManagedEndpointPoPProof
	if !managedEndpointCanonicalDecode(raw, &p, 1024) {
		return ManagedEndpointPoPProof{}, errManagedEndpointBinding
	}
	return p, nil
}

// ConfirmManagedEndpointHostCustody proves possession of the reserved host key,
// never execution of a process or possession of any network epoch key. Inputs
// must have been authenticated and compared with independently retained state.
func ConfirmManagedEndpointHostCustody(p ManagedEndpointPoPChallenge, hostPrivate []byte, now time.Time) (ManagedEndpointPoPProof, error) {
	transcript, err := p.transcriptHash(now)
	if err != nil {
		return ManagedEndpointPoPProof{}, err
	}
	private, err := ecdh.X25519().NewPrivateKey(hostPrivate)
	if err != nil || hex.EncodeToString(private.PublicKey().Bytes()) != p.ACK.Reservation.X25519 {
		return ManagedEndpointPoPProof{}, errManagedEndpointBinding
	}
	publicBytes, _ := hex.DecodeString(p.ServerEphemeralX25519)
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return ManagedEndpointPoPProof{}, errManagedEndpointBinding
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return ManagedEndpointPoPProof{}, errManagedEndpointBinding
	}
	defer clear(shared)
	confirmation, err := managedEndpointPoPConfirmation(shared, p.Nonce, transcript)
	if err != nil {
		return ManagedEndpointPoPProof{}, err
	}
	return ManagedEndpointPoPProof{ManagedEndpointPoPProtocol, ManagedEndpointPoPSuite, p.ChallengeID, hex.EncodeToString(transcript), hex.EncodeToString(confirmation)}, nil
}

// DeriveManagedEndpointPoPVerifier derives the expected transcript hash and
// verifier digest for a live challenge. It returns lowercase SHA256 hex digests,
// never the host confirmation, shared secret, or derived key. The challenge must
// be authenticated and compared with independently retained state by the caller.
// The caller owns serverPrivate and must wipe it when no longer needed; internal
// copies made by Go's crypto implementation are not guaranteed to be zeroized.
func DeriveManagedEndpointPoPVerifier(p ManagedEndpointPoPChallenge, serverPrivate []byte, now time.Time) (transcriptHash string, verifierDigest string, err error) {
	transcript, err := p.transcriptHash(now)
	if err != nil {
		return "", "", err
	}
	private, err := ecdh.X25519().NewPrivateKey(serverPrivate)
	if err != nil || hex.EncodeToString(private.PublicKey().Bytes()) != p.ServerEphemeralX25519 {
		return "", "", errManagedEndpointBinding
	}
	publicBytes, _ := hex.DecodeString(p.ACK.Reservation.X25519)
	if !managedEndpointCanonicalX25519(publicBytes) {
		return "", "", errManagedEndpointBinding
	}
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return "", "", errManagedEndpointBinding
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return "", "", errManagedEndpointBinding
	}
	defer clear(shared)
	confirmation, err := managedEndpointPoPConfirmation(shared, p.Nonce, transcript)
	if err != nil {
		return "", "", err
	}
	defer clear(confirmation)
	return hex.EncodeToString(transcript), managedEndpointPoPVerifierDigest(transcript, confirmation), nil
}

// DecodeManagedEndpointPoPProofVerifier strictly decodes a canonical proof and
// derives its verifier digest. This does not authenticate the proof. The caller
// must match its ChallengeID and TranscriptHash with retained challenge state and
// compare the returned digest with DeriveManagedEndpointPoPVerifier's digest in
// constant time, for example with crypto/subtle.ConstantTimeCompare.
func DecodeManagedEndpointPoPProofVerifier(raw []byte) (ManagedEndpointPoPProof, string, error) {
	proof, err := DecodeManagedEndpointPoPProof(raw)
	if err != nil {
		return ManagedEndpointPoPProof{}, "", err
	}
	transcript, _ := hex.DecodeString(proof.TranscriptHash)
	confirmation, _ := hex.DecodeString(proof.HostConfirmation)
	defer clear(confirmation)
	return proof, managedEndpointPoPVerifierDigest(transcript, confirmation), nil
}

func managedEndpointPoPVerifierDigest(transcript, confirmation []byte) string {
	hash := sha256.New()
	hash.Write([]byte(managedEndpointPoPVerifier))
	hash.Write(transcript)
	hash.Write(confirmation)
	return hex.EncodeToString(hash.Sum(nil))
}

func managedEndpointPoPConfirmation(shared []byte, nonce string, transcript []byte) ([]byte, error) {
	if len(shared) != 32 || bytes.Equal(shared, make([]byte, 32)) || len(transcript) != 32 {
		return nil, errManagedEndpointBinding
	}
	salt, err := hex.DecodeString(nonce)
	if err != nil || len(salt) != 32 {
		return nil, errManagedEndpointBinding
	}
	key, err := hkdf.Key(sha256.New, shared, salt, managedEndpointPoPKDF+string(transcript), 32)
	if err != nil {
		return nil, errManagedEndpointBinding
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(managedEndpointPoPConfirm))
	mac.Write(transcript)
	return mac.Sum(nil), nil
}
