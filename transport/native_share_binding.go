package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/domain"
)

const NativeShareBindingVersion = 1
const MsgNativeShareBindingPrepare = "host.native_share_binding_prepare"
const MsgNativeShareBindingProve = "host.native_share_binding_prove"
const NativeShareBindingChallengeInfo = "pagnet/native-share-binding/challenge/v1/"

// NativeShareBinding is public, immutable selection metadata for a dedicated
// context holder. It contains no epoch material or local filesystem locations.
// Generations are nonzero decimal strings on the wire. Expiry is canonical UTC
// RFC3339Nano; current selection, expiry and replay checks remain the caller's job.
type NativeShareBinding struct {
	Version             int       `json:"version"`
	BindingID           domain.ID `json:"bindingId"`
	ProposalID          domain.ID `json:"proposalId"`
	GrantID             domain.ID `json:"grantId"`
	NetworkID           domain.ID `json:"networkId"`
	ProposalGeneration  uint64    `json:"proposalGeneration,string"`
	GrantGeneration     uint64    `json:"grantGeneration,string"`
	PrincipalID         domain.ID `json:"principalId"`
	InstanceID          domain.ID `json:"instanceId"`
	HostID              domain.ID `json:"hostId"`
	NativeAdmissionID   domain.ID `json:"nativeAdmissionId"`
	RunnerID            domain.ID `json:"runnerId"`
	RunnerIncarnationID domain.ID `json:"runnerIncarnationId"`
	RunnerGeneration    uint64    `json:"runnerGeneration,string"`
	ProfileFingerprint  string    `json:"profileFingerprint"`
	ContextID           domain.ID `json:"contextId"`
	ExpiresAt           string    `json:"expiresAt"`
}

// These dormant payloads are intended for reliable host commands. Command IDs
// identify the original command across retries; prepare and prove are distinct.
type NativeShareBindingPreparePayload struct {
	CommandID domain.ID          `json:"commandId"`
	Binding   NativeShareBinding `json:"binding"`
}

type NativeShareBindingPreparedPayload struct {
	Prepare       NativeShareBindingPreparePayload `json:"prepare"`
	HolderID      domain.ID                        `json:"holderId"`
	HolderX25519  string                           `json:"holderX25519"`
	BindingDigest string                           `json:"bindingDigest"`
	Signature     []byte                           `json:"signature"`
}

type NativeShareBindingProvePayload struct {
	Version       int            `json:"version"`
	CommandID     domain.ID      `json:"commandId"`
	BindingDigest string         `json:"bindingDigest"`
	ChallengeID   domain.ID      `json:"challengeId"`
	Challenge     CryptoHPKEWrap `json:"challenge"`
}

type NativeShareBindingProvedPayload struct {
	Version       int       `json:"version"`
	CommandID     domain.ID `json:"commandId"`
	BindingDigest string    `json:"bindingDigest"`
	ChallengeID   domain.ID `json:"challengeId"`
	Challenge     []byte    `json:"challenge"`
	Signature     []byte    `json:"signature"`
}

var errNativeShareBinding = errors.New("transport: invalid native share binding")

func (b NativeShareBinding) CanonicalBytes() ([]byte, error) {
	if b.Version != NativeShareBindingVersion || b.ProposalGeneration == 0 || b.GrantGeneration == 0 || b.RunnerGeneration == 0 || !admissionHex(b.ProfileFingerprint) || !admissionTime(b.ExpiresAt) {
		return nil, errNativeShareBinding
	}
	for _, id := range []domain.ID{b.BindingID, b.ProposalID, b.GrantID, b.NetworkID, b.PrincipalID, b.InstanceID, b.HostID, b.NativeAdmissionID, b.RunnerID, b.RunnerIncarnationID, b.ContextID} {
		if !admissionID(id) {
			return nil, errNativeShareBinding
		}
	}
	return json.Marshal(b)
}

func (p NativeShareBindingPreparePayload) CanonicalBytes() ([]byte, error) {
	if !admissionID(p.CommandID) {
		return nil, errNativeShareBinding
	}
	if _, err := p.Binding.CanonicalBytes(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// Digest covers the full selection, original prepare command and dedicated
// holder identity/key. The digest itself and detached signature are excluded.
func (p NativeShareBindingPreparedPayload) Digest() (string, error) {
	if _, err := p.Prepare.CanonicalBytes(); err != nil {
		return "", err
	}
	if !admissionID(p.HolderID) || !admissionHex(p.HolderX25519) {
		return "", errNativeShareBinding
	}
	raw, err := json.Marshal(struct {
		Prepare      NativeShareBindingPreparePayload `json:"prepare"`
		HolderID     domain.ID                        `json:"holderId"`
		HolderX25519 string                           `json:"holderX25519"`
	}{p.Prepare, p.HolderID, p.HolderX25519})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("pagnet/native-share-binding/binding/v1/"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

func (p NativeShareBindingPreparedPayload) SignatureBytes() ([]byte, error) {
	digest, err := p.Digest()
	if err != nil {
		return nil, err
	}
	if p.BindingDigest != digest {
		return nil, errNativeShareBinding
	}
	return []byte("pagnet/native-share-binding/prepared/v1/" + digest), nil
}

// Verify requires the independently selected command and trusted host key.
// It does not authorize installation, admission, or use of any epoch key.
func (p NativeShareBindingPreparedPayload) Verify(expected NativeShareBindingPreparePayload, host ed25519.PublicKey) error {
	raw, err := p.SignatureBytes()
	if err != nil {
		return err
	}
	if p.Prepare != expected || len(host) != ed25519.PublicKeySize || !ed25519.Verify(host, raw, p.Signature) {
		return errNativeShareBinding
	}
	return nil
}

// ChallengeAAD is used with NativeShareBindingChallengeInfo and the existing
// e2ee HPKE base suite. The plaintext must be a fresh random 32-byte challenge.
// The encrypted challenge is excluded from its own AAD.
func (p NativeShareBindingProvePayload) ChallengeAAD() ([]byte, error) {
	if p.Version != NativeShareBindingVersion || !admissionID(p.CommandID) || !admissionID(p.ChallengeID) || !admissionHex(p.BindingDigest) {
		return nil, errNativeShareBinding
	}
	raw, err := json.Marshal(struct {
		Version       int       `json:"version"`
		CommandID     domain.ID `json:"commandId"`
		BindingDigest string    `json:"bindingDigest"`
		ChallengeID   domain.ID `json:"challengeId"`
	}{p.Version, p.CommandID, p.BindingDigest, p.ChallengeID})
	return append([]byte("pagnet/native-share-binding/challenge-aad/v1/"), raw...), err
}

func (p NativeShareBindingProvePayload) CanonicalBytes() ([]byte, error) {
	if _, err := p.ChallengeAAD(); err != nil {
		return nil, err
	}
	if len(p.Challenge.Enc) != 32 || len(p.Challenge.Ciphertext) != 32+16 {
		return nil, errNativeShareBinding
	}
	return json.Marshal(p)
}

func (p NativeShareBindingProvedPayload) SignatureBytes() ([]byte, error) {
	if _, err := (NativeShareBindingProvePayload{Version: p.Version, CommandID: p.CommandID, BindingDigest: p.BindingDigest, ChallengeID: p.ChallengeID}).ChallengeAAD(); err != nil {
		return nil, err
	}
	if len(p.Challenge) != 32 {
		return nil, errNativeShareBinding
	}
	p.Signature = nil
	raw, err := json.Marshal(p)
	return append([]byte("pagnet/native-share-binding/proved/v1/"), raw...), err
}

// Verify binds the decrypted challenge to the exact independently retained
// command, digest and challenge ID. The host key must come from trusted state.
func (p NativeShareBindingProvedPayload) Verify(expected NativeShareBindingProvePayload, challenge []byte, host ed25519.PublicKey) error {
	if _, err := expected.CanonicalBytes(); err != nil {
		return err
	}
	raw, err := p.SignatureBytes()
	if err != nil {
		return err
	}
	if p.Version != expected.Version || p.CommandID != expected.CommandID || p.BindingDigest != expected.BindingDigest || p.ChallengeID != expected.ChallengeID || !bytes.Equal(p.Challenge, challenge) || len(host) != ed25519.PublicKeySize || !ed25519.Verify(host, raw, p.Signature) {
		return errNativeShareBinding
	}
	return nil
}
