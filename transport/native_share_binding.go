package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
)

const NativeShareBindingVersion = 1
const MsgNativeShareBindingPrepare = "host.native_share_binding_prepare"
const MsgNativeShareBindingProve = "host.native_share_binding_prove"
const NativeShareBindingChallengeInfo = "pagnet/native-share-binding/challenge/v1/"

// NativeShareBinding is a server-authoritative principal selection for a new,
// closed binding. PrincipalID is not inferred from a local worker record. Owner
// authorization remains server-side. NativeGeneration is the exact opaque native
// Scope.Generation, never a numeric runner generation. All timestamps are UTC
// RFC3339Nano. This metadata grants no membership or access to epoch material.
type NativeShareBinding struct {
	Version          int       `json:"version"`
	BindingID        domain.ID `json:"bindingId"`
	ProposalID       domain.ID `json:"proposalId"`
	GrantID          domain.ID `json:"grantId"`
	NetworkID        domain.ID `json:"networkId"`
	ProposalRevision uint64    `json:"proposalRevision,string"`
	GrantGeneration  uint64    `json:"grantGeneration,string"`
	PrincipalID      domain.ID `json:"principalId"`
	InstanceID       domain.ID `json:"instanceId"`
	NativeGeneration string    `json:"nativeGeneration"`
	ContextID        domain.ID `json:"contextId"`
	ExpiresAt        string    `json:"expiresAt"`
}

// NativeShareBindingSubject is public evidence captured from the original local
// registry and authenticated host session. RunnerEpoch is the existing session
// timestamp, encoded once as canonical UTC RFC3339Nano. No paths or secrets enter
// the transcript. Current expiry, registry and replay checks remain caller duties.
type NativeShareBindingSubject struct {
	ServerURL          string    `json:"serverUrl"`
	TenantID           domain.ID `json:"tenantId"`
	AccountID          domain.ID `json:"accountId"`
	HostID             domain.ID `json:"hostId"`
	NativeAdmissionID  domain.ID `json:"nativeAdmissionId"`
	RunnerID           domain.ID `json:"runnerId"`
	RunnerEpoch        string    `json:"runnerEpoch"`
	BootID             string    `json:"bootId"`
	ProfileFingerprint string    `json:"profileFingerprint"`
}

// These dormant payloads are intended for reliable host commands. Command IDs
// identify the original command across retries; prepare and prove are distinct.
type NativeShareBindingPreparePayload struct {
	CommandID domain.ID          `json:"commandId"`
	Binding   NativeShareBinding `json:"binding"`
}

type NativeShareBindingPreparedPayload struct {
	Prepare       NativeShareBindingPreparePayload `json:"prepare"`
	Subject       NativeShareBindingSubject        `json:"subject"`
	HolderID      domain.ID                        `json:"holderId"`
	HolderX25519  string                           `json:"holderX25519"`
	BindingDigest string                           `json:"bindingDigest"`
	Signature     []byte                           `json:"signature"`
}

// BindingID routes restart-safe proof lookup and is authenticated in both the
// encrypted challenge AAD and the signed reply. It never selects a caller path.
type NativeShareBindingProvePayload struct {
	BindingID     domain.ID      `json:"bindingId"`
	Version       int            `json:"version"`
	CommandID     domain.ID      `json:"commandId"`
	BindingDigest string         `json:"bindingDigest"`
	ChallengeID   domain.ID      `json:"challengeId"`
	Challenge     CryptoHPKEWrap `json:"challenge"`
}

type NativeShareBindingProvedPayload struct {
	BindingID     domain.ID `json:"bindingId"`
	Version       int       `json:"version"`
	CommandID     domain.ID `json:"commandId"`
	BindingDigest string    `json:"bindingDigest"`
	ChallengeID   domain.ID `json:"challengeId"`
	Challenge     []byte    `json:"challenge"`
	Signature     []byte    `json:"signature"`
}

var errNativeShareBinding = errors.New("transport: invalid native share binding")

func nativeShareBindingID(id domain.ID) bool {
	u, err := uuid.Parse(string(id))
	return err == nil && u != uuid.Nil && u.String() == string(id)
}

func nativeShareBindingHex(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func nativeShareBindingTime(s string) bool {
	t, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && !t.IsZero() && t.UTC().Format(time.RFC3339Nano) == s
}

func nativeShareOpaque(s string) bool {
	return s != "" && len(s) <= 256 && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

func (b NativeShareBinding) CanonicalBytes() ([]byte, error) {
	if b.Version != NativeShareBindingVersion || b.ProposalRevision == 0 || b.GrantGeneration == 0 || !nativeShareOpaque(b.NativeGeneration) || !nativeShareBindingTime(b.ExpiresAt) {
		return nil, errNativeShareBinding
	}
	for _, id := range []domain.ID{b.BindingID, b.ProposalID, b.GrantID, b.NetworkID, b.PrincipalID, b.InstanceID, b.ContextID} {
		if !nativeShareBindingID(id) {
			return nil, errNativeShareBinding
		}
	}
	return json.Marshal(b)
}

func (s NativeShareBindingSubject) CanonicalBytes() ([]byte, error) {
	endpoint, err := url.Parse(s.ServerURL)
	if err != nil || (endpoint.Scheme != "https" && endpoint.Scheme != "http") || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || !nativeShareOpaque(s.BootID) || !nativeShareBindingTime(s.RunnerEpoch) || !nativeShareBindingHex(s.ProfileFingerprint) {
		return nil, errNativeShareBinding
	}
	for _, id := range []domain.ID{s.TenantID, s.AccountID, s.HostID, s.NativeAdmissionID, s.RunnerID} {
		if !nativeShareBindingID(id) {
			return nil, errNativeShareBinding
		}
	}
	return json.Marshal(s)
}

func (p NativeShareBindingPreparePayload) CanonicalBytes() ([]byte, error) {
	if !nativeShareBindingID(p.CommandID) {
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
	if _, err := p.Subject.CanonicalBytes(); err != nil {
		return "", err
	}
	if !nativeShareBindingID(p.HolderID) || !nativeShareBindingHex(p.HolderX25519) {
		return "", errNativeShareBinding
	}
	raw, err := json.Marshal(struct {
		Prepare      NativeShareBindingPreparePayload `json:"prepare"`
		Subject      NativeShareBindingSubject        `json:"subject"`
		HolderID     domain.ID                        `json:"holderId"`
		HolderX25519 string                           `json:"holderX25519"`
	}{p.Prepare, p.Subject, p.HolderID, p.HolderX25519})
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

// Verify requires the independently selected command, captured subject and
// trusted host key. It compares the complete transcript rather than trusting
// substituted subject metadata in the reply.
// It does not authorize installation, admission, or use of any epoch key.
func (p NativeShareBindingPreparedPayload) Verify(expected NativeShareBindingPreparePayload, subject NativeShareBindingSubject, host ed25519.PublicKey) error {
	raw, err := p.SignatureBytes()
	if err != nil {
		return err
	}
	if p.Prepare != expected || p.Subject != subject || len(host) != ed25519.PublicKeySize || !ed25519.Verify(host, raw, p.Signature) {
		return errNativeShareBinding
	}
	return nil
}

// ChallengeAAD is used with NativeShareBindingChallengeInfo and the existing
// e2ee HPKE base suite. The plaintext must be a fresh random 32-byte challenge.
// The encrypted challenge is excluded from its own AAD.
func (p NativeShareBindingProvePayload) ChallengeAAD() ([]byte, error) {
	if p.Version != NativeShareBindingVersion || !nativeShareBindingID(p.BindingID) || !nativeShareBindingID(p.CommandID) || !nativeShareBindingID(p.ChallengeID) || !nativeShareBindingHex(p.BindingDigest) {
		return nil, errNativeShareBinding
	}
	raw, err := json.Marshal(struct {
		BindingID     domain.ID `json:"bindingId"`
		Version       int       `json:"version"`
		CommandID     domain.ID `json:"commandId"`
		BindingDigest string    `json:"bindingDigest"`
		ChallengeID   domain.ID `json:"challengeId"`
	}{p.BindingID, p.Version, p.CommandID, p.BindingDigest, p.ChallengeID})
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
	if _, err := (NativeShareBindingProvePayload{BindingID: p.BindingID, Version: p.Version, CommandID: p.CommandID, BindingDigest: p.BindingDigest, ChallengeID: p.ChallengeID}).ChallengeAAD(); err != nil {
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
	if p.BindingID != expected.BindingID || p.Version != expected.Version || p.CommandID != expected.CommandID || p.BindingDigest != expected.BindingDigest || p.ChallengeID != expected.ChallengeID || !bytes.Equal(p.Challenge, challenge) || len(host) != ed25519.PublicKeySize || !ed25519.Verify(host, raw, p.Signature) {
		return errNativeShareBinding
	}
	return nil
}
