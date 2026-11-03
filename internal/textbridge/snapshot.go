package textbridge

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/transport"
)

const SnapshotProfileVersion = transport.SnapshotProfileVersion
const MaxPreparedSnapshotLifetime = transport.MaxPreparedSnapshotLifetime

type SnapshotTarget = transport.SnapshotTarget

// SnapshotApproval is private owner input. Never publish or log it.
type SnapshotApproval struct {
	Profile              string
	Target               SnapshotTarget
	OwnerApproved        bool
	ExternalInstructions string
	Provider             provider.Config
	CallsPerDay          int64
	// CommitmentKey is a persistent private 32-byte key stored with this approval.
	// Generate it once with crypto/rand and persist it privately with the approval.
	// Reuse it for the same approval; never publish it with the descriptor.
	CommitmentKey []byte `json:"-"`
}

// SnapshotPlan has no exported state and cannot be deserialized into authority.
// All request configuration is captured by value from the approved snapshot.
// No production runtime or CLI selects this dormant profile.
type SnapshotPlan struct {
	target                SnapshotTarget
	instructions          string
	config                provider.Config
	credentialFingerprint string
	descriptor            SnapshotDescriptor
}

type SnapshotDescriptor = transport.SnapshotDescriptor

// ResolveSnapshot requires explicit selection and exact current definition
// equality. Approval is an owner trust boundary, never invocation content.
func ResolveSnapshot(a SnapshotApproval, current SnapshotTarget) (*SnapshotPlan, error) {
	if a.Profile != SnapshotProfileVersion || !a.OwnerApproved || current.Validate() != nil || a.Target != current || a.CallsPerDay <= 0 || len(a.CommitmentKey) != 32 {
		return nil, errors.New("invalid approved text snapshot profile")
	}
	if _, err := provider.NewSnapshot(a.Provider, a.ExternalInstructions); err != nil {
		return nil, err
	}
	d := SnapshotDescriptor{Version: SnapshotProfileVersion, MaxInputChars: provider.MaxInputChars, MaxOutputChars: provider.MaxOutputChars, MaxResponseBytes: provider.MaxResponseBytes, RequestTimeoutSeconds: int(provider.RequestTimeout / time.Second), MaxTokens: provider.MaxOutputTokens, MaxConcurrent: 1, CallsPerDay: a.CallsPerDay}
	// A private keyed commitment binds request semantics and allowances without
	// allowing public descriptors to become offline instruction-guessing oracles.
	// Provider credential rotation does not change this public commitment.
	raw, _ := json.Marshal(struct {
		Bounds                                      SnapshotDescriptor
		Target                                      SnapshotTarget
		ProviderOrigin, Model, ExternalInstructions string
	}{d, current, a.Provider.BaseURL, a.Provider.Model, a.ExternalInstructions})
	mac := hmac.New(sha256.New, a.CommitmentKey)
	mac.Write([]byte("pagnet/textbridge/private-snapshot-commitment/v2\x00"))
	mac.Write(raw)
	d.Digest = "sha256:" + hex.EncodeToString(mac.Sum(nil))
	return &SnapshotPlan{target: current, instructions: a.ExternalInstructions, config: a.Provider, credentialFingerprint: ProviderFingerprint(a.Provider), descriptor: d}, nil
}

func (p *SnapshotPlan) Descriptor() SnapshotDescriptor { return p.descriptor }
func (p *SnapshotPlan) Limits() ledger.Limits {
	return ledger.Limits{CallsPerDay: p.descriptor.CallsPerDay, MaxConcurrent: 1}
}

// newProvider is deliberately package-private: future runtime integration must
// use this same resolved plan, its private fingerprint and durable ledger limits.
// Merely resolving or preparing a plan never sends a request.
func (p *SnapshotPlan) newProvider() (Provider, error) {
	return provider.NewSnapshot(p.config, p.instructions)
}

type SnapshotPreparationBinding = transport.SnapshotPreparationBinding
type SnapshotPreparedTranscript = transport.SnapshotPreparedTranscript
type SignedSnapshotPreparation = transport.SignedSnapshotPreparation

// PrepareSnapshotDescriptor signs a local non-executable statement only.
func PrepareSnapshotDescriptor(p *SnapshotPlan, b SnapshotPreparationBinding, now, expires time.Time, key ed25519.PrivateKey) (SignedSnapshotPreparation, error) {
	if p == nil || b.Target != p.target || !expires.After(now) || expires.Sub(now) > MaxPreparedSnapshotLifetime {
		return SignedSnapshotPreparation{}, errors.New("invalid snapshot preparation")
	}
	return transport.SignSnapshotPreparation(SnapshotPreparedTranscript{Binding: b, Profile: p.Descriptor(), IssuedAt: now.Unix(), ExpiresAt: expires.Unix()}, key)
}
func VerifySnapshotPreparation(s SignedSnapshotPreparation, expected SnapshotPreparedTranscript, now time.Time, hostKey ed25519.PublicKey) error {
	return s.Verify(expected, now, hostKey)
}
