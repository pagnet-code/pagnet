package textbridge

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
)

const SnapshotProfileVersion = "textbridge_snapshot_v1"
const preparedSnapshotDomain = "pagnet/edu-conti/prepared-textbridge-snapshot/v1\x00"
const MaxPreparedSnapshotLifetime = 5 * time.Minute

// SnapshotTarget identifies the exact managed definition approved by the owner.
// The resolver accepts values, never paths, workspace readers or agent runtimes.
type SnapshotTarget struct {
	AgentID               string `json:"agentId"`
	DefinitionRevision    int64  `json:"definitionRevision"`
	DefinitionFingerprint string `json:"definitionFingerprint"`
}

// SnapshotApproval is private owner input. Never publish or log it.
type SnapshotApproval struct {
	Profile              string
	Target               SnapshotTarget
	OwnerApproved        bool
	ExternalInstructions string
	Provider             provider.Config
	CallsPerDay          int64
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

// SnapshotDescriptor is the only public profile view. The digest excludes keys
// and credential fingerprints; neither instruction text nor paths are exposed.
type SnapshotDescriptor struct {
	Version               string `json:"version"`
	Digest                string `json:"digest"`
	ExecutionReady        bool   `json:"executionReady"`
	MaxInputChars         int    `json:"maxInputChars"`
	MaxOutputChars        int    `json:"maxOutputChars"`
	MaxResponseBytes      int    `json:"maxResponseBytes"`
	RequestTimeoutSeconds int    `json:"requestTimeoutSeconds"`
	MaxTokens             int    `json:"maxTokens"`
	MaxConcurrent         int64  `json:"maxConcurrent"`
	CallsPerDay           int64  `json:"callsPerDay"`
}

func validSnapshotValue(s string) bool {
	return strings.TrimSpace(s) != "" && len(s) <= 512 && !strings.ContainsAny(s, "\r\n\x00")
}
func validSnapshotTarget(t SnapshotTarget) bool {
	return validSnapshotValue(t.AgentID) && t.DefinitionRevision > 0 && validSnapshotValue(t.DefinitionFingerprint)
}

// ResolveSnapshot requires explicit selection and exact current definition
// equality. Approval is an owner trust boundary, never invocation content.
func ResolveSnapshot(a SnapshotApproval, current SnapshotTarget) (*SnapshotPlan, error) {
	if a.Profile != SnapshotProfileVersion || !a.OwnerApproved || !validSnapshotTarget(current) || a.Target != current || a.CallsPerDay <= 0 {
		return nil, errors.New("invalid approved text snapshot profile")
	}
	if _, err := provider.NewSnapshot(a.Provider, a.ExternalInstructions); err != nil {
		return nil, err
	}
	d := SnapshotDescriptor{Version: SnapshotProfileVersion, MaxInputChars: provider.MaxInputChars, MaxOutputChars: provider.MaxOutputChars, MaxResponseBytes: provider.MaxResponseBytes, RequestTimeoutSeconds: int(provider.RequestTimeout / time.Second), MaxTokens: provider.MaxOutputTokens, MaxConcurrent: 1, CallsPerDay: a.CallsPerDay}
	// The versioned public commitment binds all nonsecret request semantics and
	// allowances. Key rotations remain private and do not create an oracle.
	raw, _ := json.Marshal(struct {
		Bounds                                      SnapshotDescriptor
		Target                                      SnapshotTarget
		ProviderOrigin, Model, ExternalInstructions string
	}{d, current, a.Provider.BaseURL, a.Provider.Model, a.ExternalInstructions})
	d.Digest = "sha256:" + digest(append([]byte(SnapshotProfileVersion+"\x00"), raw...))
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

// SnapshotPreparationBinding is supplied by authenticated installation and
// challenge state. Verification requires equality with separately trusted state.
type SnapshotPreparationBinding struct {
	InstallationID  string         `json:"installationId"`
	ServiceID       string         `json:"serviceId"`
	Generation      int64          `json:"generation"`
	TenantID        string         `json:"tenantId"`
	HostID          string         `json:"hostId"`
	Target          SnapshotTarget `json:"target"`
	RunnerID        string         `json:"runnerId"`
	Epoch           int64          `json:"epoch"`
	BootID          string         `json:"bootId"`
	ServerChallenge string         `json:"serverChallenge"`
	ServerRevision  int64          `json:"serverRevision"`
}

func (b SnapshotPreparationBinding) valid() bool {
	for _, v := range []string{b.InstallationID, b.ServiceID, b.TenantID, b.HostID, b.RunnerID, b.BootID, b.ServerChallenge} {
		if !validSnapshotValue(v) {
			return false
		}
	}
	return b.Generation > 0 && b.Epoch > 0 && b.ServerRevision > 0 && validSnapshotTarget(b.Target)
}

type SnapshotPreparedTranscript struct {
	Binding   SnapshotPreparationBinding `json:"binding"`
	Profile   SnapshotDescriptor         `json:"profile"`
	IssuedAt  int64                      `json:"issuedAt"`
	ExpiresAt int64                      `json:"expiresAt"`
}

type SignedSnapshotPreparation struct {
	Transcript SnapshotPreparedTranscript `json:"transcript"`
	Signature  []byte                     `json:"signature"`
}

func snapshotSigningBytes(t SnapshotPreparedTranscript) []byte {
	raw, _ := json.Marshal(t)
	return append([]byte(preparedSnapshotDomain), raw...)
}

// PrepareSnapshotDescriptor signs a local, non-executable statement. It does not
// register, send, activate, or imply server acceptance of a runner.
func PrepareSnapshotDescriptor(p *SnapshotPlan, b SnapshotPreparationBinding, now, expires time.Time, key ed25519.PrivateKey) (SignedSnapshotPreparation, error) {
	if p == nil || !b.valid() || b.Target != p.target || len(key) != ed25519.PrivateKeySize || !expires.After(now) || expires.Sub(now) > MaxPreparedSnapshotLifetime {
		return SignedSnapshotPreparation{}, errors.New("invalid snapshot preparation")
	}
	t := SnapshotPreparedTranscript{b, p.Descriptor(), now.Unix(), expires.Unix()}
	if t.ExpiresAt <= t.IssuedAt {
		return SignedSnapshotPreparation{}, errors.New("invalid snapshot preparation lifetime")
	}
	return SignedSnapshotPreparation{t, ed25519.Sign(key, snapshotSigningBytes(t))}, nil
}

// VerifySnapshotPreparation checks the host signature, expiry and the entire
// independently expected transcript (including identity, challenge and bounds).
// It conveys preparation only; executionReady must remain false.
func VerifySnapshotPreparation(s SignedSnapshotPreparation, expected SnapshotPreparedTranscript, now time.Time, hostKey ed25519.PublicKey) error {
	t := s.Transcript
	if len(hostKey) != ed25519.PublicKeySize || t != expected || !t.Binding.valid() || t.Profile.Version != SnapshotProfileVersion || t.Profile.ExecutionReady || t.ExpiresAt <= t.IssuedAt || t.ExpiresAt-t.IssuedAt > int64(MaxPreparedSnapshotLifetime/time.Second) || now.Unix() < t.IssuedAt || now.Unix() >= t.ExpiresAt || !ed25519.Verify(hostKey, snapshotSigningBytes(t), s.Signature) {
		return errors.New("invalid or expired snapshot preparation")
	}
	return nil
}
