package transport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/domain"
)

const SnapshotProfileVersion = "textbridge_snapshot_v2"
const PreparedSnapshotDomain = "pagnet/textbridge/prepared-snapshot/v2\x00"
const MaxPreparedSnapshotLifetime = 5 * time.Minute
const MaxSnapshotPreparationBytes = 16 << 10

var errSnapshot = errors.New("transport: invalid snapshot preparation")

// SnapshotTarget represents a managed definition fingerprint as "sha256:" plus
// lowercase hex of its raw 32 bytes (the server managedReviewTarget value).
// Consumers must decode the suffix to exactly 32 bytes before comparing with
// that raw server value; it is not a hash of the server fingerprint.
type SnapshotTarget struct {
	AgentID               string `json:"agentId"`
	DefinitionRevision    int64  `json:"definitionRevision"`
	DefinitionFingerprint string `json:"definitionFingerprint"`
}

func (t SnapshotTarget) Validate() error {
	if !nativeShareBindingID(domain.ID(t.AgentID)) || t.DefinitionRevision <= 0 || !snapshotDigest(t.DefinitionFingerprint) {
		return errSnapshot
	}
	return nil
}

// SnapshotDescriptor is a private-keyed commitment to an approved configuration.
// It reveals neither instructions, provider configuration, nor commitment key.
// Preparation does not authorize execution.
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

func snapshotDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && nativeShareBindingHex(strings.TrimPrefix(s, "sha256:"))
}
func (d SnapshotDescriptor) Validate() error {
	if d.Version != SnapshotProfileVersion || !snapshotDigest(d.Digest) || d.ExecutionReady || d.MaxInputChars != 16000 || d.MaxOutputChars != 16000 || d.MaxResponseBytes != 128<<10 || d.RequestTimeoutSeconds != 30 || d.MaxTokens != 4096 || d.MaxConcurrent != 1 || d.CallsPerDay <= 0 {
		return errSnapshot
	}
	return nil
}

// SnapshotPreparationBinding must originate in authenticated installation and
// challenge state. Epoch is the runner's exact persisted connected_at timestamp
// in canonical UTC RFC3339Nano form, with PostgreSQL microsecond precision.
// ServerAudience is the canonical captured server base URL; HTTP is limited to
// literal loopback IPs. BootID is bounded opaque admission state.
type SnapshotPreparationBinding struct {
	InstallationID  string         `json:"installationId"`
	ServiceID       string         `json:"serviceId"`
	Generation      int64          `json:"generation"`
	TenantID        string         `json:"tenantId"`
	HostID          string         `json:"hostId"`
	Target          SnapshotTarget `json:"target"`
	RunnerID        string         `json:"runnerId"`
	Epoch           string         `json:"epoch"`
	BootID          string         `json:"bootId"`
	ServerAudience  string         `json:"serverAudience"`
	ServerChallenge string         `json:"serverChallenge"`
	ServerRevision  int64          `json:"serverRevision"`
}

func (b SnapshotPreparationBinding) Validate() error {
	for _, id := range []string{b.InstallationID, b.ServiceID, b.TenantID, b.HostID, b.RunnerID} {
		if !nativeShareBindingID(domain.ID(id)) {
			return errSnapshot
		}
	}
	challenge, err := base64.RawURLEncoding.DecodeString(b.ServerChallenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != b.ServerChallenge || b.Generation <= 0 || b.ServerRevision <= 0 || !nativeShareBindingTime(b.Epoch) || b.Target.Validate() != nil {
		return errSnapshot
	}
	u, err := url.Parse(b.ServerAudience)
	if err != nil || !utf8.ValidString(b.ServerAudience) || len(b.ServerAudience) > 2048 || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Hostname() == "" || u.User != nil || strings.HasSuffix(u.Path, "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != b.ServerAudience || strings.ToLower(u.Host) != u.Host || strings.ContainsAny(b.ServerAudience, "\x00\r\n") {
		return errSnapshot
	}
	epoch, _ := time.Parse(time.RFC3339Nano, b.Epoch)
	if !nativeShareOpaque(b.BootID) || epoch.Nanosecond()%1000 != 0 {
		return errSnapshot
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return errSnapshot
		}
	}
	return nil
}

type SnapshotPreparedTranscript struct {
	Binding   SnapshotPreparationBinding `json:"binding"`
	Profile   SnapshotDescriptor         `json:"profile"`
	IssuedAt  int64                      `json:"issuedAt"`
	ExpiresAt int64                      `json:"expiresAt"`
}

func (t SnapshotPreparedTranscript) Validate() error {
	// Positive timestamps make ordered subtraction overflow-safe.
	if t.Binding.Validate() != nil || t.Profile.Validate() != nil || t.IssuedAt <= 0 || t.ExpiresAt <= t.IssuedAt || t.ExpiresAt-t.IssuedAt > int64(MaxPreparedSnapshotLifetime/time.Second) {
		return errSnapshot
	}
	return nil
}
func (t SnapshotPreparedTranscript) SigningBytes() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(t)
	return append([]byte(PreparedSnapshotDomain), raw...), err
}

type SignedSnapshotPreparation struct {
	Transcript SnapshotPreparedTranscript `json:"transcript"`
	Signature  []byte                     `json:"signature"`
}

func SignSnapshotPreparation(t SnapshotPreparedTranscript, key ed25519.PrivateKey) (SignedSnapshotPreparation, error) {
	raw, err := t.SigningBytes()
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return SignedSnapshotPreparation{}, errSnapshot
	}
	return SignedSnapshotPreparation{t, ed25519.Sign(key, raw)}, nil
}

// Verify requires the complete independently expected transcript and pinned host
// key. It confers no execution authority or replay protection.
func (s SignedSnapshotPreparation) Verify(expected SnapshotPreparedTranscript, now time.Time, hostKey ed25519.PublicKey) error {
	raw, err := s.Transcript.SigningBytes()
	if err != nil || s.Transcript != expected || len(hostKey) != ed25519.PublicKeySize || len(s.Signature) != ed25519.SignatureSize || now.Unix() < s.Transcript.IssuedAt || now.Unix() >= s.Transcript.ExpiresAt || !ed25519.Verify(hostKey, raw, s.Signature) {
		return errSnapshot
	}
	return nil
}
func EncodeSnapshotPreparation(s SignedSnapshotPreparation) ([]byte, error) {
	if s.Transcript.Validate() != nil || len(s.Signature) != ed25519.SignatureSize {
		return nil, errSnapshot
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > MaxSnapshotPreparationBytes {
		return nil, errSnapshot
	}
	return raw, nil
}

// DecodeSnapshotPreparation accepts only the exact canonical encoding, rejecting
// duplicate/unknown fields, alternate casing, nulls, escapes and trailing bytes.
func DecodeSnapshotPreparation(raw []byte, expected SnapshotPreparedTranscript, now time.Time, hostKey ed25519.PublicKey) (SignedSnapshotPreparation, error) {
	var s SignedSnapshotPreparation
	if len(raw) == 0 || len(raw) > MaxSnapshotPreparationBytes || !utf8.Valid(raw) {
		return s, errSnapshot
	}
	if json.Unmarshal(raw, &s) != nil {
		return SignedSnapshotPreparation{}, errSnapshot
	}
	canonical, err := EncodeSnapshotPreparation(s)
	if err != nil || !bytes.Equal(raw, canonical) || s.Verify(expected, now, hostKey) != nil {
		return SignedSnapshotPreparation{}, errSnapshot
	}
	return s, nil
}
