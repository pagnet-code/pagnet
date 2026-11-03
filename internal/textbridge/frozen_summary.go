package textbridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/sdk"
)

const FrozenSummaryVersion = "owner_frozen_summary_v1"
const MaxFrozenSummaryBytes = provider.MaxInputChars * utf8.UTFMax
const maxFrozenSummaryFileBytes = 1 << 20
const maxFrozenSummaryProjects = 256

// FrozenSummaryApproval is private local owner input, never a public descriptor.
// Instructions are captured once at approval. No source path is persisted.
// All fields are immutable except Disabled, which can only transition to true.
// HistoricalSourceLabel is attribution for historical material, never a claim
// that this responder is the current source agent.
type FrozenSummaryApproval struct {
	Version, ID, Server, Service                                        string
	ProjectIDs                                                          []string
	Instructions, ContentDigest                                         string
	ProviderOrigin, Model, KeyFile, KeyFingerprint, ProviderFingerprint string
	CallsPerDay                                                         int64
	CreatedAt, ExpiresAt                                                time.Time
	HistoricalSourceLabel                                               string `json:",omitempty"`
	Disabled                                                            bool
}

// FrozenSummaryInput is supplied by the local owner, never invocation content.
type FrozenSummaryInput struct {
	Profile               Profile
	ProjectIDs            []string
	InstructionFile       string
	CallsPerDay           int64
	ExpiresAt             time.Time
	HistoricalSourceLabel string
}

func frozenSummaryDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func frozenSummaryUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func (a FrozenSummaryApproval) validate() error {
	invalid := errors.New("invalid local frozen summary approval")
	if a.Version != FrozenSummaryVersion || !frozenSummaryUUID(a.ID) || !frozenSummaryUUID(a.Service) || a.CreatedAt.IsZero() || !a.ExpiresAt.After(a.CreatedAt) || a.CallsPerDay <= 0 || !filepath.IsAbs(a.KeyFile) || filepath.Clean(a.KeyFile) != a.KeyFile {
		return invalid
	}
	if (sdk.Config{Server: a.Server, Credential: "pgn_act_v1_local", ExpectedPrincipalID: a.Service}).Validate() != nil {
		return invalid
	}
	if len(a.ProjectIDs) == 0 || len(a.ProjectIDs) > maxFrozenSummaryProjects {
		return invalid
	}
	for i, id := range a.ProjectIDs {
		if !frozenSummaryUUID(id) || (i > 0 && a.ProjectIDs[i-1] >= id) {
			return invalid
		}
	}
	if len(a.Instructions) > MaxFrozenSummaryBytes || a.ContentDigest != frozenSummaryDigest([]byte(a.Instructions)) {
		return invalid
	}
	for _, digest := range []string{a.KeyFingerprint, a.ProviderFingerprint} {
		raw, err := hex.DecodeString(digest)
		if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != digest {
			return invalid
		}
	}
	if _, err := provider.NewSnapshot(provider.Config{BaseURL: a.ProviderOrigin, Model: a.Model, APIKey: "validation-only"}, a.Instructions); err != nil {
		return invalid
	}
	if !utf8.ValidString(a.HistoricalSourceLabel) || len(a.HistoricalSourceLabel) > 256 || strings.IndexFunc(a.HistoricalSourceLabel, unicode.IsControl) >= 0 {
		return invalid
	}
	return nil
}

func frozenSummaryDirectory(dir string) (string, error) {
	if err := PrivateDir(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "frozen-summaries")
	return path, PrivateDir(path)
}

// CreateFrozenSummaryApproval snapshots an owner file and provider binding into
// a new approval ID. It never overwrites an approval or persists an API key.
func CreateFrozenSummaryApproval(dir string, in FrozenSummaryInput, now time.Time) (FrozenSummaryApproval, error) {
	var zero FrozenSummaryApproval
	p := in.Profile
	if p.Disabled || p.ServiceRole() != "responder" || p.ProjectContractName() != SharingProjectContract || p.Limits.MaxConcurrent != 1 || in.CallsPerDay != p.Limits.CallsPerDay {
		return zero, errors.New("frozen summary requires matching enabled V2 responder policy")
	}
	raw, err := ReadPrivate(in.InstructionFile, MaxFrozenSummaryBytes)
	if err != nil {
		return zero, err
	}
	key, err := ReadProviderKey(p.KeyFile)
	if err != nil {
		return zero, err
	}
	config := provider.Config{BaseURL: p.ProviderOrigin, Model: p.Model, APIKey: key}
	if p.Fingerprint != ProviderFingerprint(config) {
		return zero, errors.New("frozen summary provider configuration mismatch")
	}
	projects := append([]string(nil), in.ProjectIDs...)
	sort.Strings(projects)
	a := FrozenSummaryApproval{Version: FrozenSummaryVersion, ID: uuid.NewString(), Server: p.Server, Service: p.Service, ProjectIDs: projects, Instructions: string(raw), ContentDigest: frozenSummaryDigest(raw), ProviderOrigin: p.ProviderOrigin, Model: p.Model, KeyFile: p.KeyFile, KeyFingerprint: frozenSummaryDigest([]byte(key)), ProviderFingerprint: p.Fingerprint, CallsPerDay: in.CallsPerDay, CreatedAt: now.UTC(), ExpiresAt: in.ExpiresAt.UTC(), HistoricalSourceLabel: in.HistoricalSourceLabel}
	if err := a.validate(); err != nil {
		return zero, err
	}
	if !a.ExpiresAt.After(now) {
		return zero, errors.New("frozen summary approval has expired")
	}
	if _, err := provider.NewSnapshot(config, a.Instructions); err != nil {
		return zero, err
	}
	store, err := frozenSummaryDirectory(dir)
	if err != nil {
		return zero, err
	}
	unlock, err := LockProfile(store)
	if err != nil {
		return zero, err
	}
	defer unlock()
	name := a.ID + ".json"
	if _, err := os.Lstat(filepath.Join(store, name)); !errors.Is(err, os.ErrNotExist) {
		return zero, errors.New("frozen summary approval ID already exists or is inaccessible")
	}
	if err := SavePrivateJSON(store, name, a); err != nil {
		return zero, err
	}
	return a, nil
}

// LoadFrozenSummaryApproval reads only saved bytes, never an instruction source.
func LoadFrozenSummaryApproval(dir, id string) (FrozenSummaryApproval, error) {
	var a FrozenSummaryApproval
	if !frozenSummaryUUID(id) {
		return a, errors.New("invalid frozen summary approval ID")
	}
	raw, err := ReadPrivate(filepath.Join(dir, "frozen-summaries", id+".json"), maxFrozenSummaryFileBytes)
	if err != nil {
		return a, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if !utf8.Valid(raw) || d.Decode(&a) != nil || d.Decode(new(any)) != io.EOF || a.ID != id || a.validate() != nil {
		return FrozenSummaryApproval{}, errors.New("invalid saved frozen summary approval")
	}
	return a, nil
}

// DisableFrozenSummaryApproval is irreversible. Edits require a new approval ID.
func DisableFrozenSummaryApproval(dir, id string) error {
	store, err := frozenSummaryDirectory(dir)
	if err != nil {
		return err
	}
	unlock, err := LockProfile(store)
	if err != nil {
		return err
	}
	defer unlock()
	a, err := LoadFrozenSummaryApproval(dir, id)
	if err != nil {
		return err
	}
	if a.Disabled {
		return nil
	}
	a.Disabled = true
	return SavePrivateJSON(store, id+".json", a)
}

// FrozenSummaryPlan captures immutable request semantics by value. It grants no
// tools, workspace, history, or live-agent identity. No production route selects it.
type FrozenSummaryPlan struct {
	approval    FrozenSummaryApproval
	config      provider.Config
	fingerprint string
}

// ResolveFrozenSummary rechecks the private approval, expiry and current local
// provider policy. Future dispatch must resolve again before each provider call
// and compare Fingerprint with queued work; a cached plan cannot detect disable.
func ResolveFrozenSummary(dir, id string, current Profile, now time.Time) (*FrozenSummaryPlan, error) {
	a, err := LoadFrozenSummaryApproval(dir, id)
	if err != nil {
		return nil, err
	}
	if a.Disabled || current.Disabled || !now.Before(a.ExpiresAt) || now.Before(a.CreatedAt) || current.ServiceRole() != "responder" || current.ProjectContractName() != SharingProjectContract || current.Server != a.Server || current.Service != a.Service || current.ProviderOrigin != a.ProviderOrigin || current.Model != a.Model || current.KeyFile != a.KeyFile || current.Fingerprint != a.ProviderFingerprint || current.Limits != (ledger.Limits{CallsPerDay: a.CallsPerDay, MaxConcurrent: 1}) {
		return nil, errors.New("frozen summary approval is inactive or configuration changed")
	}
	key, err := ReadProviderKey(a.KeyFile)
	if err != nil {
		return nil, err
	}
	config := provider.Config{BaseURL: a.ProviderOrigin, Model: a.Model, APIKey: key}
	if frozenSummaryDigest([]byte(key)) != a.KeyFingerprint || ProviderFingerprint(config) != a.ProviderFingerprint {
		return nil, errors.New("frozen summary provider configuration mismatch")
	}
	if _, err := provider.NewSnapshot(config, a.Instructions); err != nil {
		return nil, err
	}
	// Include fixed provider bounds and the complete private approval so changes
	// to attribution, allowance, expiry or any other policy invalidate queued work.
	raw, _ := json.Marshal(struct {
		Domain                                                           string
		Approval                                                         FrozenSummaryApproval
		MaxInputChars, MaxOutputChars, MaxOutputTokens, MaxResponseBytes int
		RequestTimeout                                                   time.Duration
	}{"pagnet/textbridge/frozen-summary-dispatch/v1", a, provider.MaxInputChars, provider.MaxOutputChars, provider.MaxOutputTokens, provider.MaxResponseBytes, provider.RequestTimeout})
	return &FrozenSummaryPlan{approval: a, config: config, fingerprint: frozenSummaryDigest(raw)}, nil
}

// Fingerprint is private dispatch metadata and must never be published as status.
func (p *FrozenSummaryPlan) Fingerprint() string { return p.fingerprint }
func (p *FrozenSummaryPlan) AllowsProject(id string) bool {
	i := sort.SearchStrings(p.approval.ProjectIDs, id)
	return i < len(p.approval.ProjectIDs) && p.approval.ProjectIDs[i] == id
}
func (p *FrozenSummaryPlan) Limits() ledger.Limits {
	return ledger.Limits{CallsPerDay: p.approval.CallsPerDay, MaxConcurrent: 1}
}
func (p *FrozenSummaryPlan) newProvider() (Provider, error) {
	return provider.NewSnapshot(p.config, p.approval.Instructions)
}
