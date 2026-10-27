package textbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
)

// Profile contains private local credentials and must never be returned as status.
// Profiles bind a single service to immutable provider policy. There is no
// re-enable operation: disabled profiles cannot revive previously queued work.
type Profile struct {
	ProjectContract                             string `json:",omitempty"`
	Role                                        string `json:",omitempty"`
	Service, Server, Credential                 string
	ProviderOrigin, Model, KeyFile, Fingerprint string
	Limits                                      ledger.Limits
	Disabled                                    bool
	Registration                                *ProfileRegistration `json:",omitempty"`
}

// ProfileRegistration binds a local installation to its confirmed owner state.
// Pending registrations may have no response pins until registration succeeds.
type ProfileRegistration struct {
	InstallationID, HostID string
	Role                   string
	ProfileVersion         int
	TenantID, OwnerUserID  string
	Generation             int64
	DesiredState           string
	Pending                bool
}

func (r *ProfileRegistration) valid() bool {
	if r == nil {
		return true
	}
	canonicalUUID := func(value string) bool {
		id, err := uuid.Parse(value)
		return err == nil && id != uuid.Nil && id.String() == value
	}
	if !canonicalUUID(r.InstallationID) || !canonicalUUID(r.HostID) || (r.Role != "responder" && r.Role != "sender") || r.ProfileVersion != 1 {
		return false
	}
	if r.Pending && r.TenantID == "" && r.OwnerUserID == "" && r.Generation == 0 && r.DesiredState == "" {
		return true
	}
	return canonicalUUID(r.TenantID) && canonicalUUID(r.OwnerUserID) && r.Generation >= 1 && (r.DesiredState == "enabled" || r.DesiredState == "disabled")
}

// ProfileBase resolves the private text bridge directory beneath state. Empty state
// uses ~/.pagnet, matching the CLI. It creates missing directories.
func ProfileBase(state string) (string, error) {
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		state = filepath.Join(home, ".pagnet")
	}
	base, err := filepath.Abs(filepath.Join(state, "text-bridge"))
	if err != nil {
		return "", err
	}
	return base, PrivateDir(base)
}

// ReadProviderKey reads a bounded, private file belonging to the current OS user.
func ReadProviderKey(path string) (string, error) {
	raw, err := ReadPrivate(path, 8192)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", errors.New("provider key file is empty")
	}
	return key, nil
}

// ProviderFingerprint binds provider configuration, including the local key.
func ProviderFingerprint(c provider.Config) string {
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// LoadProfile reads a private profile and verifies its service binding.
// Callers performing mutations must hold LockProfile for the directory.
func LoadProfile(dir, service string) (Profile, error) {
	var p Profile
	raw, err := ReadPrivate(filepath.Join(dir, "profile.json"), 32768)
	if err != nil {
		return p, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Service != service || !p.Registration.valid() {
		return p, errors.New("invalid local text bridge profile")
	}
	// Legacy CLI sender profiles contain only connection fields. Their existing
	// directory identifies the role; no profile files or SDK spool are migrated.
	if p.Role == "" && filepath.Base(filepath.Dir(dir)) == "senders" {
		p.Role = "sender"
	}
	role := p.ServiceRole()
	if (role != "sender" && role != "responder") || (p.Registration != nil && p.Registration.Role != role) || p.validateProjectContractName() != nil {
		return p, errors.New("invalid local text bridge role")
	}
	if role == "sender" {
		if p.ProviderOrigin != "" || p.Model != "" || p.KeyFile != "" || p.Fingerprint != "" || p.Limits != (ledger.Limits{}) {
			return p, errors.New("sender profile must not contain provider configuration")
		}
	} else if !filepath.IsAbs(p.KeyFile) || p.Fingerprint == "" || p.Limits.CallsPerDay <= 0 || p.Limits.MaxConcurrent != 1 {
		return p, errors.New("invalid local text bridge provider profile")
	}
	if err := (sdk.Config{Server: p.Server, Credential: p.Credential, ExpectedPrincipalID: service}).Validate(); err != nil {
		return p, errors.New("invalid local text bridge connection profile")
	}
	return p, nil
}

// SaveProfile durably replaces the local profile. Callers must hold LockProfile.
func SaveProfile(dir string, p Profile) error {
	return SavePrivateJSON(dir, "profile.json", p)
}

// SavePrivateJSON atomically writes JSON with mode 0600 in a private directory.
// The directory must have passed PrivateDir. Only single-component local filenames
// are accepted.
func SavePrivateJSON(dir, name string, value any) error {
	if err := validatePrivateFilename(name); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".profile-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		err = json.NewEncoder(f).Encode(value)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// validatePrivateFilename rejects separators on every supported platform so a
// caller cannot turn a local filename into a path outside the private directory.
func validatePrivateFilename(name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00") {
		return errors.New("invalid local text bridge filename")
	}
	return nil
}

// ProfileDirectory resolves a service beneath the current OS user's private state.
// This is local filesystem ownership, not authorization for a remote owner account.
func ProfileDirectory(state, service string) (string, error) {
	id, err := uuid.Parse(service)
	if err != nil || id == uuid.Nil || id.String() != service {
		return "", errors.New("--service must be a service UUID")
	}
	base, err := ProfileBase(state)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, service)
	return dir, PrivateDir(dir)
}

// ResolveProfile loads a service profile from the current OS user's private state.
// It does not read the provider key, connect remotely, or lock a running responder.
// Mutating callers must instead lock ProfileDirectory before LoadProfile.
func ResolveProfile(state, service string) (string, Profile, error) {
	dir, err := ProfileDirectory(state, service)
	if err != nil {
		return "", Profile{}, err
	}
	p, err := LoadProfile(dir, service)
	return dir, p, err
}

// OpenProfileLedger opens only an existing saved ledger; it never recreates a
// missing ledger for a saved profile. Mutating callers must hold LockProfile.
func OpenProfileLedger(dir string, p Profile) (*ledger.Store, error) {
	if _, err := os.Lstat(filepath.Join(dir, "ledger", "ledger.sqlite")); err != nil {
		return nil, errors.New("saved text bridge ledger is missing or inaccessible")
	}
	return ledger.Open(filepath.Join(dir, "ledger"), p.LedgerBinding(), p.Limits)
}

// ProfileStatus is the owner-safe local status view. It deliberately contains
// no credentials, key paths, provider configuration, or configuration fingerprint.
type ProfileStatus struct {
	Service  string
	Disabled bool
	Budget   ledger.BudgetStatus
}

// ReadProfileStatus snapshots saved status without reading the provider key or
// connecting to a provider or server. It uses the same OS-owner checks as the CLI.
func ReadProfileStatus(ctx context.Context, state, service string) (ProfileStatus, error) {
	dir, p, err := ResolveProfile(state, service)
	if err != nil {
		return ProfileStatus{}, err
	}
	store, err := OpenProfileLedger(dir, p)
	if err != nil {
		return ProfileStatus{}, err
	}
	defer store.Close()
	budget, err := store.BudgetSnapshot(ctx)
	if err != nil {
		return ProfileStatus{}, err
	}
	return ProfileStatus{Service: p.Service, Disabled: p.Disabled, Budget: budget}, nil
}

// ServiceRole preserves the implicit responder role of existing profiles.
func (p Profile) ServiceRole() string {
	if p.Role == "" {
		return "responder"
	}
	return p.Role
}

// ProfileDirectoryForRole retains the existing separate sender state directory.
func ProfileDirectoryForRole(state, service, role string) (string, error) {
	if role == "responder" {
		return ProfileDirectory(state, service)
	}
	if role != "sender" {
		return "", errors.New("text bridge role must be sender or responder")
	}
	id, err := uuid.Parse(service)
	if err != nil || id == uuid.Nil || id.String() != service {
		return "", errors.New("--service must be a service UUID")
	}
	base, err := ProfileBase(state)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "senders", service)
	return dir, PrivateDir(dir)
}

// OpenSenderStore never recreates missing saved sender operation state.
// The caller must hold the profile lock throughout the store's lifetime.
func OpenSenderStore(dir string, p Profile) (*sender.Store, error) {
	if p.ServiceRole() != "sender" {
		return nil, errors.New("sender profile required")
	}
	if _, err := ReadPrivate(filepath.Join(dir, "operations", "state"), 64<<20); err != nil {
		return nil, errors.New("saved sender operation state is missing or inaccessible")
	}
	return sender.Open(filepath.Join(dir, "operations"), p.SenderBinding())
}

const OwnerTextProjectContract = "owner_text_project_v1"
const SharingProjectContract = "sdk_project_v2"

func (p Profile) validateProjectContractName() error {
	if p.ProjectContract != "" && p.ProjectContract != SharingProjectContract && p.ProjectContract != OwnerTextProjectContract {
		return errors.New("unknown text bridge project contract")
	}
	return nil
}
func (p Profile) ProjectContractName() string {
	if p.ProjectContract == "" {
		return SharingProjectContract
	}
	return p.ProjectContract
}
func (p Profile) validateProjectContract() error {
	if err := p.validateProjectContractName(); err != nil {
		return err
	}
	if p.ProjectContract == "" || p.ProjectContract == SharingProjectContract {
		return nil
	}
	if p.ProjectContract != OwnerTextProjectContract {
		return errors.New("unknown text bridge project contract")
	}
	r := p.Registration
	if r == nil || !r.valid() || r.Pending || r.DesiredState != "enabled" || r.Role != p.ServiceRole() {
		return errors.New("owner project requires confirmed enabled installation registration")
	}
	return nil
}
func (p Profile) LedgerBinding() ledger.Binding {
	return ledger.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service, ProjectContract: p.ProjectContract}
}
func (p Profile) SenderBinding() sender.Binding {
	return sender.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service, ProjectContract: p.ProjectContract}
}
