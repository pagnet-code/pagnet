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
	"github.com/pagnet-code/pagnet/sdk"
)

// Profile contains private local credentials and must never be returned as status.
// Profiles bind a single service to immutable provider policy. There is no
// re-enable operation: disabled profiles cannot revive previously queued work.
type Profile struct {
	Service, Server, Credential                 string
	ProviderOrigin, Model, KeyFile, Fingerprint string
	Limits                                      ledger.Limits
	Disabled                                    bool
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
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Service != service || !filepath.IsAbs(p.KeyFile) || p.Fingerprint == "" || p.Limits.CallsPerDay <= 0 || p.Limits.MaxConcurrent != 1 {
		return p, errors.New("invalid local text bridge profile")
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
// The directory must have passed PrivateDir and name must be a local filename.
func SavePrivateJSON(dir, name string, value any) error {
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
	return ledger.Open(filepath.Join(dir, "ledger"), ledger.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service}, p.Limits)
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
