// Package localinstallation explicitly installs and loads one owner-private
// local root. Loading never creates identity, key, configuration or workers.
package localinstallation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/internal/privatefs"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

const configFilename = "installation.json"
const keyFilename = "installation.key"
const version = "pagnet.local.installation.v1"
const maxConfigBytes = 8192

var pinKey = registry.AuthorityKey{Kind: registry.AuthorityLocalInstallation, ID: "configuration:v1"}

type Settings struct {
	SocketPath              string `json:"socketPath"`
	MaxWorkers              int    `json:"maxWorkers"`
	MaxStartupMetadataBytes int    `json:"maxStartupMetadataBytes"`
	StartupTimeoutMillis    int    `json:"startupTimeoutMillis"`
}

func DefaultSettings(socket string) Settings { return Settings{socket, 128, 4 << 20, 10000} }

type Options struct {
	Settings        Settings
	RegistryOptions registry.Options
}
type Configuration struct {
	Version      string               `json:"version"`
	Domain       string               `json:"domain"`
	StoreID      string               `json:"storeId"`
	Operator     fabric.Principal     `json:"operator"`
	KeyReference durable.KeyReference `json:"keyReference"`
	Settings     Settings             `json:"settings"`
}
type installationPin struct {
	Version       string               `json:"version"`
	ConfigDigest  [32]byte             `json:"configDigest"`
	KeyCommitment [32]byte             `json:"keyCommitment"`
	KeyReference  durable.KeyReference `json:"keyReference"`
}
type AlreadyInstalledError struct{ Directory, Domain, StoreID string }

func (e *AlreadyInstalledError) Error() string {
	return "Local installation already exists; load its retained identity and configuration"
}

type IncompleteInstallationError struct{ cause error }

func (e *IncompleteInstallationError) Error() string {
	return "Local installation is incomplete or unavailable; existing identity and keys were preserved"
}
func (e *IncompleteInstallationError) Unwrap() error { return e.cause }
func denied() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Current private local operator installation required")
}
func normalizedOptions(options registry.Options) registry.Options {
	if options == (registry.Options{}) {
		return registry.DefaultOptions()
	}
	return options
}
func validSettings(dir string, c Settings) bool {
	if !filepath.IsAbs(c.SocketPath) || filepath.Clean(c.SocketPath) != c.SocketPath || len(c.SocketPath) > 4096 || c.MaxWorkers < 1 || c.MaxWorkers > 4096 || c.MaxStartupMetadataBytes < 1024 || c.MaxStartupMetadataBytes > 64<<20 || c.StartupTimeoutMillis < 1000 || c.StartupTimeoutMillis > 60000 {
		return false
	}
	relative, e := filepath.Rel(dir, c.SocketPath)
	return e == nil && (relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}
func validDirectory(dir string) bool {
	return filepath.IsAbs(dir) && filepath.Clean(dir) == dir && len(dir) <= 4096
}

// Bootstrap is the only key-generating operation. Each private file is flushed
// and published without overwrite before the signed FULL installation pin.
// Partial failure preserves all original files/root; retry never repairs them.
func Bootstrap(ctx context.Context, dir string, o Options) (_ *Installation, err error) {
	if ctx == nil || !validDirectory(dir) || !validSettings(dir, o.Settings) {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid explicit local installation configuration")
	}
	if _, e := os.Lstat(dir); e == nil {
		retained, e := Load(ctx, dir, o.RegistryOptions)
		if e != nil {
			return nil, &IncompleteInstallationError{e}
		}
		existing := &AlreadyInstalledError{dir, retained.configuration.Domain, retained.configuration.StoreID}
		_ = retained.Close()
		return nil, existing
	} else if !os.IsNotExist(e) {
		return nil, &IncompleteInstallationError{e}
	}
	operator, e := currentOperator()
	if e != nil {
		return nil, e
	}
	store, e := registry.BootstrapWithOptions(ctx, dir, operator, normalizedOptions(o.RegistryOptions))
	if e != nil {
		return nil, &IncompleteInstallationError{e}
	}
	keep := false
	defer func() {
		if !keep {
			store.Close()
			if err != nil {
				err = &IncompleteInstallationError{err}
			}
		}
	}()
	owner, e := setupOwner(store, operator)
	if e != nil {
		return nil, e
	}
	rawKey := make([]byte, 32)
	defer clear(rawKey)
	if _, e = rand.Read(rawKey); e != nil {
		return nil, e
	}
	keyID := make([]byte, 16)
	if _, e = rand.Read(keyID); e != nil {
		return nil, e
	}
	root := store.AuthorityIdentity()
	config := Configuration{Version: version, Domain: root.Namespace, StoreID: root.StoreID, Operator: operator, KeyReference: durable.KeyReference{ID: "local-" + hex.EncodeToString(keyID), Version: "1"}, Settings: o.Settings}
	raw, e := json.Marshal(config)
	if e != nil || len(raw) > maxConfigBytes {
		return nil, denied()
	}
	if e = publishFile(dir, keyFilename, rawKey); e != nil {
		return nil, e
	}
	if e = publishFile(dir, configFilename, raw); e != nil {
		return nil, e
	}
	pin := installationPin{version, sha256.Sum256(raw), keyCommitment(root, rawKey), config.KeyReference}
	encoded, _ := json.Marshal(pin)
	e = store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error { _, e := tx.CAS(pinKey, 0, encoded, false); return e })
	if e != nil {
		return nil, e
	}
	installation, e := loaded(ctx, store, dir)
	if e != nil {
		return nil, e
	}
	keep = true
	return installation, nil
}

// Load returns the one actual retained Store with its writer lock held. Missing
// or altered files/key/pin fail closed; no fallback root or secret is generated.
func Load(ctx context.Context, dir string, o registry.Options) (*Installation, error) {
	if ctx == nil || !validDirectory(dir) {
		return nil, denied()
	}
	store, e := registry.OpenWithOptions(ctx, dir, normalizedOptions(o))
	if e != nil {
		return nil, e
	}
	installation, e := loaded(ctx, store, dir)
	if e != nil {
		store.Close()
		return nil, e
	}
	return installation, nil
}
func setupOwner(store *registry.Store, operator fabric.Principal) (fabric.ExecutionContext, error) {
	root := store.AuthorityIdentity()
	if root.Owner != operator {
		return fabric.ExecutionContext{}, denied()
	}
	// This is a locally verified setup capability, with NO live peer-session
	// evidence. It cannot serve as an authenticated external invocation caller.
	return fabric.NewAuthenticatedContext(operator, root.Namespace, []byte(version+":operator-setup:"+root.StoreID))
}
func keyCommitment(root registry.AuthorityIdentity, key []byte) [32]byte {
	raw, _ := json.Marshal(struct{ Purpose, Domain, Store string }{version + ":key", root.Namespace, root.StoreID})
	h := sha256.New()
	h.Write(raw)
	h.Write(key)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func loaded(ctx context.Context, store *registry.Store, dir string) (*Installation, error) {
	actual, e := store.CurrentAuthorityDirectory(ctx)
	if e != nil || actual != dir {
		return nil, denied()
	}
	operator, e := currentOperator()
	if e != nil {
		return nil, e
	}
	owner, e := setupOwner(store, operator)
	if e != nil {
		return nil, e
	}
	raw, e := privatefs.ReadFile(filepath.Join(dir, configFilename), maxConfigBytes)
	if e != nil {
		return nil, e
	}
	var config Configuration
	if e = fabric.DecodeJSONWithLimits(raw, &config, fabric.WireLimits{MaxBytes: maxConfigBytes, MaxDepth: 16, MaxMembers: 128}); e != nil {
		return nil, e
	}
	root := store.AuthorityIdentity()
	if config.Version != version || config.Domain != root.Namespace || config.StoreID != root.StoreID || config.Operator != operator || !validSettings(dir, config.Settings) {
		return nil, denied()
	}
	key, e := privatefs.ReadFile(filepath.Join(dir, keyFilename), 32)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	if len(key) != 32 {
		return nil, denied()
	}
	var pin installationPin
	e = store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
		record, e := tx.Get(pinKey)
		if e != nil {
			return e
		}
		if record.Retired || record.Revision != 1 {
			return denied()
		}
		return fabric.DecodeJSON(record.Value, &pin)
	})
	if e != nil {
		return nil, e
	}
	if pin.Version != version || pin.ConfigDigest != sha256.Sum256(raw) || pin.KeyCommitment != keyCommitment(root, key) || pin.KeyReference != config.KeyReference {
		return nil, denied()
	}
	// Validate the pinned opaque reference through the same crypto implementation.
	if _, e = durable.NewAESGCM(config.KeyReference, key); e != nil {
		return nil, e
	}
	provider := &KeyProvider{reference: config.KeyReference}
	copy(provider.key[:], key)
	installation := &Installation{Store: store, Keys: provider, configuration: config, done: make(chan struct{})}
	pid, birth, err := currentOperatorProcess()
	if err != nil {
		provider.Close()
		return nil, err
	}
	exact := []byte(version + ":operator-setup:" + root.StoreID)
	binding := &operatorBinding{installation: installation, store: store, root: root, operator: operator, pid: pid, birth: birth, setupDigest: sha256.Sum256(exact)}
	installation.binding = binding
	installation.owner, err = fabric.NewAuthenticatedContextWithEvidence(operator, root.Namespace, exact, binding)
	if err != nil {
		provider.Close()
		return nil, err
	}
	return installation, nil
}
func publishFile(dir, name string, data []byte) error {
	file, e := os.CreateTemp(dir, ".installation-")
	if e != nil {
		return e
	}
	defer os.Remove(file.Name())
	if e = file.Chmod(0600); e == nil {
		_, e = file.Write(data)
	}
	if e == nil {
		e = file.Sync()
	}
	closeError := file.Close()
	if e != nil {
		return e
	}
	if closeError != nil {
		return closeError
	}
	if e = privatefs.Publish(file.Name(), filepath.Join(dir, name)); e != nil {
		return e
	}
	if e = os.Remove(file.Name()); e != nil && !os.IsNotExist(e) {
		return e
	}
	return privatefs.SyncDirectory(dir, name)
}

// Installation owns Store and Keys. Close waits for current operator callbacks;
// composed transports/runtime resources must be joined before calling it.
type Installation struct {
	Store         *registry.Store
	Keys          *KeyProvider
	configuration Configuration
	owner         fabric.ExecutionContext
	binding       *operatorBinding
	mu            sync.Mutex
	closing       bool
	active        int
	done          chan struct{}
}

func (*Installation) MarshalJSON() ([]byte, error) { return nil, denied() }
func (*Installation) UnmarshalJSON([]byte) error   { return denied() }

func (i *Installation) Configuration() Configuration { return i.configuration }
func (i *Installation) Operator(ctx context.Context) (fabric.ExecutionContext, error) {
	if e := i.enter(ctx); e != nil {
		return fabric.ExecutionContext{}, e
	}
	defer i.leave()
	if e := i.verify(ctx, i.owner); e != nil {
		return fabric.ExecutionContext{}, e
	}
	return i.owner, nil
}
func (i *Installation) enter(ctx context.Context) error {
	if i == nil || ctx == nil || ctx.Err() != nil {
		return denied()
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closing {
		return denied()
	}
	i.active++
	return nil
}
func (i *Installation) leave() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.active--
	if i.closing && i.active == 0 {
		close(i.done)
	}
}

type operatorBinding struct {
	installation *Installation
	store        *registry.Store
	root         registry.AuthorityIdentity
	operator     fabric.Principal
	pid          int
	birth        string
	setupDigest  [32]byte
}

func (*operatorBinding) MarshalJSON() ([]byte, error) { return nil, denied() }
func (*operatorBinding) UnmarshalJSON([]byte) error   { return denied() }

func (i *Installation) verify(ctx context.Context, owner fabric.ExecutionContext) error {
	proof, ok := owner.AuthenticationEvidence().(*operatorBinding)
	if !ok || proof == nil || proof != i.binding || proof.installation != i || proof.store != i.Store || proof.operator != i.configuration.Operator || owner.VerifyAuthenticatedDigest(proof.setupDigest, i.configuration.Domain) != nil {
		return denied()
	}
	pid, birth, err := currentOperatorProcess()
	if err != nil || pid != proof.pid || birth != proof.birth {
		return denied()
	}

	operator, e := currentOperator()
	if e != nil || operator != i.configuration.Operator || owner.VerifyAuthenticated(i.configuration.Domain) != nil || owner.PrincipalView() != operator {
		return denied()
	}
	root, e := i.Store.CurrentAuthorityIdentity(ctx)
	if e != nil || root.Namespace != i.configuration.Domain || root.StoreID != i.configuration.StoreID || root.Owner != operator || root.KeyRevision != proof.root.KeyRevision || root.Namespace != proof.root.Namespace || root.StoreID != proof.root.StoreID || root.Owner != proof.root.Owner || !bytes.Equal(root.PublicKey, proof.root.PublicKey) {
		return denied()
	}
	return nil
}

// WithCurrentOperator is an independent current OS/root fence, outside SQL.
// Its callback is synchronous, bounded by the caller context, and joined before
// Close. It supplies setup authority only, never live external caller evidence.
func (i *Installation) WithCurrentOperator(ctx context.Context, owner fabric.ExecutionContext, next func(context.Context) error) error {
	if next == nil {
		return denied()
	}
	if e := i.enter(ctx); e != nil {
		return e
	}
	defer i.leave()
	if e := i.verify(ctx, owner); e != nil {
		return e
	}
	e := next(ctx)
	if e != nil {
		return e
	}
	return i.verify(ctx, owner)
}
func (i *Installation) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return denied()
	}
	if i == nil {
		return nil
	}
	i.mu.Lock()
	if !i.closing {
		i.closing = true
		if i.active == 0 {
			close(i.done)
		}
	}
	i.mu.Unlock()
	select {
	case <-i.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return errors.Join(i.Keys.Close(), i.Store.Close())
}
func (i *Installation) Close() error { return i.CloseContext(context.Background()) }
