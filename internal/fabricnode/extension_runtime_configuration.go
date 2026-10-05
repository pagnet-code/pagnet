package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type ExtensionSettings struct {
	MaxProfiles, MaxExtensions, MaxInterceptors, MaxEntryBytes, MaxDirectoryBytes int
	ExecutorConcurrency, MaxActiveInvocations                                     int
	MaxRedirects                                                                  uint32
	SettlementTimeout                                                             time.Duration
	Continuations                                                                 continuation.Options
}

func DefaultExtensionSettings() ExtensionSettings {
	return ExtensionSettings{MaxProfiles: 64, MaxExtensions: 64, MaxInterceptors: 512, MaxEntryBytes: 32768, MaxDirectoryBytes: 32768, ExecutorConcurrency: 32, MaxActiveInvocations: 64, MaxRedirects: 8, SettlementTimeout: 5 * time.Second, Continuations: continuation.DefaultOptions()}
}
func (s ExtensionSettings) validate() error {
	if s.MaxProfiles < 1 || s.MaxProfiles > 256 || s.MaxExtensions < 1 || s.MaxExtensions > 128 || s.MaxInterceptors < 1 || s.MaxInterceptors > 4096 || s.MaxEntryBytes < 1024 || s.MaxEntryBytes > 32768 || s.MaxDirectoryBytes < 1024 || s.MaxDirectoryBytes > 32768 || s.MaxActiveInvocations < 1 || s.MaxActiveInvocations > 65536 || s.ExecutorConcurrency < 1 || s.ExecutorConcurrency > 4096 || s.MaxRedirects < 1 || s.MaxRedirects > 64 || s.SettlementTimeout < time.Millisecond || s.SettlementTimeout > time.Minute {
		return localDenied()
	}
	return continuation.ValidateOptions(s.Continuations)
}

var extensionConfigurationKey = registry.AuthorityKey{Kind: registry.AuthorityLocalInstallation, ID: "extensions/configuration:v1"}

type extensionConfiguration struct {
	Format    uint32
	State     string
	Root      registry.AuthorityIdentity
	Key       durable.KeyReference
	Directory string
	Settings  ExtensionSettings
}
type extensionSetupCipher struct{ Cipher []byte }

func extensionSetupAAD(root registry.AuthorityIdentity, key durable.KeyReference) []byte {
	b, _ := json.Marshal(struct {
		Purpose, Domain, Store, ID string
		Key                        durable.KeyReference
	}{"pagnet.installed.extensions.v1", root.Namespace, root.StoreID, extensionConfigurationKey.ID, key})
	return b
}
func sealExtensionSetup(i *localinstallation.Installation, c extensionConfiguration) ([]byte, error) {
	b, e := json.Marshal(c)
	if e != nil || len(b) > 16384 {
		return nil, localDenied()
	}
	defer clear(b)
	cipher, e := i.Keys.Seal(extensionSetupAAD(c.Root, c.Key), b)
	if e != nil {
		return nil, e
	}
	return json.Marshal(extensionSetupCipher{cipher})
}
func openExtensionSetup(i *localinstallation.Installation, root registry.AuthorityIdentity, r registry.AuthorityRecord) (extensionConfiguration, error) {
	var c extensionConfiguration
	var box extensionSetupCipher
	if r.Key != extensionConfigurationKey || r.Retired || registry.VerifyAuthorityRecord(root, r) != nil || fabric.DecodeJSONWithLimits(r.Value, &box, fabric.WireLimits{MaxBytes: 32768, MaxDepth: 4, MaxMembers: 8}) != nil {
		return c, localDenied()
	}
	b, e := i.Keys.Open(extensionSetupAAD(root, i.Keys.Reference()), box.Cipher)
	if e != nil {
		return c, localDenied()
	}
	defer clear(b)
	if fabric.DecodeJSONWithLimits(b, &c, fabric.WireLimits{MaxBytes: 16384, MaxDepth: 8, MaxMembers: 128}) != nil || c.Format != 1 || c.Key != i.Keys.Reference() || !(root.Namespace == c.Root.Namespace && root.StoreID == c.Root.StoreID && root.Owner == c.Root.Owner && root.KeyRevision == c.Root.KeyRevision && bytes.Equal(root.PublicKey, c.Root.PublicKey)) || c.Settings.validate() != nil || !(c.State == "preparing" && r.Revision == 1 || c.State == "ready" && r.Revision == 2) {
		return extensionConfiguration{}, localDenied()
	}
	return c, nil
}
func extensionSetupRecord(ctx context.Context, i *localinstallation.Installation, key registry.AuthorityKey) (registry.AuthorityRecord, error) {
	owner, e := i.Operator(ctx)
	if e != nil {
		return registry.AuthorityRecord{}, e
	}
	var r registry.AuthorityRecord
	e = i.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 1}, func(tx *registry.AuthorityTx) error { var x error; r, x = tx.Get(key); return x })
	return r, e
}
func extensionRegistryConfig(i *localinstallation.Installation, s ExtensionSettings) extregistry.Config {
	c := extregistry.DefaultConfig(i.Store, i.Keys, func(ctx context.Context, owner fabric.ExecutionContext, _ registry.AuthorityIdentity) error {
		return i.WithCurrentOperator(ctx, owner, func(context.Context) error { return nil })
	})
	c.MaxExtensions = s.MaxExtensions
	c.MaxInterceptors = s.MaxInterceptors
	c.MaxEntryBytes = s.MaxEntryBytes
	c.MaxDirectoryBytes = s.MaxDirectoryBytes
	return c
}

// InitializeExtensionInfrastructure is explicit setup under the retained root.
// A signed preparing pin precedes private SQLite creation; ready publication
// follows verified readback. Startup never completes this interrupted phase.
func InitializeExtensionInfrastructure(ctx context.Context, i *localinstallation.Installation, s ExtensionSettings) error {
	if ctx == nil || i == nil || i.Store == nil || i.Keys == nil || s.validate() != nil {
		return localDenied()
	}
	root, e := i.Store.CurrentAuthorityIdentity(ctx)
	if e != nil {
		return e
	}
	directory, e := i.Store.CurrentAuthorityDirectory(ctx)
	if e != nil {
		return e
	}
	directory = filepath.Join(directory, "continuations")
	owner, e := i.Operator(ctx)
	if e != nil {
		return e
	}
	r, e := extensionSetupRecord(ctx, i, extensionConfigurationKey)
	want := extensionConfiguration{1, "preparing", root, i.Keys.Reference(), directory, s}
	if authorityMissing(e) {
		if _, x := os.Lstat(directory); !os.IsNotExist(x) {
			return localDenied()
		}
		for _, key := range []registry.AuthorityKey{extensionProfileKey(extensionProfilesID), extensionProfileKey("pagnet.extensions.directory")} {
			if _, x := extensionSetupRecord(ctx, i, key); !authorityMissing(x) {
				return localDenied()
			}
		}
		value, x := sealExtensionSetup(i, want)
		if x != nil {
			return x
		}
		e = i.WithCurrentOperator(ctx, owner, func(c context.Context) error {
			return i.Store.WithNativeAuthority(c, owner, registry.AuthorityScope{MaxOperations: 1}, func(tx *registry.AuthorityTx) error {
				var x error
				r, x = tx.CAS(extensionConfigurationKey, 0, value, false)
				return x
			})
		})
		if e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else {
		got, x := openExtensionSetup(i, root, r)
		if x != nil || got.Directory != directory || got.Settings != s {
			return localDenied()
		}
		want.State = got.State
	}
	if e = initializeExtensionProfiles(ctx, i, s.MaxProfiles); e != nil {
		return e
	}
	var extensions *extregistry.Store
	if _, x := extensionSetupRecord(ctx, i, extensionProfileKey("pagnet.extensions.directory")); authorityMissing(x) {
		extensions, e = extregistry.Bootstrap(ctx, owner, extensionRegistryConfig(i, s))
	} else if x != nil {
		return x
	} else {
		extensions, e = extregistry.Open(ctx, owner, extensionRegistryConfig(i, s))
	}
	if e != nil {
		return e
	}
	if e = extensions.Close(); e != nil {
		return e
	}
	var store *continuation.Store
	if _, x := os.Lstat(filepath.Join(directory, "continuations.sqlite")); os.IsNotExist(x) && want.State == "preparing" {
		store, e = continuation.Bootstrap(ctx, directory, continuation.Scope{Audience: root.Namespace}, s.Continuations, i.Keys)
	} else {
		store, e = continuation.Open(ctx, directory, continuation.Scope{Audience: root.Namespace}, s.Continuations, i.Keys)
	}
	if e != nil {
		return e
	}
	if e = store.Close(); e != nil {
		return e
	}
	if want.State == "ready" {
		return nil
	}
	want.State = "ready"
	value, e := sealExtensionSetup(i, want)
	if e != nil {
		return e
	}
	return i.WithCurrentOperator(ctx, owner, func(c context.Context) error {
		return i.Store.WithNativeAuthority(c, owner, registry.AuthorityScope{MaxOperations: 1}, func(tx *registry.AuthorityTx) error {
			_, x := tx.CAS(extensionConfigurationKey, 1, value, false)
			return x
		})
	})
}

type extensionInfrastructure struct {
	Settings      ExtensionSettings
	Registry      *extregistry.Store
	Profiles      *ExtensionProfiles
	Continuations *continuation.Store
}

func openExtensionInfrastructure(ctx context.Context, i *localinstallation.Installation) (*extensionInfrastructure, error) {
	if ctx == nil || i == nil {
		return nil, localDenied()
	}
	r, e := extensionSetupRecord(ctx, i, extensionConfigurationKey)
	if authorityMissing(e) {
		for _, key := range []registry.AuthorityKey{extensionProfileKey(extensionProfilesID), extensionProfileKey("pagnet.extensions.directory")} {
			if _, x := extensionSetupRecord(ctx, i, key); !authorityMissing(x) {
				return nil, localDenied()
			}
		}
		dir, x := i.Store.CurrentAuthorityDirectory(ctx)
		if x != nil {
			return nil, x
		}
		if _, x = os.Lstat(filepath.Join(dir, "continuations")); !os.IsNotExist(x) {
			return nil, localDenied()
		}
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	root, e := i.Store.CurrentAuthorityIdentity(ctx)
	if e != nil {
		return nil, e
	}
	c, e := openExtensionSetup(i, root, r)
	if e != nil || c.State != "ready" {
		return nil, localDenied()
	}
	dir, e := i.Store.CurrentAuthorityDirectory(ctx)
	if e != nil || c.Directory != filepath.Join(dir, "continuations") {
		return nil, localDenied()
	}
	p, e := OpenExtensionProfiles(ctx, i, c.Settings.MaxProfiles)
	if e != nil {
		return nil, e
	}
	owner, e := i.Operator(ctx)
	if e != nil {
		return nil, e
	}
	extensions, e := extregistry.Open(ctx, owner, extensionRegistryConfig(i, c.Settings))
	if e != nil {
		return nil, e
	}
	store, e := continuation.Open(ctx, c.Directory, continuation.Scope{Audience: root.Namespace}, c.Settings.Continuations, i.Keys)
	if e != nil {
		extensions.Close()
		return nil, e
	}
	return &extensionInfrastructure{c.Settings, extensions, p, store}, nil
}
