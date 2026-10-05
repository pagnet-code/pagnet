package fabricnode

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

// InstalledServiceSettings is an explicit retained operator choice. No private
// URL, schema, credential value, environment lookup or caller permission lives
// in these infrastructure settings. The installation.json key/root pin remains
// immutable; this independently encrypted signed root row owns service startup.
type InstalledServiceSettings struct {
	ProviderSelector   string                          `json:"providerSelector"`
	InvocationConfig   fabricservices.InvocationConfig `json:"invocationConfig"`
	MaxConnections     int                             `json:"maxConnections"`
	SetupTimeoutMillis int                             `json:"setupTimeoutMillis"`
	SetupConcurrency   int                             `json:"setupConcurrency"`
}
type serviceSettingPlain struct {
	Format   int
	Key      durable.KeyReference
	Settings InstalledServiceSettings
}
type serviceSettingCipher struct{ Cipher []byte }

func DefaultInstalledServiceSettings() InstalledServiceSettings {
	c := DefaultInstalledServiceConfig(fabricservices.CredentialFreeProvider{})
	return settingsFromConfig("credentials.none", c)
}
func settingsFromConfig(selector string, c ServiceRuntimeConfig) InstalledServiceSettings {
	return InstalledServiceSettings{selector, c.InvocationConfig, c.MaxConnections, int(c.SetupTimeout / time.Millisecond), c.SetupConcurrency}
}
func validInstalledServiceSettings(s InstalledServiceSettings) bool {
	if !fabric.ValidNamespacedName(s.ProviderSelector) || len(s.ProviderSelector) > 256 || s.SetupTimeoutMillis < 1 || s.SetupTimeoutMillis > 60000 {
		return false
	}
	c := s.runtimeConfig(fabricservices.CredentialFreeProvider{})
	if !validServiceRuntimeConfig(c) {
		return false
	}
	q := s.InvocationConfig
	return q.MaxInvocations > 0 && q.MaxInvocations <= 1<<20 && q.MaxFrames > 0 && q.MaxFrames <= 1<<24 && q.MaxBytes >= 64<<10 && q.MaxBytes <= 1<<40 && q.MaxFramesPerInvocation > 0 && q.MaxFramesPerInvocation <= 1<<16
}
func (s InstalledServiceSettings) runtimeConfig(p fabricservices.CredentialProvider) ServiceRuntimeConfig {
	return ServiceRuntimeConfig{Credentials: p, InvocationConfig: s.InvocationConfig, MaxConnections: s.MaxConnections, SetupTimeout: time.Duration(s.SetupTimeoutMillis) * time.Millisecond, SetupConcurrency: s.SetupConcurrency}
}
func serviceSettingsAAD(i *localinstallation.Installation) []byte {
	r := i.Store.AuthorityIdentity()
	b, _ := json.Marshal(struct{ Purpose, Domain, Store string }{"pagnet.installed.services.v1", r.Namespace, r.StoreID})
	return b
}
func sealServiceSettings(i *localinstallation.Installation, s InstalledServiceSettings) ([]byte, error) {
	if i == nil || i.Store == nil || i.Keys == nil || !validInstalledServiceSettings(s) {
		return nil, localDenied()
	}
	raw, e := json.Marshal(serviceSettingPlain{1, i.Keys.Reference(), s})
	if e != nil || len(raw) > 8<<10 {
		return nil, localDenied()
	}
	defer clear(raw)
	cipher, e := i.Keys.Seal(serviceSettingsAAD(i), raw)
	if e != nil {
		return nil, e
	}
	defer clear(cipher)
	out, e := json.Marshal(serviceSettingCipher{cipher})
	if e != nil || len(out) > 16<<10 {
		return nil, localDenied()
	}
	return out, nil
}
func decodeServiceSettings(i *localinstallation.Installation, row registry.AuthorityRecord) (InstalledServiceSettings, error) {
	var box serviceSettingCipher
	var zero InstalledServiceSettings
	if row.Retired || row.Revision != 1 || registry.VerifyAuthorityRecord(i.Store.AuthorityIdentity(), row) != nil || len(row.Value) > 16<<10 {
		return zero, localDenied()
	}
	if fabric.DecodeJSONWithLimits(row.Value, &box, fabric.WireLimits{MaxBytes: 16 << 10, MaxDepth: 4, MaxMembers: 4}) != nil || len(box.Cipher) > (8<<10)+64 {
		return zero, localDenied()
	}
	raw, e := i.Keys.Open(serviceSettingsAAD(i), box.Cipher)
	if e != nil {
		return zero, localDenied()
	}
	defer clear(raw)
	var plain serviceSettingPlain
	if fabric.DecodeJSONWithLimits(raw, &plain, fabric.WireLimits{MaxBytes: 8 << 10, MaxDepth: 16, MaxMembers: 128}) != nil || plain.Format != 1 || plain.Key != i.Keys.Reference() || !validInstalledServiceSettings(plain.Settings) {
		return zero, localDenied()
	}
	return plain.Settings, nil
}
func authorityMissing(e error) bool {
	var f *fabric.Error
	return errors.As(e, &f) && f.Code == fabric.CodeNotFound
}

// LoadInstalledServiceSettings distinguishes intentional native-only from
// damaged/partial service state. It never initializes or regenerates any row.
func LoadInstalledServiceSettings(ctx context.Context, i *localinstallation.Installation) (*InstalledServiceSettings, error) {
	if ctx == nil || i == nil || i.Store == nil || i.Keys == nil {
		return nil, localDenied()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	owner, e := i.Operator(ctx)
	if e != nil {
		return nil, e
	}
	keys := []registry.AuthorityKey{fabricservices.InstalledServiceConfigurationKey(), {Kind: registry.AuthorityServiceInvocation, ID: "configuration"}, {Kind: registry.AuthorityServiceInvocation, ID: "startup/header"}}
	rows := make([]registry.AuthorityRecord, 3)
	absent := 0
	e = i.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{MaxOperations: 4, Timeout: 5 * time.Second}, func(tx *registry.AuthorityTx) error {
		for n, k := range keys {
			r, e := tx.Get(k)
			if authorityMissing(e) {
				absent++
				continue
			}
			if e != nil {
				return e
			}
			if r.Retired {
				return localDenied()
			}
			rows[n] = r
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if absent == 3 {
		return nil, nil
	}
	if absent != 0 {
		return nil, localDenied()
	}
	settings, e := decodeServiceSettings(i, rows[0])
	if e != nil {
		return nil, e
	}
	return &settings, nil
}

// InitializeConfiguredServices atomically retains all THREE infrastructure
// records under the existing installation owner/key. No connection/paid turn
// starts; the actual current LocalBoundary is injected for future admissions.
func InitializeConfiguredServices(ctx context.Context, i *localinstallation.Installation, b *LocalBoundary, s InstalledServiceSettings) error {
	if ctx == nil || i == nil || i.Store == nil || i.Keys == nil || b == nil || b.store != i.Store || !validInstalledServiceSettings(s) {
		return localDenied()
	}
	encoded, e := sealServiceSettings(i, s)
	if e != nil {
		return e
	}
	defer clear(encoded)
	owner, e := i.Operator(ctx)
	if e != nil {
		return e
	}
	return i.WithCurrentOperator(ctx, owner, func(current context.Context) error {
		p, e := fabricservices.NewProfileStore(current, i.Store, i.Operator, i.Keys)
		if e != nil {
			return e
		}
		_, _, e = fabricservices.BootstrapConfiguredServiceState(current, p, s.InvocationConfig, b, s.MaxConnections, encoded)
		return e
	})
}

type unavailableServiceProvider struct{}

func (unavailableServiceProvider) Resolve(ctx context.Context, _ string) (fabricservices.Credentials, error) {
	if ctx == nil {
		return fabricservices.Credentials{}, localDenied()
	}
	if e := ctx.Err(); e != nil {
		return fabricservices.Credentials{}, e
	}
	return fabricservices.Credentials{}, fabric.NewError(fabric.CodeUnsupported, "The explicitly configured private service credential provider is unavailable")
}

// selectedInstalledServiceConfig never guesses credentials from catalogs/environment.
func selectedInstalledServiceConfig(s *InstalledServiceSettings, c InstalledConfig) (*ServiceRuntimeConfig, error) {
	if s == nil {
		if c.Services != nil {
			return nil, localDenied()
		}
		return nil, nil
	}
	var p fabricservices.CredentialProvider
	if s.ProviderSelector == "credentials.none" {
		p = fabricservices.CredentialFreeProvider{}
	} else {
		p = c.ServiceProviders[s.ProviderSelector]
	}
	var hook func()
	if c.Services != nil {
		if s.ProviderSelector != "operator.private" || !validServiceRuntimeConfig(*c.Services) || c.Services.SetupTimeout%time.Millisecond != 0 || settingsFromConfig(s.ProviderSelector, *c.Services) != *s {
			return nil, localDenied()
		}
		p = c.Services.Credentials
		hook = c.Services.OnDescriptorsCommitted
	}
	if p == nil {
		p = unavailableServiceProvider{}
	}
	out := s.runtimeConfig(p)
	out.OnDescriptorsCommitted = hook
	return &out, nil
}
