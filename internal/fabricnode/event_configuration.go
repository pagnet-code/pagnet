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
	"github.com/pagnet-code/pagnet/fabric/events/httpbinding"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

var eventConfigurationKey = registry.AuthorityKey{Kind: registry.AuthorityLocalInstallation, ID: "events/configuration:v1"}

type eventConfiguration struct {
	Format   int
	State    string
	Key      durable.KeyReference
	Settings EventSettings
}
type eventConfigurationCipher struct{ Cipher []byte }

func eventScope(i *localinstallation.Installation) durable.Scope {
	c := i.Configuration()
	return durable.Scope{Audience: c.StoreID, Domain: c.Domain}
}
func eventSettingsAAD(i *localinstallation.Installation) []byte {
	c := i.Configuration()
	raw, _ := json.Marshal(struct{ Purpose, Domain, Store string }{"pagnet.installed.events.v1", c.Domain, c.StoreID})
	return raw
}
func eventSettingsSeal(i *localinstallation.Installation, c eventConfiguration) ([]byte, error) {
	raw, e := json.Marshal(c)
	if e != nil || len(raw) > 512<<10 {
		return nil, localDenied()
	}
	defer clear(raw)
	cipher, e := i.Keys.Seal(eventSettingsAAD(i), raw)
	if e != nil {
		return nil, e
	}
	defer clear(cipher)
	return json.Marshal(eventConfigurationCipher{cipher})
}
func eventSettingsOpen(i *localinstallation.Installation, r registry.AuthorityRecord) (eventConfiguration, error) {
	var c eventConfiguration
	var box eventConfigurationCipher
	if r.Key != eventConfigurationKey || r.Retired || (r.Revision != 1 && r.Revision != 2) || registry.VerifyAuthorityRecord(i.Store.AuthorityIdentity(), r) != nil || fabric.DecodeJSONWithLimits(r.Value, &box, fabric.WireLimits{MaxBytes: 768 << 10, MaxDepth: 4, MaxMembers: 4}) != nil {
		return c, localDenied()
	}
	raw, e := i.Keys.Open(eventSettingsAAD(i), box.Cipher)
	if e != nil {
		return c, localDenied()
	}
	defer clear(raw)
	if fabric.DecodeJSONWithLimits(raw, &c, fabric.WireLimits{MaxBytes: 512 << 10, MaxDepth: 32, MaxMembers: 16384}) != nil || c.Format != 1 || c.Key != i.Keys.Reference() || !(c.State == "preparing" && r.Revision == 1 || c.State == "ready" && r.Revision == 2) {
		return eventConfiguration{}, localDenied()
	}
	return c, nil
}
func eventAuthority(ctx context.Context, i *localinstallation.Installation, owner fabric.ExecutionContext, next func(*registry.AuthorityTx) error) error {
	return i.WithCurrentOperator(ctx, owner, func(current context.Context) error {
		return i.Store.WithNativeAuthority(current, owner, registry.AuthorityScope{MaxOperations: 1, Timeout: 5 * time.Second}, next)
	})
}
func eventRecord(ctx context.Context, i *localinstallation.Installation) (registry.AuthorityRecord, error) {
	owner, e := i.Operator(ctx)
	if e != nil {
		return registry.AuthorityRecord{}, e
	}
	var r registry.AuthorityRecord
	e = eventAuthority(ctx, i, owner, func(tx *registry.AuthorityTx) error { var e error; r, e = tx.Get(eventConfigurationKey); return e })
	return r, e
}
func eventDirectory(ctx context.Context, i *localinstallation.Installation) (string, error) {
	root, e := i.Store.CurrentAuthorityDirectory(ctx)
	if e != nil {
		return "", e
	}
	return filepath.Join(root, "events"), nil
}

func validateEventSettings(ctx context.Context, s EventSettings) (EventSettings, error) {
	if ctx == nil || len(s.Observers) < 1 || len(s.Observers) > 1024 {
		return s, localDenied()
	}
	queue, err := durable.ValidateConfig(s.Queue)
	if err != nil {
		return s, err
	}
	s.Queue = queue
	if durable.ValidateIngressConfig(s.Ingress) != nil || s.Ingress.MaxEventBytes > s.Queue.MaxEventBytes || s.DeliveryTimeout < time.Millisecond || s.DeliveryTimeout > time.Minute || s.PollInterval < time.Millisecond || s.PollInterval > time.Second || len(s.Queue.Subscriptions) != len(s.Observers) {
		return s, localDenied()
	}
	known := make(map[string]map[string]bool, len(s.Queue.Subscriptions))
	for _, sub := range s.Queue.Subscriptions {
		types := make(map[string]bool, len(sub.Types))
		for _, kind := range sub.Types {
			types[kind] = true
		}
		known[sub.ID] = types
	}
	// Validate destinations without network/provider callbacks. Store validation
	// independently checks subscriptions/limits before writing its identity.
	for _, o := range s.Observers {
		types, ok := known[o.ID]
		if !ok || len(types) != len(o.Types) || !fabric.ValidNamespacedName(o.CredentialSelector) {
			return s, localDenied()
		}
		for _, kind := range o.Types {
			if !types[kind] {
				return s, localDenied()
			}
			delete(types, kind)
		}
		delete(known, o.ID)
		h, e := httpbinding.New(httpbinding.Config{Endpoint: o.Endpoint, Binding: o.ID, AllowPlainHTTP: o.AllowPlainHTTP, Concurrency: 1, MaxEventBytes: s.Queue.MaxEventBytes, Timeout: s.DeliveryTimeout})
		if e != nil {
			return s, e
		}
		if e = h.CloseContext(ctx); e != nil {
			return s, e
		}
	}
	return s, nil
}

// InitializeConfiguredEvents is an explicit owner operation, never startup
// repair. A FULL preparing pin precedes SQLite creation; a separate FULL ready
// receipt follows verified database setup. Interrupted setup may be explicitly
// retried with exactly the same configuration, original identity and key.
func InitializeConfiguredEvents(ctx context.Context, i *localinstallation.Installation, s EventSettings) error {
	if ctx == nil || i == nil || i.Store == nil || i.Keys == nil || len(s.Observers) < 1 || len(s.Observers) > 1024 {
		return localDenied()
	}
	var err error
	s, err = validateEventSettings(ctx, s)
	if err != nil {
		return err
	}
	want, e := json.Marshal(s)
	if e != nil || len(want) > 512<<10 {
		return localDenied()
	}
	dir, e := eventDirectory(ctx, i)
	if e != nil {
		return e
	}
	r, e := eventRecord(ctx, i)
	if authorityMissing(e) {
		// A directory without its signed root purpose is partial state; explicit
		// setup does not silently attest arbitrary or previously removed state.
		if _, statErr := os.Lstat(dir); !os.IsNotExist(statErr) {
			return localDenied()
		}
		sealed, e := eventSettingsSeal(i, eventConfiguration{1, "preparing", i.Keys.Reference(), s})
		if e != nil {
			return e
		}
		owner, e := i.Operator(ctx)
		if e != nil {
			return e
		}
		e = eventAuthority(ctx, i, owner, func(tx *registry.AuthorityTx) error {
			var e error
			r, e = tx.CAS(eventConfigurationKey, 0, sealed, false)
			return e
		})
		if e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	c, e := eventSettingsOpen(i, r)
	if e != nil {
		return e
	}
	actual, e := json.Marshal(c.Settings)
	if e != nil || !bytes.Equal(actual, want) {
		return fabric.NewError(fabric.CodeInvalidInput, "Event delivery already has a different retained configuration")
	}
	var store *durable.Store
	if c.State == "ready" {
		store, e = durable.Open(ctx, dir, eventScope(i), s.Queue, i.Keys)
	} else {
		_, statErr := os.Lstat(dir)
		if os.IsNotExist(statErr) {
			store, e = durable.Bootstrap(ctx, dir, eventScope(i), s.Queue, i.Keys)
		} else if statErr == nil {
			store, e = durable.Open(ctx, dir, eventScope(i), s.Queue, i.Keys)
		} else {
			e = statErr
		}
	}
	if e != nil {
		return e
	}
	if e = store.Close(); e != nil {
		return e
	}
	if c.State == "ready" {
		return nil
	}
	c.State = "ready"
	sealed, e := eventSettingsSeal(i, c)
	if e != nil {
		return e
	}
	owner, e := i.Operator(ctx)
	if e != nil {
		return e
	}
	return eventAuthority(ctx, i, owner, func(tx *registry.AuthorityTx) error {
		_, e := tx.CAS(eventConfigurationKey, r.Revision, sealed, false)
		return e
	})
}

// OpenInstalledEvents loads only current signed ready configuration and original
// encrypted state. All-missing is disabled. Partial state never regenerates keys,
// changes trust boundaries or creates a database implicitly.
func OpenInstalledEvents(ctx context.Context, i *localinstallation.Installation, providers map[string]httpbinding.CredentialProvider) (*EventRuntime, error) {
	if ctx == nil || i == nil || i.Store == nil || i.Keys == nil {
		return nil, localDenied()
	}
	dir, e := eventDirectory(ctx, i)
	if e != nil {
		return nil, e
	}
	r, e := eventRecord(ctx, i)
	if authorityMissing(e) {
		if _, statErr := os.Lstat(dir); os.IsNotExist(statErr) {
			return nil, nil
		}
		return nil, localDenied()
	}
	if e != nil {
		return nil, e
	}
	c, e := eventSettingsOpen(i, r)
	if e != nil {
		return nil, e
	}
	if c.State != "ready" {
		return nil, fabric.NewError(fabric.CodeTargetUnavailable, "Finish the interrupted explicit event delivery setup")
	}
	return openEventRuntime(ctx, dir, eventScope(i), c.Settings, i.Keys, providers)
}
