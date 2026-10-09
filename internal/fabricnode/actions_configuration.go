package fabricnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/actions"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

var actionsConfigurationKey = registry.AuthorityKey{Kind: registry.AuthorityLocalInstallation, ID: "actions/configuration:v1"}

type actionsConfiguration struct {
	Format   int
	State    string
	Key      durable.KeyReference
	Settings ActionsSettings
}
type actionsConfigurationCipher struct{ Cipher []byte }

// ActionsProducerSettings is one retained, operator-selected event producer:
// its exact principal and the Ed25519 public key that signs its events. The
// public key is trusted configuration, never a wire assertion.
type ActionsProducerSettings struct {
	Principal fabric.Principal  `json:"principal"`
	PublicKey ed25519.PublicKey `json:"publicKey"`
}

// ActionsWebhookSettings selects one explicit, generic external webhook ingress.
type ActionsWebhookSettings struct {
	ID             string             `json:"id"`
	Mode           string             `json:"mode"`
	Target         fabric.EndpointRef `json:"target"`
	TargetRevision fabric.Revision    `json:"targetRevision"`
	MaxEventBytes  int                `json:"maxEventBytes"`
	MaxProofBytes  int                `json:"maxProofBytes"`
	Timeout        time.Duration      `json:"timeout"`
	MaxConcurrent  int                `json:"maxConcurrent"`
}

// ActionsCronSettings selects one explicit, generic internal schedule. The
// issuer principal + retained signing key mint the exact signed schedule ticks.
type ActionsCronSettings struct {
	ID              string             `json:"id"`
	Mode            string             `json:"mode"`
	Target          fabric.EndpointRef `json:"target"`
	Revision        fabric.Revision    `json:"revision"`
	Interval        time.Duration      `json:"interval"`
	Timeout         time.Duration      `json:"timeout"`
	IssuerPrincipal fabric.Principal   `json:"issuerPrincipal"`
	IssuerKey       ed25519.PrivateKey `json:"issuerKey"`
}

// ActionsSettings is the private retained operator configuration for the
// installed actions runtime: the producer/definition keys, the trigger
// definitions, the durable queue, and the optional webhook/cron registrations.
type ActionsSettings struct {
	Producers           []ActionsProducerSettings   `json:"producers"`
	DefinitionPublicKey ed25519.PublicKey           `json:"definitionPublicKey"`
	Definitions         []actions.TriggerDefinition `json:"definitions"`
	Queue               durable.Config              `json:"queue"`
	MaxDefinitions      int                         `json:"maxDefinitions"`
	MaxFanout           int                         `json:"maxFanout"`
	MaxProofBytes       int                         `json:"maxProofBytes"`
	MaxEnvelopeBytes    int                         `json:"maxEnvelopeBytes"`
	Webhook             *ActionsWebhookSettings     `json:"webhook,omitempty"`
	Cron                *ActionsCronSettings        `json:"cron,omitempty"`
}

// empty reports whether the retained configuration is all-missing (disabled).
func (s ActionsSettings) empty() bool { return len(s.Producers) == 0 }

func actionsScope(i *localinstallation.Installation) durable.Scope {
	c := i.Configuration()
	// The audience is the installation's domain (the registry store's namespace):
	// it is the endpoint domain the dispatch boundary verifies against and the
	// local boundary's root namespace, so the authenticated caller, the source
	// authority and the retained forward context all share one genuine audience.
	// The StoreID is the opaque store identity, not an authentication audience.
	return durable.Scope{Audience: c.Domain, Domain: c.Domain}
}
func actionsSettingsAAD(i *localinstallation.Installation) []byte {
	c := i.Configuration()
	raw, _ := json.Marshal(struct{ Purpose, Domain, Store string }{"pagnet.installed.actions.v1", c.Domain, c.StoreID})
	return raw
}
func actionsSettingsSeal(i *localinstallation.Installation, c actionsConfiguration) ([]byte, error) {
	raw, e := json.Marshal(c)
	if e != nil || len(raw) > 512<<10 {
		return nil, localDenied()
	}
	defer clear(raw)
	cipher, e := i.Keys.Seal(actionsSettingsAAD(i), raw)
	if e != nil {
		return nil, e
	}
	defer clear(cipher)
	return json.Marshal(actionsConfigurationCipher{cipher})
}
func actionsSettingsOpen(i *localinstallation.Installation, r registry.AuthorityRecord) (actionsConfiguration, error) {
	var c actionsConfiguration
	var box actionsConfigurationCipher
	if r.Key != actionsConfigurationKey || r.Retired || (r.Revision != 1 && r.Revision != 2) || registry.VerifyAuthorityRecord(i.Store.AuthorityIdentity(), r) != nil || fabric.DecodeJSONWithLimits(r.Value, &box, fabric.WireLimits{MaxBytes: 768 << 10, MaxDepth: 4, MaxMembers: 4}) != nil {
		return c, localDenied()
	}
	raw, e := i.Keys.Open(actionsSettingsAAD(i), box.Cipher)
	if e != nil {
		return c, localDenied()
	}
	defer clear(raw)
	if fabric.DecodeJSONWithLimits(raw, &c, fabric.WireLimits{MaxBytes: 512 << 10, MaxDepth: 32, MaxMembers: 16384}) != nil || c.Format != 1 || c.Key != i.Keys.Reference() || !(c.State == "preparing" && r.Revision == 1 || c.State == "ready" && r.Revision == 2) {
		return actionsConfiguration{}, localDenied()
	}
	return c, nil
}
func actionsAuthority(ctx context.Context, i *localinstallation.Installation, owner fabric.ExecutionContext, next func(*registry.AuthorityTx) error) error {
	return i.WithCurrentOperator(ctx, owner, func(current context.Context) error {
		return i.Store.WithNativeAuthority(current, owner, registry.AuthorityScope{MaxOperations: 1, Timeout: 5 * time.Second}, next)
	})
}
func actionsRecord(ctx context.Context, i *localinstallation.Installation) (registry.AuthorityRecord, error) {
	owner, e := i.Operator(ctx)
	if e != nil {
		return registry.AuthorityRecord{}, e
	}
	var r registry.AuthorityRecord
	e = actionsAuthority(ctx, i, owner, func(tx *registry.AuthorityTx) error { var e error; r, e = tx.Get(actionsConfigurationKey); return e })
	return r, e
}
func actionsDirectory(ctx context.Context, i *localinstallation.Installation) (string, error) {
	root, e := i.Store.CurrentAuthorityDirectory(ctx)
	if e != nil {
		return "", e
	}
	return filepath.Join(root, "actions"), nil
}

func validActionsPrincipal(p fabric.Principal) bool {
	return p.Ref != "" && p.Issuer != "" && p.Kind != ""
}

func validateActionsSettings(ctx context.Context, scope durable.Scope, s ActionsSettings) (ActionsSettings, error) {
	if ctx == nil || len(s.Producers) < 1 || len(s.Producers) > 4096 || len(s.DefinitionPublicKey) != ed25519.PublicKeySize || len(s.Definitions) < 1 {
		return s, localDenied()
	}
	seen := make(map[string]bool, len(s.Producers))
	for _, p := range s.Producers {
		if !validActionsPrincipal(p.Principal) || len(p.PublicKey) != ed25519.PublicKeySize || p.Principal.Ref == "" || seen[p.Principal.Ref] {
			return s, localDenied()
		}
		seen[p.Principal.Ref] = true
	}
	queue, err := durable.ValidateConfig(s.Queue)
	if err != nil {
		return s, err
	}
	s.Queue = queue
	if s.MaxDefinitions < 1 || s.MaxDefinitions > 1024 || len(s.Definitions) > s.MaxDefinitions || s.MaxFanout < 1 || s.MaxFanout > 128 || s.MaxProofBytes < 1 || s.MaxProofBytes > 65536 || s.MaxEnvelopeBytes < 1024 || s.MaxEnvelopeBytes > 65536 {
		return s, localDenied()
	}
	defSeen := make(map[string]bool, len(s.Definitions))
	for _, d := range s.Definitions {
		if d.ID == "" || defSeen[d.ID] {
			return s, localDenied()
		}
		defSeen[d.ID] = true
		// The producer (event source) must be a retained producer.
		if !seen[d.Source] {
			return s, localDenied()
		}
	}
	if s.Webhook != nil {
		if s.Webhook.ID == "" || (s.Webhook.Mode != "trigger" && s.Webhook.Mode != "emit") || (s.Webhook.Mode == "emit" && (s.Webhook.Target.String() == "" || s.Webhook.TargetRevision == "")) || s.Webhook.MaxEventBytes < 1 || s.Webhook.MaxEventBytes > 1<<20 || s.Webhook.MaxProofBytes < 1 || s.Webhook.MaxProofBytes > 65536 || s.Webhook.Timeout < time.Millisecond || s.Webhook.Timeout > time.Minute || s.Webhook.MaxConcurrent < 1 || s.Webhook.MaxConcurrent > 4096 {
			return s, localDenied()
		}
	}
	if s.Cron != nil {
		if s.Cron.ID == "" || (s.Cron.Mode != "trigger" && s.Cron.Mode != "emit") || (s.Cron.Mode == "emit" && (s.Cron.Target.String() == "" || s.Cron.Revision == "")) || s.Cron.Interval < time.Millisecond || s.Cron.Interval > 24*time.Hour || s.Cron.Timeout < time.Millisecond || s.Cron.Timeout > time.Minute || !validActionsPrincipal(s.Cron.IssuerPrincipal) || len(s.Cron.IssuerKey) != ed25519.PrivateKeySize {
			return s, localDenied()
		}
		// The cron issuer must be a retained producer so its ticks verify.
		if !seen[s.Cron.IssuerPrincipal.Ref] {
			return s, localDenied()
		}
	}
	return s, nil
}

// DefaultActionsSettings selects finite durable queue limits for one retained
// producer and a single trigger. It is explicit configuration, not discovery.
func DefaultActionsSettings(producer ActionsProducerSettings, definitions []actions.TriggerDefinition) ActionsSettings {
	return ActionsSettings{
		Producers:           []ActionsProducerSettings{producer},
		DefinitionPublicKey: nil,
		Definitions:         definitions,
		Queue:               durable.DefaultConfig([]durable.Subscription{{ID: "actions.dispatch", Types: []string{"dev.pagnet.actions.queued"}}}),
		MaxDefinitions:      128,
		MaxFanout:           32,
		MaxProofBytes:       65536,
		MaxEnvelopeBytes:    65536,
	}
}

// InitializeConfiguredActions is an explicit owner operation, never startup
// repair. A FULL preparing pin precedes the actions store creation; a separate
// FULL ready receipt follows verified store setup. Interrupted setup may be
// explicitly retried with exactly the same configuration, original identity
// and key.
func InitializeConfiguredActions(ctx context.Context, i *localinstallation.Installation, s ActionsSettings) error {
	if ctx == nil || i == nil || i.Store == nil || i.Keys == nil {
		return localDenied()
	}
	scope := actionsScope(i)
	var err error
	s, err = validateActionsSettings(ctx, scope, s)
	if err != nil {
		return err
	}
	want, e := json.Marshal(s)
	if e != nil || len(want) > 512<<10 {
		return localDenied()
	}
	dir, e := actionsDirectory(ctx, i)
	if e != nil {
		return e
	}
	r, e := actionsRecord(ctx, i)
	if authorityMissing(e) {
		// A directory without its signed root purpose is partial state; explicit
		// setup does not silently attest arbitrary or previously removed state.
		if _, statErr := os.Lstat(dir); !os.IsNotExist(statErr) {
			return localDenied()
		}
		sealed, e := actionsSettingsSeal(i, actionsConfiguration{1, "preparing", i.Keys.Reference(), s})
		if e != nil {
			return e
		}
		owner, e := i.Operator(ctx)
		if e != nil {
			return e
		}
		e = actionsAuthority(ctx, i, owner, func(tx *registry.AuthorityTx) error {
			var e error
			r, e = tx.CAS(actionsConfigurationKey, 0, sealed, false)
			return e
		})
		if e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	c, e := actionsSettingsOpen(i, r)
	if e != nil {
		return e
	}
	actual, e := json.Marshal(c.Settings)
	if e != nil || !bytes.Equal(actual, want) {
		return fabric.NewError(fabric.CodeInvalidInput, "Actions delivery already has a different retained configuration")
	}
	// Verify the retained configuration can actually open the actions store with
	// a genuine authority composition before marking it ready. This never
	// bootstraps missing identity or creates state a retry cannot reproduce.
	store, e := openActionsStoreOnly(ctx, dir, scope, c.Settings, i.Keys, true)
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
	sealed, e := actionsSettingsSeal(i, c)
	if e != nil {
		return e
	}
	owner, e := i.Operator(ctx)
	if e != nil {
		return e
	}
	return actionsAuthority(ctx, i, owner, func(tx *registry.AuthorityTx) error {
		_, e := tx.CAS(actionsConfigurationKey, r.Revision, sealed, false)
		return e
	})
}

// OpenInstalledActions loads only the current signed ready configuration and
// original encrypted state. All-missing is disabled. Partial state never
// regenerates keys, changes trust boundaries or creates a store implicitly.
func OpenInstalledActionsConfig(ctx context.Context, i *localinstallation.Installation) (ActionsSettings, error) {
	if ctx == nil || i == nil || i.Store == nil || i.Keys == nil {
		return ActionsSettings{}, localDenied()
	}
	dir, e := actionsDirectory(ctx, i)
	if e != nil {
		return ActionsSettings{}, e
	}
	r, e := actionsRecord(ctx, i)
	if authorityMissing(e) {
		if _, statErr := os.Lstat(dir); os.IsNotExist(statErr) {
			return ActionsSettings{}, nil
		}
		return ActionsSettings{}, localDenied()
	}
	if e != nil {
		return ActionsSettings{}, e
	}
	c, e := actionsSettingsOpen(i, r)
	if e != nil {
		return ActionsSettings{}, e
	}
	if c.State != "ready" {
		return ActionsSettings{}, fabric.NewError(fabric.CodeTargetUnavailable, "Finish the interrupted explicit actions setup")
	}
	scope := actionsScope(i)
	c.Settings, e = validateActionsSettings(ctx, scope, c.Settings)
	return c.Settings, e
}
