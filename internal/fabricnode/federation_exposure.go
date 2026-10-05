package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync/atomic"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// FederationExposure explicitly publishes an exact local target/binding view
// to one owner-certified foreign domain. It is infrastructure exposure, NOT
// principal permissions or business policy. Destination interceptors still run.
type FederationExposure struct {
	RemoteDomain string             `json:"remoteDomain"`
	Target       fabric.EndpointRef `json:"target"`
	Revision     fabric.Revision    `json:"revision"`
	BindingID    string             `json:"bindingId"`
}
type FederationExposureConfiguration struct {
	Exposures []FederationExposure `json:"exposures"`
}
type federationExposureCipher struct {
	Version    string               `json:"version"`
	Key        durable.KeyReference `json:"key"`
	Ciphertext []byte               `json:"ciphertext"`
}
type FederationExposures struct {
	store     *registry.Store
	root      registry.AuthorityIdentity
	owner     func(context.Context) (fabric.ExecutionContext, error)
	operator  LocalOperator
	protector durable.DataProtector
	snapshot  atomic.Pointer[exposureSnapshot]
}

type exposureSnapshot struct {
	revision uint64
	digest   [32]byte
	entries  map[FederationExposure]struct{}
	targets  map[exposureTarget]struct{}
}

type exposureTarget struct {
	Remote   string
	Target   fabric.EndpointRef
	Revision fabric.Revision
}

const exposureVersion = "pagnet.fabric.federation.exposure.v1"

func exposureKey() registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityFederationExposure, ID: "exposure-v1"}
}
func NewFederationExposures(ctx context.Context, s *registry.Store, owner func(context.Context) (fabric.ExecutionContext, error), operator LocalOperator, p durable.DataProtector) (*FederationExposures, error) {
	if ctx == nil || s == nil || owner == nil || operator == nil || p == nil || p.Reference().ID == "" || p.Reference().Version == "" {
		return nil, localDenied()
	}
	root, e := s.CurrentAuthorityIdentity(ctx)
	if e != nil {
		return nil, e
	}
	v := &FederationExposures{store: s, root: root, owner: owner, operator: operator, protector: p}
	c, e := owner(ctx)
	if e != nil {
		return nil, e
	}
	if e = v.current(ctx, c, func(context.Context) error { return nil }); e != nil {
		return nil, e
	}
	return v, nil
}
func (v *FederationExposures) aad() []byte {
	raw, _ := json.Marshal(struct {
		Purpose, Domain, Store string
		Key                    durable.KeyReference
	}{exposureVersion, v.root.Namespace, v.root.StoreID, v.protector.Reference()})
	return raw
}
func (v *FederationExposures) validate(c FederationExposureConfiguration) error {
	if len(c.Exposures) > 64 {
		return fabric.NewError(fabric.CodeInvalidInput, "Federation exposure count exceeds bound")
	}
	seen := map[string]bool{}
	for _, x := range c.Exposures {
		if x.RemoteDomain == "" || len(x.RemoteDomain) > 128 || x.RemoteDomain == v.root.Namespace || x.Target.Domain() != v.root.Namespace || x.Revision == "" || len(x.Revision) > 256 || x.BindingID == "" || len(x.BindingID) > 256 {
			return localDenied()
		}
		raw, _ := json.Marshal(x)
		key := string(raw)
		if seen[key] {
			return localDenied()
		}
		seen[key] = true
	}
	raw, e := json.Marshal(c)
	if e != nil || len(raw) > 48<<10 {
		return fabric.NewError(fabric.CodeInvalidInput, "Federation exposure configuration exceeds bound")
	}
	return nil
}
func (v *FederationExposures) current(ctx context.Context, c fabric.ExecutionContext, next func(context.Context) error) error {
	if v == nil || ctx == nil || c.VerifyAuthenticated(v.root.Namespace) != nil || c.PrincipalView() != v.root.Owner {
		return localDenied()
	}
	root, e := v.store.CurrentAuthorityIdentity(ctx)
	if e != nil || root.Namespace != v.root.Namespace || root.StoreID != v.root.StoreID || root.Owner != v.root.Owner || root.KeyRevision != v.root.KeyRevision || !bytes.Equal(root.PublicKey, v.root.PublicKey) {
		return localDenied()
	}
	return guardedBoundary(ctx, func(ctx context.Context, n func(context.Context) error) error {
		return v.operator.WithCurrentOperator(ctx, c, n)
	}, next)
}

// Put explicitly installs/updates the encrypted infrastructure projection using
// actual signed FULL CAS. Missing Open never initializes or replaces it.
func (v *FederationExposures) Put(ctx context.Context, expected uint64, c FederationExposureConfiguration) (uint64, error) {
	if v == nil || v.validate(c) != nil {
		return 0, localDenied()
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return 0, e
	}
	defer clear(raw)
	sealed, e := v.protector.Seal(v.aad(), raw)
	if e != nil {
		return 0, e
	}
	defer clear(sealed)
	value, e := json.Marshal(federationExposureCipher{exposureVersion, v.protector.Reference(), sealed})
	if e != nil || len(value) > 64<<10 {
		return 0, localDenied()
	}
	owner, e := v.owner(ctx)
	if e != nil {
		return 0, e
	}
	var revision uint64
	var committed registry.AuthorityRecord
	e = v.current(ctx, owner, func(ctx context.Context) error {
		return v.store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
			if row, err := tx.Get(exposureKey()); err == nil && row.PreviousRevision == expected {
				current, _, err := v.loadTx(tx)
				if err != nil {
					return err
				}
				canonical, err := json.Marshal(current)
				if err != nil {
					return err
				}
				if bytes.Equal(canonical, raw) {
					revision = row.Revision
					committed = row
					return nil
				}
			}
			row, e := tx.CAS(exposureKey(), expected, value, false)
			revision = row.Revision
			committed = row
			return e
		})
	})
	if e == nil {
		v.publishSnapshot(c, committed)
	}
	return revision, e
}
func (v *FederationExposures) loadTx(tx *registry.AuthorityTx) (FederationExposureConfiguration, uint64, error) {
	var c FederationExposureConfiguration
	row, e := tx.Get(exposureKey())
	if e != nil {
		return c, 0, e
	}
	if registry.VerifyAuthorityRecord(v.root, row) != nil || row.Retired {
		return c, 0, localDenied()
	}
	var sealed federationExposureCipher
	if fabric.DecodeJSONWithLimits(row.Value, &sealed, fabric.WireLimits{MaxBytes: 64 << 10, MaxDepth: 8, MaxMembers: 512}) != nil || sealed.Version != exposureVersion || sealed.Key != v.protector.Reference() {
		return c, 0, localDenied()
	}
	raw, e := v.protector.Open(v.aad(), sealed.Ciphertext)
	if e != nil {
		return c, 0, e
	}
	defer clear(raw)
	if fabric.DecodeJSONWithLimits(raw, &c, fabric.WireLimits{MaxBytes: 48 << 10, MaxDepth: 8, MaxMembers: 512}) != nil || v.validate(c) != nil {
		return c, 0, localDenied()
	}
	return c, row.Revision, nil
}

// CheckTx is bounded local crypto/readback in the SAME destination admission
// transaction. A matching exposure never bypasses target/current-binding or
// configured extension checks at dispatch. No provider or nested Store IO.
func (v *FederationExposures) CheckTx(tx *registry.AuthorityTx, remote string, target fabric.EndpointRef, revision fabric.Revision, binding string) error {
	if v == nil || tx == nil {
		return localDenied()
	}
	snapshot := v.snapshot.Load()
	if snapshot == nil {
		return localDenied()
	}
	row, e := tx.Get(exposureKey())
	if e != nil {
		return e
	}
	if row.Retired || row.Revision != snapshot.revision || registry.VerifyAuthorityRecord(v.root, row) != nil || sha256.Sum256(row.Value) != snapshot.digest {
		return fabric.NewError(fabric.CodeTargetUnavailable, "Federation exposure snapshot requires explicit reload")
	}
	if _, ok := snapshot.entries[FederationExposure{remote, target, revision, binding}]; ok {
		return nil
	}

	return fabric.NewError(fabric.CodeUnauthenticated, "Selected target is not published to this federation link")
}

// Reload compiles indexed immutable exposure membership only on explicit
// configuration change/restart. Missing/corrupt retained configuration denies;
// it never bootstraps or substitutes a newly generated configuration.
func (v *FederationExposures) Reload(ctx context.Context) error {
	owner, e := v.owner(ctx)
	if e != nil {
		return e
	}
	var c FederationExposureConfiguration
	var record registry.AuthorityRecord
	e = v.current(ctx, owner, func(ctx context.Context) error {
		return v.store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
			var e error
			c, _, e = v.loadTx(tx)
			if e != nil {
				return e
			}
			record, e = tx.Get(exposureKey())
			return e
		})
	})
	if e == nil {
		v.publishSnapshot(c, record)
	}
	return e
}
func (v *FederationExposures) publishSnapshot(c FederationExposureConfiguration, row registry.AuthorityRecord) {
	entries := make(map[FederationExposure]struct{}, len(c.Exposures))
	targets := make(map[exposureTarget]struct{}, len(c.Exposures))
	for _, x := range c.Exposures {
		entries[x] = struct{}{}
		targets[exposureTarget{x.RemoteDomain, x.Target, x.Revision}] = struct{}{}
	}
	snapshot := &exposureSnapshot{revision: row.Revision, digest: sha256.Sum256(row.Value), entries: entries, targets: targets}
	for {
		old := v.snapshot.Load()
		if old != nil && old.revision > snapshot.revision {
			return
		}
		if v.snapshot.CompareAndSwap(old, snapshot) {
			return
		}
	}
}

// CheckTargetTx is pre-selection admission integrity only. Exact binding
// selection must still run CheckTx before downstream paid acceptance.
func (v *FederationExposures) CheckTargetTx(tx *registry.AuthorityTx, remote string, target fabric.EndpointRef, revision fabric.Revision) error {
	if v == nil || tx == nil {
		return localDenied()
	}
	s := v.snapshot.Load()
	if s == nil {
		return localDenied()
	}
	row, e := tx.Get(exposureKey())
	if e != nil {
		return e
	}
	if row.Retired || row.Revision != s.revision || registry.VerifyAuthorityRecord(v.root, row) != nil || sha256.Sum256(row.Value) != s.digest {
		return fabric.NewError(fabric.CodeTargetUnavailable, "Federation exposure snapshot requires explicit reload")
	}
	if _, ok := s.targets[exposureTarget{remote, target, revision}]; !ok {
		return localDenied()
	}
	return nil
}
