package fabricagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// HostedProfile pins operator-selected original CLOUD execution state. It is
// not a local.native launch profile and contains no guessed session/PID or key.
// Public descriptions belong to the descriptor, private instructions never do.
type HostedProfile struct {
	DefinitionID    string              `json:"definitionId"`
	PrincipalID     string              `json:"principalId"`
	NetworkID       string              `json:"networkId"`
	Scope           sessionworker.Scope `json:"scope"`
	OwnershipID     string              `json:"ownershipId"`
	NativeProfile   [32]byte            `json:"nativeProfile"`
	WorkerDirectory string              `json:"workerDirectory"`
}

// OriginalHostedProbe must verify the genuine original registry/bootstrap and
// authenticated worker ownership. An instance database row or SID is not proof.
// The operation is inspection only: it cannot wake/start or submit a turn.
type OriginalHostedProbe func(context.Context, HostedProfile) error
type HostedOwner func(context.Context) (fabric.ExecutionContext, error)
type HostedProfiles struct {
	store     *registry.Store
	owner     HostedOwner
	root      registry.AuthorityIdentity
	protector durable.DataProtector
	probe     OriginalHostedProbe
}
type hostedProfileBox struct {
	Cipher []byte `json:"cipher"`
}

func hostedProfileError() error {
	return fabric.NewError(fabric.CodeStaleReference, "Original hosted agent binding is unavailable or changed")
}
func (p HostedProfile) Validate() error {
	if _, e := nativeauthority.NewCloudScope(p.Scope); e != nil {
		return hostedProfileError()
	}
	for _, id := range []string{p.DefinitionID, p.PrincipalID, p.NetworkID, p.OwnershipID, p.Scope.TenantID, p.Scope.HostID, p.Scope.InstanceID} {
		if _, e := domain.ParseID(id); e != nil {
			return hostedProfileError()
		}
	}
	if p.NativeProfile == ([32]byte{}) || !filepath.IsAbs(p.WorkerDirectory) || filepath.Clean(p.WorkerDirectory) != p.WorkerDirectory || len(p.WorkerDirectory) > 4096 {
		return hostedProfileError()
	}
	return nil
}
func NewHostedProfiles(ctx context.Context, store *registry.Store, owner HostedOwner, protector durable.DataProtector, probe OriginalHostedProbe) (*HostedProfiles, error) {
	if ctx == nil || store == nil || owner == nil || protector == nil || probe == nil {
		return nil, hostedProfileError()
	}
	root, e := store.CurrentAuthorityIdentity(ctx)
	if e != nil {
		return nil, e
	}
	caller, e := owner(ctx)
	if e != nil || caller.VerifyAuthenticated(root.Namespace) != nil || caller.PrincipalView() != root.Owner {
		return nil, hostedProfileError()
	}
	return &HostedProfiles{store, owner, root, protector, probe}, nil
}
func hostedProfileKey(scope registry.DescriptorBatchScope) registry.AuthorityKey {
	raw, _ := json.Marshal(scope)
	h := sha256.Sum256(raw)
	return registry.AuthorityKey{Kind: registry.AuthorityNativeCheckpoint, ID: "hosted/profile/" + hex.EncodeToString(h[:])}
}
func (s *HostedProfiles) aad(scope registry.DescriptorBatchScope) []byte {
	raw, _ := json.Marshal(struct{ Purpose, Domain, Store, Key string }{"pagnet.original-hosted.profile.v1", s.root.Namespace, s.root.StoreID, hostedProfileKey(scope).ID})
	return raw
}
func (s *HostedProfiles) with(ctx context.Context, scope registry.DescriptorBatchScope, next func(*registry.AuthorityTx) error) error {
	if s == nil || ctx == nil || scope.Endpoint.Domain() != s.root.Namespace || scope.ExpectedEndpointRevision == "" || scope.BindingID == "" || scope.ExpectedProjectionRevision != 0 {
		return hostedProfileError()
	}
	owner, e := s.owner(ctx)
	if e != nil {
		return e
	}
	return s.store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{Endpoint: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, BindingID: scope.BindingID, MaxOperations: 8, Timeout: 5 * time.Second}, next)
}
func (s *HostedProfiles) decode(tx *registry.AuthorityTx, scope registry.DescriptorBatchScope) (HostedProfile, registry.AuthorityRecord, error) {
	row, e := tx.Get(hostedProfileKey(scope))
	if e != nil {
		return HostedProfile{}, row, e
	}
	if row.Retired || registry.VerifyAuthorityRecord(s.root, row) != nil {
		return HostedProfile{}, row, hostedProfileError()
	}
	var box hostedProfileBox
	if fabric.DecodeJSONWithLimits(row.Value, &box, fabric.WireLimits{MaxBytes: 16 << 10, MaxDepth: 4, MaxMembers: 8}) != nil {
		return HostedProfile{}, row, hostedProfileError()
	}
	raw, e := s.protector.Open(s.aad(scope), box.Cipher)
	if e != nil {
		return HostedProfile{}, row, hostedProfileError()
	}
	defer clear(raw)
	var profile HostedProfile
	if fabric.DecodeJSONWithLimits(raw, &profile, fabric.WireLimits{MaxBytes: 8 << 10, MaxDepth: 8, MaxMembers: 64}) != nil || profile.Validate() != nil {
		return HostedProfile{}, row, hostedProfileError()
	}
	return profile, row, nil
}

// Install requires genuine current kernel owner administration and authentic
// original worker inspection before FULL root CAS. Exact retries are immutable;
// reconfiguration requires an explicit different published descriptor revision.
func (s *HostedProfiles) Install(ctx context.Context, access *fabricauth.OwnerAdministration, scope registry.DescriptorBatchScope, p HostedProfile) (uint64, error) {
	if s == nil || ctx == nil || access == nil || access.VerifyCurrent(ctx) != nil || access.PrincipalView() != s.root.Owner || p.Validate() != nil {
		return 0, hostedProfileError()
	}
	if e := s.probe(ctx, p); e != nil {
		return 0, e
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > 8<<10 {
		return 0, hostedProfileError()
	}
	defer clear(raw)
	cipher, e := s.protector.Seal(s.aad(scope), raw)
	if e != nil {
		return 0, e
	}
	defer clear(cipher)
	box, e := json.Marshal(hostedProfileBox{cipher})
	if e != nil || len(box) > 16<<10 {
		return 0, hostedProfileError()
	}
	var revision uint64
	if access.VerifyCurrent(ctx) != nil {
		return 0, hostedProfileError()
	}
	e = s.with(ctx, scope, func(tx *registry.AuthorityTx) error {
		// The expensive kernel/root check belongs outside Store SQL locks.
		// Inside the transaction only the opaque lifetime/root predicate is used.
		if !access.MatchesAuthority(s.root) {
			return hostedProfileError()
		}
		old, row, readErr := s.decode(tx, scope)
		if readErr == nil {
			encoded, _ := json.Marshal(old)
			defer clear(encoded)
			if !bytes.Equal(encoded, raw) {
				return hostedProfileError()
			}
			revision = row.Revision
			return nil
		}
		var f *fabric.Error
		if !errors.As(readErr, &f) || f.Code != fabric.CodeNotFound {
			return readErr
		}
		row, e := tx.CAS(hostedProfileKey(scope), 0, box, false)
		if e != nil {
			return e
		}
		revision = row.Revision
		return nil
	})
	return revision, e
}
func (s *HostedProfiles) Get(ctx context.Context, scope registry.DescriptorBatchScope) (HostedProfile, [32]byte, error) {
	var profile HostedProfile
	var fingerprint [32]byte
	e := s.with(ctx, scope, func(tx *registry.AuthorityTx) error {
		var row registry.AuthorityRecord
		var e error
		profile, row, e = s.decode(tx, scope)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(struct {
			Scope    registry.DescriptorBatchScope
			Profile  HostedProfile
			Revision uint64
		}{scope, profile, row.Revision})
		defer clear(raw)
		fingerprint = sha256.Sum256(raw)
		return nil
	})
	return profile, fingerprint, e
}

// CallerAuthority loads the explicitly signed original-worker association and
// checks its genuine current private worker before creating a private witness.
// This is not authentication by description, a SID, or a cloud database row;
// the actual kernel socket and activation are additionally bound by BindHosted.
// Every destination transaction calls witness.VerifyTx again, so a retired or
// replaced association cannot retain authority through an earlier inspection.
func (s *HostedProfiles) CallerAuthority(ctx context.Context, scope registry.DescriptorBatchScope, principal fabric.Principal) (*fabricauth.HostedCallerAuthority, error) {
	var profile HostedProfile
	var record registry.AuthorityRecord
	err := s.with(ctx, scope, func(tx *registry.AuthorityTx) error {
		var err error
		profile, record, err = s.decode(tx, scope)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = s.probe(ctx, profile); err != nil {
		return nil, err
	}
	return fabricauth.NewHostedCallerAuthority(s.root, principal, scope, record)
}
