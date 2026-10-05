package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/extension"
	domain "github.com/pagnet-code/pagnet/fabric/registry"
)

type directory struct {
	Format                                                           int                      `json:"format"`
	Root                                                             domain.AuthorityIdentity `json:"root"`
	Key                                                              durable.KeyReference     `json:"key"`
	MaxExtensions, MaxInterceptors, MaxEntryBytes, MaxDirectoryBytes int
	Entries                                                          []Reference `json:"entries"`
}
type sealed struct {
	Format int                  `json:"format"`
	Key    durable.KeyReference `json:"key"`
	Cipher []byte               `json:"cipher"`
}
type Store struct {
	ordered             []Reference
	mu                  sync.Mutex
	config              Config
	identity            domain.AuthorityIdentity
	key                 durable.KeyReference
	generation          uint64
	refs                map[string]Reference
	entries             map[string]Installation
	plan                *extension.Plan
	quarantined, closed bool
	snapshot            atomic.Pointer[Snapshot]
	transaction         func(context.Context, fabric.ExecutionContext, domain.AuthorityScope, func(*domain.AuthorityTx) error) error
}

const directoryID = "pagnet.extensions.directory"

func failure() error {
	return fabric.NewError(fabric.CodeProtocolError, "Retained extension configuration unavailable")
}
func invalid() error {
	return fabric.NewError(fabric.CodeInvalidInput, "Invalid extension configuration")
}
func conflict() error {
	return fabric.NewError(fabric.CodeInvalidMutation, "Extension configuration revision conflict")
}
func text(s string, max int, empty bool) bool {
	return (empty || s != "") && len(s) <= max && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func key(id string) domain.AuthorityKey {
	return domain.AuthorityKey{Kind: domain.AuthorityExtensionConfiguration, ID: id}
}
func scope(c Config) domain.AuthorityScope {
	return domain.AuthorityScope{MaxOperations: c.MaxExtensions + 5, Timeout: 5 * time.Second}
}
func Bootstrap(ctx context.Context, owner fabric.ExecutionContext, c Config) (*Store, error) {
	return open(ctx, owner, c, true)
}
func Open(ctx context.Context, owner fabric.ExecutionContext, c Config) (*Store, error) {
	return open(ctx, owner, c, false)
}
func open(ctx context.Context, owner fabric.ExecutionContext, c Config, create bool) (*Store, error) {
	if ctx == nil || c.Root == nil || c.Protector == nil || c.OwnerValidator == nil || c.MaxExtensions < 1 || c.MaxExtensions > 128 || c.MaxInterceptors < 1 || c.MaxInterceptors > 4096 || c.MaxEntryBytes < 1024 || c.MaxEntryBytes > 32768 || c.MaxDirectoryBytes < 1024 || c.MaxDirectoryBytes > 32768 {
		return nil, invalid()
	}
	identity, e := c.Root.CurrentAuthorityIdentity(ctx)
	if e != nil {
		return nil, failure()
	}
	ref := c.Protector.Reference()
	if !text(ref.ID, 256, false) || !text(ref.Version, 128, false) {
		return nil, invalid()
	}
	s := &Store{config: c, identity: identity, key: ref, refs: map[string]Reference{}, entries: map[string]Installation{}, transaction: c.Root.WithNativeAuthority}
	if e = s.authorize(ctx, owner); e != nil {
		return nil, e
	}
	if create {
		plan, e := extension.Compile(nil, c.MaxInterceptors)
		if e != nil {
			return nil, e
		}
		value, e := s.seal(directoryID, s.directory(nil), c.MaxDirectoryBytes)
		if e != nil {
			return nil, e
		}
		e = c.Root.WithNativeAuthority(ctx, owner, scope(c), func(tx *domain.AuthorityTx) error {
			if _, e := tx.Get(key(directoryID)); e == nil {
				return conflict()
			} else {
				var fe *fabric.Error
				if !errors.As(e, &fe) || fe.Code != fabric.CodeNotFound {
					return e
				}
			}
			_, e := tx.CAS(key(directoryID), 0, value, false)
			return e
		})
		if e != nil {
			return nil, e
		}
		s.plan = plan
	}
	if e = s.reload(ctx, owner); e != nil {
		return nil, e
	}
	return s, nil
}
func (s *Store) authorize(ctx context.Context, owner fabric.ExecutionContext) error {
	if ctx == nil || ctx.Err() != nil || owner.VerifyAuthenticated(s.identity.Namespace) != nil || owner.PrincipalView() != s.identity.Owner {
		return fabric.NewError(fabric.CodeUnauthenticated, "Live registered extension owner required")
	}
	current, e := s.config.Root.CurrentAuthorityIdentity(ctx)
	if e != nil || !sameRoot(current, s.identity) || s.config.Protector.Reference() != s.key {
		return failure()
	}
	if s.config.OwnerValidator(ctx, owner, current) != nil {
		return fabric.NewError(fabric.CodeUnauthenticated, "Live registered extension owner required")
	}
	return nil
}
func sameRoot(a, b domain.AuthorityIdentity) bool {
	return a.Namespace == b.Namespace && a.StoreID == b.StoreID && a.Owner == b.Owner && a.KeyRevision == b.KeyRevision && bytes.Equal(a.PublicKey, b.PublicKey)
}
func (s *Store) aad(id string) []byte {
	raw, _ := json.Marshal(struct {
		Format                 int
		Namespace, StoreID, ID string
		Key                    durable.KeyReference
	}{1, s.identity.Namespace, s.identity.StoreID, id, s.key})
	return raw
}
func (s *Store) seal(id string, value any, max int) ([]byte, error) {
	raw, e := json.Marshal(value)
	if e != nil || len(raw) > max {
		return nil, invalid()
	}
	cipher, e := s.config.Protector.Seal(s.aad(id), raw)
	if e != nil || len(cipher) > max+4096 {
		return nil, failure()
	}
	result, e := json.Marshal(sealed{1, s.key, cipher})
	if e != nil || len(result) > 65536 {
		return nil, invalid()
	}
	return result, nil
}
func (s *Store) decode(id string, raw []byte, out any, max int) error {
	var record sealed
	if fabric.DecodeJSONWithLimits(raw, &record, fabric.WireLimits{MaxBytes: 65536, MaxDepth: 64, MaxMembers: 16384}) != nil || record.Format != 1 || record.Key != s.key || len(record.Cipher) > max+4096 {
		return failure()
	}
	plain, e := s.config.Protector.Open(s.aad(id), record.Cipher)
	if e != nil || len(plain) > max || fabric.DecodeJSONWithLimits(plain, out, fabric.WireLimits{MaxBytes: max, MaxDepth: 64, MaxMembers: 16384}) != nil {
		return failure()
	}
	return nil
}
func (s *Store) directory(refs []Reference) directory {
	return directory{1, s.identity, s.key, s.config.MaxExtensions, s.config.MaxInterceptors, s.config.MaxEntryBytes, s.config.MaxDirectoryBytes, refs}
}
func (s *Store) validateInstallation(input Installation) (Installation, error) {
	raw, e := json.Marshal(input)
	if e != nil || len(raw) > s.config.MaxEntryBytes {
		return Installation{}, invalid()
	}
	var owned Installation
	if fabric.DecodeJSONWithLimits(raw, &owned, fabric.WireLimits{MaxBytes: s.config.MaxEntryBytes, MaxDepth: 64, MaxMembers: 8192}) != nil || len(owned.Bindings) > 256 {
		return Installation{}, invalid()
	}
	bindings := map[string]bool{}
	for _, b := range owned.Bindings {
		decoded, e := hex.DecodeString(b.ProfileDigest)
		if !text(b.ID, 256, false) || !fabric.ValidNamespacedName(b.Protocol) || !text(b.Selector, 4096, false) || !text(b.CredentialPrincipalRef, 256, true) || e != nil || len(decoded) != 32 || b.ProfileDigest != hex.EncodeToString(decoded) || bindings[b.ID] {
			return Installation{}, invalid()
		}
		bindings[b.ID] = true
	}
	for _, r := range owned.Manifest.Interceptors {
		if !bindings[r.Binding] {
			return Installation{}, invalid()
		}
	}
	for _, r := range owned.Manifest.EventSubscriptions {
		if !bindings[r.Binding] {
			return Installation{}, invalid()
		}
	}
	for _, r := range owned.Manifest.Triggers {
		if !bindings[r.Binding] {
			return Installation{}, invalid()
		}
	}
	// Binding order is not execution order; commit a stable owned configuration.
	sort.Slice(owned.Bindings, func(i, j int) bool { return owned.Bindings[i].ID < owned.Bindings[j].ID })
	return owned, nil
}
func (s *Store) compile(entries map[string]Installation, refs map[string]Reference, generation uint64) (*extension.Plan, []byte, error) {
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	manifests := make([]extension.ExtensionManifest, 0, len(ids))
	for _, id := range ids {
		manifests = append(manifests, entries[id].Manifest)
	}
	installed := make([]struct {
		Reference    Reference
		Installation Installation
	}, 0, len(ids))
	for _, id := range ids {
		installed = append(installed, struct {
			Reference    Reference
			Installation Installation
		}{refs[id], entries[id]})
	}
	raw, _ := json.Marshal(struct {
		Format             int
		Namespace, StoreID string
		Generation         uint64
		Installations      any
	}{1, s.identity.Namespace, s.identity.StoreID, generation, installed})
	plan, err := extension.CompileConfigured(manifests, s.config.MaxInterceptors, hash(raw))
	return plan, raw, err
}
func (s *Store) reload(ctx context.Context, owner fabric.ExecutionContext) error {
	if e := s.authorize(ctx, owner); e != nil {
		return e
	}
	refs := map[string]Reference{}
	entries := map[string]Installation{}
	var generation uint64
	var purpose domain.AuthorityRecord
	var directoryDigest [32]byte
	e := s.config.Root.WithNativeAuthority(ctx, owner, scope(s.config), func(tx *domain.AuthorityTx) error {
		saved, e := tx.Get(key(directoryID))
		if e != nil || saved.Retired {
			return failure()
		}
		var d directory
		if e = s.decode(directoryID, saved.Value, &d, s.config.MaxDirectoryBytes); e != nil {
			return e
		}
		if d.Format != 1 || !sameRoot(d.Root, s.identity) || d.Key != s.key || d.MaxExtensions != s.config.MaxExtensions || d.MaxInterceptors != s.config.MaxInterceptors || d.MaxEntryBytes != s.config.MaxEntryBytes || d.MaxDirectoryBytes != s.config.MaxDirectoryBytes || len(d.Entries) > s.config.MaxExtensions {
			return failure()
		}
		previous := ""
		for _, ref := range d.Entries {
			if ref.ID <= previous || ref.Revision == 0 || !text(ref.PhysicalID, 256, false) || len(ref.Digest) != 64 {
				return failure()
			}
			previous = ref.ID
			record, e := tx.Get(key(ref.PhysicalID))
			if e != nil || record.Retired || record.Revision != ref.Revision {
				return failure()
			}
			var installed Installation
			if e = s.decode(ref.PhysicalID, record.Value, &installed, s.config.MaxEntryBytes); e != nil {
				return e
			}
			installed, e = s.validateInstallation(installed)
			if e != nil || installed.Manifest.ID != ref.ID {
				return failure()
			}
			raw, _ := json.Marshal(installed)
			if hash(raw) != ref.Digest {
				return failure()
			}
			refs[ref.ID] = ref
			entries[ref.ID] = installed
		}
		generation = saved.Revision
		directoryDigest = sha256.Sum256(saved.Value)
		purpose, e = tx.ExtensionPurposeGeneration()
		return e
	})
	if e != nil {
		return e
	}
	plan, evidence, e := s.compile(entries, refs, generation)
	if e != nil {
		return e
	}
	s.refs = refs
	s.ordered = sortedReferences(refs)
	s.entries = entries
	s.generation = generation
	s.plan = plan
	s.quarantined = false
	s.snapshot.Store(&Snapshot{Generation: s.generation, Plan: s.plan, evidence: evidence, purpose: purpose, directoryDigest: directoryDigest})
	return nil
}
func (s *Store) Reload(ctx context.Context, owner fabric.ExecutionContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return failure()
	}
	s.quarantined = true
	s.snapshot.Store(nil)
	return s.reload(ctx, owner)
}
func (s *Store) Snapshot() (Snapshot, error) {
	snapshot := s.snapshot.Load()
	if snapshot == nil {
		return Snapshot{}, failure()
	}
	return Snapshot{Generation: snapshot.Generation, Plan: snapshot.Plan}, nil
}

func (s *Store) ConfiguredSnapshot() (ConfiguredSnapshot, error) {
	snapshot := s.snapshot.Load()
	if snapshot == nil {
		return ConfiguredSnapshot{}, failure()
	}
	return ConfiguredSnapshot{Generation: snapshot.Generation, Plan: snapshot.Plan, Evidence: append([]byte(nil), snapshot.evidence...)}, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.plan = nil
	s.snapshot.Store(nil)
	return nil
}
func physicalID(id string, generation uint64) string {
	return "extension." + hash([]byte(fmt.Sprintf("%s:%d", id, generation)))
}
