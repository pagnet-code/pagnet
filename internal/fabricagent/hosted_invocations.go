package fabricagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/transport"
)

// HostedInvocations is the signed initial-effect journal for original hosted
// invocations. Before any enqueue or effect it retains the exact original and
// finalized canonical envelopes, the genuine kernel/hosted caller, the current
// selected binding/revision/plan, the command ID, the original encrypted
// input/AAD/epoch and the accepted association. It reuses the global
// original-dispatch claim: an exact retry returns the same ciphertext, command
// and source without re-signing; a changed caller, input, binding, epoch,
// revision, plan or command conflicts; a failed admission loses the claim and
// the journal together, so loss after possible acceptance is UNKNOWN, never a
// new paid turn.
type HostedInvocations struct {
	store     *registry.Store
	profiles  *HostedProfiles
	owner     HostedOwner
	root      registry.AuthorityIdentity
	protector durable.DataProtector
	limits    HostedInvocationLimits
}

// InvokedInput is pre-computed by the composing adapter: the exact prompt text
// encrypted with the cloud network key epoch. This journal never performs e2ee
// crypto itself; it validates shape and retains the opaque ciphertext.
type InvokedInput struct {
	Ciphertext e2ee.EncryptedPayloadV1 `json:"ciphertext"`
	AAD        e2ee.AAD                `json:"aad"`
	CommandID  string                  `json:"commandId"`
}

// HostedInvocationReceipt is the retained record value plus its signed AuthorityRecord proof.
// A retry returns the retained value byte-for-byte; nothing is regenerated.
type HostedInvocationReceipt struct {
	Format              int                           `json:"format"`
	Principal           fabric.Principal              `json:"principal"`
	InvocationID        string                        `json:"invocationId"`
	Original            []byte                        `json:"original"`
	Finalized           []byte                        `json:"finalized"`
	Target              fabric.EndpointRef            `json:"target"`
	TargetRevision      fabric.Revision               `json:"targetRevision"`
	BindingID           string                        `json:"bindingId"`
	BindingSHA          [32]byte                      `json:"bindingSha"`
	EndpointRevision    fabric.Revision               `json:"endpointRevision"`
	PlanFingerprint     [32]byte                      `json:"planFingerprint"`
	CommandID           string                        `json:"commandId"`
	Ciphertext          e2ee.EncryptedPayloadV1       `json:"ciphertext"`
	AAD                 e2ee.AAD                      `json:"aad"`
	ProfileFingerprint  [32]byte                      `json:"profileFingerprint"`
	AssociationRevision uint64                        `json:"associationRevision,string"`
	Scope               registry.DescriptorBatchScope `json:"scope"`
	State               string                        `json:"state"`
	Proof               registry.AuthorityRecord      `json:"-"`
}

type HostedInvocationLimits struct {
	MaxInvocations uint64 `json:"maxInvocations,string"`
	MaxBytes       uint64 `json:"maxBytes,string"`
}

func validHostedInvocationLimits(l HostedInvocationLimits) bool {
	return l.MaxInvocations > 0 && l.MaxInvocations <= 1<<20 && l.MaxBytes >= 64<<10 && l.MaxBytes <= 1<<30
}

func hostedInvocationError() error {
	return fabric.NewError(fabric.CodeStaleReference, "Original hosted invocation journal is unavailable or changed")
}
func hostedCallerError() error {
	return fabric.NewError(fabric.CodeStaleReference, "Original hosted caller association is unavailable or changed")
}
func sameAuthorityRoot(a, b registry.AuthorityIdentity) bool {
	return a.Namespace == b.Namespace && a.StoreID == b.StoreID && a.Owner == b.Owner && a.KeyRevision == b.KeyRevision && bytes.Equal(a.PublicKey, b.PublicKey)
}

const (
	hostedInvocationChunkBytes = 24 << 10
	hostedInvocationMaxBytes   = 768 << 10
)

type hostedInvocationMarker struct {
	Format             int              `json:"format"`
	Bytes              int              `json:"bytes"`
	Chunks             int              `json:"chunks"`
	CipherDigest       [32]byte         `json:"cipherDigest"`
	Principal          fabric.Principal `json:"principal"`
	InvocationID       string           `json:"invocationId"`
	CommandID          string           `json:"commandId"`
	ProfileFingerprint [32]byte         `json:"profileFingerprint"`
}

func hostedInvocationKey(principal fabric.Principal, invocation string) registry.AuthorityKey {
	raw, _ := json.Marshal(struct {
		Purpose    string
		Principal  fabric.Principal
		Invocation string
	}{"pagnet.hosted.invocation.v1", principal, invocation})
	digest := sha256.Sum256(raw)
	return registry.AuthorityKey{Kind: registry.AuthorityNativeCheckpoint, ID: "hosted/invocation/" + hex.EncodeToString(digest[:])}
}
func hostedInvocationChunkKey(key registry.AuthorityKey, index int) registry.AuthorityKey {
	key.ID += "/chunk/" + strconv.Itoa(index)
	return key
}

var hostedInvocationStateKey = registry.AuthorityKey{Kind: registry.AuthorityNativeCheckpoint, ID: "hosted/invocation/capacity"}

type hostedInvocationState struct {
	Format      int                    `json:"format"`
	Key         durable.KeyReference   `json:"key"`
	Limits      HostedInvocationLimits `json:"limits"`
	Invocations uint64                 `json:"invocations,string"`
	Bytes       uint64                 `json:"bytes,string"`
}

// NewHostedInvocations captures the current signed root and verifies the
// current kernel owner exactly like NewHostedProfiles. The protector and store
// must be the same ones the profiles were built with; a split root or key
// reference fails closed.
func NewHostedInvocations(ctx context.Context, store *registry.Store, profiles *HostedProfiles, protector durable.DataProtector, limits HostedInvocationLimits) (*HostedInvocations, error) {
	if ctx == nil || store == nil || profiles == nil || protector == nil || !validHostedInvocationLimits(limits) || store != profiles.store || protector.Reference() != profiles.protector.Reference() {
		return nil, hostedInvocationError()
	}
	root, e := store.CurrentAuthorityIdentity(ctx)
	if e != nil || !sameAuthorityRoot(root, profiles.root) {
		return nil, hostedInvocationError()
	}
	caller, e := profiles.owner(ctx)
	if e != nil || caller.VerifyAuthenticated(root.Namespace) != nil || caller.PrincipalView() != root.Owner {
		return nil, hostedInvocationError()
	}
	return &HostedInvocations{store: store, profiles: profiles, owner: profiles.owner, root: root, protector: protector, limits: limits}, nil
}

func (s *HostedInvocations) aad(key registry.AuthorityKey) []byte {
	raw, _ := json.Marshal(struct{ Purpose, Domain, Store, Key string }{"pagnet.original-hosted.invocation.v1", s.root.Namespace, s.root.StoreID, key.ID})
	return raw
}
func (s *HostedInvocations) with(ctx context.Context, scope registry.DescriptorBatchScope, next func(*registry.AuthorityTx) error) error {
	if s == nil || ctx == nil || scope.Endpoint.Domain() != s.root.Namespace || scope.ExpectedEndpointRevision == "" || scope.BindingID == "" || scope.ExpectedProjectionRevision != 0 {
		return hostedInvocationError()
	}
	owner, e := s.owner(ctx)
	if e != nil {
		return e
	}
	return s.store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{Endpoint: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, BindingID: scope.BindingID, MaxOperations: 128, Timeout: 5 * time.Second}, next)
}

// callerWitness decodes the accepted association, re-probes the genuine
// original worker and builds the private witness whose VerifyTx rechecks the
// association record in the SAME destination transaction. This mirrors
// HostedProfiles.CallerAuthority inline because the journal also binds the
// association record revision.
func (s *HostedInvocations) callerWitness(ctx context.Context, scope registry.DescriptorBatchScope, principal fabric.Principal) (HostedProfile, [32]byte, uint64, *fabricauth.HostedCallerAuthority, error) {
	var profile HostedProfile
	var record registry.AuthorityRecord
	e := s.with(ctx, scope, func(tx *registry.AuthorityTx) error {
		var err error
		profile, record, err = s.profiles.decode(tx, scope)
		return err
	})
	if e != nil {
		if ctx.Err() != nil {
			return HostedProfile{}, [32]byte{}, 0, nil, e
		}
		return HostedProfile{}, [32]byte{}, 0, nil, hostedCallerError()
	}
	if e = s.profiles.probe(ctx, profile); e != nil {
		if ctx.Err() != nil {
			return HostedProfile{}, [32]byte{}, 0, nil, e
		}
		return HostedProfile{}, [32]byte{}, 0, nil, hostedCallerError()
	}
	raw, _ := json.Marshal(struct {
		Scope    registry.DescriptorBatchScope
		Profile  HostedProfile
		Revision uint64
	}{scope, profile, record.Revision})
	defer clear(raw)
	witness, e := fabricauth.NewHostedCallerAuthority(s.root, principal, scope, record)
	if e != nil {
		return HostedProfile{}, [32]byte{}, 0, nil, hostedCallerError()
	}
	return profile, sha256.Sum256(raw), record.Revision, witness, nil
}

// Reserve journals the first uncertain hosted effect BEFORE any enqueue or
// effect. Exact retries return the retained receipt byte-for-byte and never
// re-sign or re-claim; every other change conflicts. False never permits send.
func (s *HostedInvocations) Reserve(ctx context.Context, scope registry.DescriptorBatchScope, caller fabric.ExecutionContext, original, finalized []byte, f fabric.DispatchAdmissionFrame, invoked InvokedInput, planFingerprint [32]byte, prepared ...*registry.PreparedInvocationTarget) (HostedInvocationReceipt, bool, error) {
	if s == nil || ctx == nil || caller.VerifyAuthenticated(s.root.Namespace) != nil {
		return HostedInvocationReceipt{}, false, hostedInvocationError()
	}
	before, e := caller.DecodeVerifiedEnvelope(original, s.root.Namespace)
	if e != nil {
		return HostedInvocationReceipt{}, false, e
	}
	var after fabric.Envelope
	if fabric.DecodeJSON(finalized, &after) != nil || after.Validate() != nil || after.Operation != fabric.OperationInvoke || after.Target == nil || after.ID != before.ID || after.Principal != before.Principal || after.Source != before.Source || after.Target.Endpoint() != scope.Endpoint {
		return HostedInvocationReceipt{}, false, hostedInvocationError()
	}
	if planFingerprint == ([32]byte{}) {
		return HostedInvocationReceipt{}, false, hostedInvocationError()
	}
	principal := caller.PrincipalView()
	deadline := ""
	if after.Context.Deadline != nil {
		deadline = after.Context.Deadline.UTC().Format(time.RFC3339Nano)
	}
	if f.SourceDomain != s.root.Namespace || f.AudienceDomain != s.root.Namespace || f.CallerRef != principal.Ref || f.InvocationID != after.ID || f.FinalizedDispatchDigest != sha256.Sum256(finalized) || f.Deadline != deadline {
		return HostedInvocationReceipt{}, false, hostedInvocationError()
	}
	if _, e = domain.ParseID(invoked.CommandID); e != nil {
		return HostedInvocationReceipt{}, false, hostedInvocationError()
	}
	if invoked.Ciphertext.Validate() != nil || invoked.AAD.ProtectedContext != nil || invoked.AAD.NativeContent != nil || invoked.AAD.ProtocolVersion != transport.ProtocolVersion || invoked.AAD.ObjectType != e2ee.ObjectTypeInvocationInput || invoked.AAD.ObjectID != after.ID || invoked.AAD.Recipient == "" || invoked.AAD.NetworkID == "" || invoked.AAD.KeyEpochID != invoked.Ciphertext.KeyEpochID {
		return HostedInvocationReceipt{}, false, hostedInvocationError()
	}
	descriptor, e := s.store.GetEndpoint(ctx, scope.Endpoint, scope.ExpectedEndpointRevision)
	if e != nil {
		return HostedInvocationReceipt{}, false, e
	}
	var binding fabric.BindingSummary
	found := false
	for i := range descriptor.Bindings {
		if descriptor.Bindings[i].ID == scope.BindingID {
			binding = descriptor.Bindings[i]
			found = true
			break
		}
	}
	if !found {
		return HostedInvocationReceipt{}, false, hostedInvocationError()
	}
	encodedBinding, _ := json.Marshal(binding)
	bindingSHA := sha256.Sum256(encodedBinding)
	profile, fingerprint, associationRevision, witness, e := s.callerWitness(ctx, scope, principal)
	if e != nil {
		return HostedInvocationReceipt{}, false, e
	}
	if invoked.AAD.Recipient != profile.Scope.InstanceID || invoked.AAD.NetworkID != profile.NetworkID {
		return HostedInvocationReceipt{}, false, hostedInvocationError()
	}
	value := HostedInvocationReceipt{Format: 1, Principal: principal, InvocationID: after.ID, Original: bytes.Clone(original), Finalized: bytes.Clone(finalized), Target: *after.Target, TargetRevision: after.ExpectedRevision, BindingID: scope.BindingID, BindingSHA: bindingSHA, EndpointRevision: scope.ExpectedEndpointRevision, PlanFingerprint: planFingerprint, CommandID: invoked.CommandID, Ciphertext: invoked.Ciphertext, AAD: invoked.AAD, ProfileFingerprint: fingerprint, AssociationRevision: associationRevision, Scope: scope, State: "reserved"}
	var result HostedInvocationReceipt
	var fresh bool
	e = s.with(ctx, scope, func(tx *registry.AuthorityTx) error {
		if e := witness.VerifyTx(tx); e != nil {
			return hostedCallerError()
		}
		key := hostedInvocationKey(principal, after.ID)
		retained, e := s.readRecordTx(tx, key)
		if e == nil {
			if e := s.compareRetained(retained, scope, principal, original, finalized, after.ExpectedRevision, invoked, planFingerprint, bindingSHA, fingerprint, associationRevision); e != nil {
				return e
			}
			result = retained
			return nil
		}
		var typed *fabric.Error
		if !errors.As(e, &typed) || typed.Code != fabric.CodeNotFound {
			return e
		}
		// Co-commit the global original-dispatch claim first. Any later failure
		// rolls the claim and the journal back together: no partial paid state.
		if _, e := tx.SignDispatchAdmission(caller, original, finalized, f, prepared...); e != nil {
			return e
		}
		raw, e := json.Marshal(value)
		if e != nil || len(raw) > hostedInvocationMaxBytes {
			return hostedInvocationError()
		}
		defer clear(raw)
		cipher, e := s.protector.Seal(s.aad(key), raw)
		if e != nil || len(cipher) > hostedInvocationMaxBytes+1024 {
			return hostedInvocationError()
		}
		defer clear(cipher)
		marker := hostedInvocationMarker{Format: 1, Bytes: len(cipher), Chunks: (len(cipher) + hostedInvocationChunkBytes - 1) / hostedInvocationChunkBytes, CipherDigest: sha256.Sum256(cipher), Principal: principal, InvocationID: after.ID, CommandID: invoked.CommandID, ProfileFingerprint: fingerprint}
		markerRaw, e := json.Marshal(marker)
		if e != nil || len(markerRaw) > 4096 {
			return hostedInvocationError()
		}
		state, stateRow, e := s.stateTx(tx)
		if e != nil {
			var typed *fabric.Error
			if !errors.As(e, &typed) || typed.Code != fabric.CodeNotFound {
				return e
			}
			state = hostedInvocationState{Format: 1, Key: s.protector.Reference(), Limits: s.limits}
			stateInit, e := s.encodeState(state)
			if e != nil {
				return e
			}
			stateRow, e = tx.CAS(hostedInvocationStateKey, 0, stateInit, false)
			if e != nil {
				return e
			}
		}
		// Capacity is checked AFTER the claim so exhaustion rolls both back.
		if state.Invocations >= state.Limits.MaxInvocations || uint64(len(cipher)+len(markerRaw)) > state.Limits.MaxBytes-state.Bytes {
			return fabric.NewError(fabric.CodeTargetUnavailable, "Retained hosted invocation capacity exhausted")
		}
		for i := 0; i < marker.Chunks; i++ {
			chunk, _ := json.Marshal(cipher[i*hostedInvocationChunkBytes : min((i+1)*hostedInvocationChunkBytes, len(cipher))])
			if _, e := tx.CAS(hostedInvocationChunkKey(key, i), 0, chunk, false); e != nil {
				return e
			}
		}
		row, e := tx.CAS(key, 0, markerRaw, false)
		if e != nil {
			return e
		}
		state.Invocations++
		state.Bytes += uint64(len(cipher) + len(markerRaw))
		stateValue, e := s.encodeState(state)
		if e != nil {
			return e
		}
		if _, e := tx.CAS(hostedInvocationStateKey, stateRow.Revision, stateValue, false); e != nil {
			return e
		}
		value.Proof = row
		result = value
		fresh = true
		return nil
	})
	return result, fresh, e
}

// compareRetained names the first changed field class. An exact retry never
// re-seals, re-signs or re-claims; a retired record cannot be re-reserved.
func (s *HostedInvocations) compareRetained(r HostedInvocationReceipt, scope registry.DescriptorBatchScope, principal fabric.Principal, original, finalized []byte, targetRevision fabric.Revision, invoked InvokedInput, planFingerprint [32]byte, bindingSHA, fingerprint [32]byte, associationRevision uint64) error {
	switch {
	case r.Principal != principal:
		return fabric.NewError(fabric.CodeStaleReference, "Original hosted invocation caller changed")
	case !bytes.Equal(r.Original, original) || !bytes.Equal(r.Finalized, finalized):
		return fabric.NewError(fabric.CodeStaleReference, "Original hosted invocation input changed")
	case r.CommandID != invoked.CommandID:
		return fabric.NewError(fabric.CodeStaleReference, "Original hosted invocation command changed")
	case r.AAD.KeyEpochID != invoked.AAD.KeyEpochID || r.Ciphertext.KeyEpochID != invoked.Ciphertext.KeyEpochID:
		return fabric.NewError(fabric.CodeStaleReference, "Original hosted invocation key epoch changed")
	case r.Ciphertext != invoked.Ciphertext || r.AAD != invoked.AAD:
		return fabric.NewError(fabric.CodeStaleReference, "Original hosted invocation input changed")
	case r.PlanFingerprint != planFingerprint:
		return fabric.NewError(fabric.CodeStaleReference, "Original hosted invocation plan changed")
	case r.BindingID != scope.BindingID || r.Target != scope.Endpoint || r.BindingSHA != bindingSHA:
		return fabric.NewError(fabric.CodeStaleReference, "Original hosted invocation binding changed")
	case r.EndpointRevision != scope.ExpectedEndpointRevision || r.TargetRevision != targetRevision:
		return fabric.NewError(fabric.CodeStaleReference, "Original hosted invocation revision changed")
	case r.Scope != scope || r.ProfileFingerprint != fingerprint || r.AssociationRevision != associationRevision:
		return fabric.NewError(fabric.CodeStaleReference, "Original hosted invocation association changed")
	}
	return nil
}

func (s *HostedInvocations) stateTx(tx *registry.AuthorityTx) (hostedInvocationState, registry.AuthorityRecord, error) {
	var st hostedInvocationState
	row, e := tx.Get(hostedInvocationStateKey)
	if e != nil {
		return st, row, e
	}
	if row.Retired || registry.VerifyAuthorityRecord(s.root, row) != nil {
		return st, row, hostedInvocationError()
	}
	var box struct{ Cipher []byte }
	if fabric.DecodeJSONWithLimits(row.Value, &box, fabric.WireLimits{MaxBytes: 2048, MaxDepth: 2, MaxMembers: 4}) != nil {
		return st, row, hostedInvocationError()
	}
	raw, e := s.protector.Open(s.aad(hostedInvocationStateKey), box.Cipher)
	if e != nil {
		return st, row, hostedInvocationError()
	}
	defer clear(raw)
	if fabric.DecodeJSONWithLimits(raw, &st, fabric.WireLimits{MaxBytes: 4096, MaxDepth: 4, MaxMembers: 32}) != nil || st.Format != 1 || st.Key != s.protector.Reference() || st.Limits != s.limits || st.Invocations > st.Limits.MaxInvocations || st.Bytes > st.Limits.MaxBytes {
		return st, row, hostedInvocationError()
	}
	return st, row, nil
}
func (s *HostedInvocations) encodeState(st hostedInvocationState) ([]byte, error) {
	raw, e := json.Marshal(st)
	if e != nil || len(raw) > 1024 {
		return nil, hostedInvocationError()
	}
	defer clear(raw)
	cipher, e := s.protector.Seal(s.aad(hostedInvocationStateKey), raw)
	if e != nil || len(cipher) > 2048 {
		return nil, hostedInvocationError()
	}
	out, _ := json.Marshal(struct{ Cipher []byte }{cipher})
	clear(cipher)
	if len(out) > 4096 {
		return nil, hostedInvocationError()
	}
	return out, nil
}

// readRecordTx opens the sealed retained value under the root signature. A
// retired record fails closed and can never be re-reserved.
func (s *HostedInvocations) readRecordTx(tx *registry.AuthorityTx, key registry.AuthorityKey) (HostedInvocationReceipt, error) {
	row, e := tx.Get(key)
	if e != nil {
		return HostedInvocationReceipt{}, e
	}
	if row.Retired || registry.VerifyAuthorityRecord(s.root, row) != nil {
		return HostedInvocationReceipt{}, hostedInvocationError()
	}
	// The two 32-byte digests are JSON number arrays: 8 top-level members +
	// 3 principal members + 2x32 array elements = 75, plus headroom.
	var marker hostedInvocationMarker
	if fabric.DecodeJSONWithLimits(row.Value, &marker, fabric.WireLimits{MaxBytes: 4096, MaxDepth: 3, MaxMembers: 128}) != nil || marker.Format != 1 || marker.Bytes < 1 || marker.Bytes > hostedInvocationMaxBytes+1024 || marker.Chunks != (marker.Bytes+hostedInvocationChunkBytes-1)/hostedInvocationChunkBytes || marker.Chunks > (hostedInvocationMaxBytes+1024+hostedInvocationChunkBytes-1)/hostedInvocationChunkBytes {
		return HostedInvocationReceipt{}, hostedInvocationError()
	}
	cipher := make([]byte, 0, marker.Bytes)
	defer func() { clear(cipher) }()
	for i := 0; i < marker.Chunks; i++ {
		chunk, e := tx.Get(hostedInvocationChunkKey(key, i))
		if e != nil || chunk.Retired || registry.VerifyAuthorityRecord(s.root, chunk) != nil {
			return HostedInvocationReceipt{}, hostedInvocationError()
		}
		var value []byte
		if json.Unmarshal(chunk.Value, &value) != nil || len(value) != min(hostedInvocationChunkBytes, marker.Bytes-i*hostedInvocationChunkBytes) {
			return HostedInvocationReceipt{}, hostedInvocationError()
		}
		cipher = append(cipher, value...)
		clear(value)
	}
	if sha256.Sum256(cipher) != marker.CipherDigest {
		return HostedInvocationReceipt{}, hostedInvocationError()
	}
	raw, e := s.protector.Open(s.aad(key), cipher)
	if e != nil {
		return HostedInvocationReceipt{}, hostedInvocationError()
	}
	defer clear(raw)
	var r HostedInvocationReceipt
	if fabric.DecodeJSONWithLimits(raw, &r, fabric.WireLimits{MaxBytes: hostedInvocationMaxBytes, MaxDepth: 8, MaxMembers: 256}) != nil || r.Format != 1 || r.State != "reserved" || r.AAD.ObjectID != r.InvocationID || r.Ciphertext.Validate() != nil {
		return HostedInvocationReceipt{}, hostedInvocationError()
	}
	r.Proof = row
	return r, nil
}

// ValidateDelivered is the daemon delivery guard: a transported hosted
// invocation is accepted only if it is the exact retained original for this
// genuine current caller. It never admits a new effect.
func (s *HostedInvocations) ValidateDelivered(ctx context.Context, scope registry.DescriptorBatchScope, caller fabric.ExecutionContext, inv transport.FabricHostedInvocation) (HostedInvocationReceipt, error) {
	if s == nil || ctx == nil {
		return HostedInvocationReceipt{}, hostedInvocationError()
	}
	if e := inv.Validate(); e != nil {
		return HostedInvocationReceipt{}, e
	}
	if caller.VerifyAuthenticated(s.root.Namespace) != nil {
		return HostedInvocationReceipt{}, hostedInvocationError()
	}
	principal := caller.PrincipalView()
	_, _, _, witness, e := s.callerWitness(ctx, scope, principal)
	if e != nil {
		return HostedInvocationReceipt{}, e
	}
	key := hostedInvocationKey(principal, inv.InvocationID)
	var result HostedInvocationReceipt
	e = s.with(ctx, scope, func(tx *registry.AuthorityTx) error {
		if e := witness.VerifyTx(tx); e != nil {
			return hostedCallerError()
		}
		profile, _, e := s.profiles.decode(tx, scope)
		if e != nil {
			return e
		}
		r, e := s.readRecordTx(tx, key)
		if e != nil {
			return e
		}
		if r.Principal != principal || r.CommandID != inv.CommandID || r.Ciphertext != inv.Envelope || r.AAD != inv.AAD || r.Target != inv.Ref || r.TargetRevision != inv.Revision || r.AAD.NetworkID != inv.NetworkID || r.AAD.Recipient != inv.InstanceID || profile.OwnershipID != inv.OwnershipID || profile.Scope.Generation != inv.OwnershipGeneration || r.Scope != scope {
			return fabric.NewError(fabric.CodeStaleReference, "Hosted invocation delivery does not match its retained original")
		}
		result = r
		return nil
	})
	return result, e
}
