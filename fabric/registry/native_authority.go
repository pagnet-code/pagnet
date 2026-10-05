package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type NativeAuthorityKind string

const (
	AuthorityController NativeAuthorityKind = "controller"
	// Extension configuration is a separate global signed private purpose, not
	// a native worker binding or publicly callable offer.
	AuthorityExtensionConfiguration NativeAuthorityKind = "extension_configuration"
	AuthorityNativeCheckpoint       NativeAuthorityKind = "native_checkpoint"
	AuthorityFederationPeer         NativeAuthorityKind = "federation_peer"
	AuthorityFederationInvocation   NativeAuthorityKind = "federation_invocation"
	AuthorityServiceBinding         NativeAuthorityKind = "service_binding"
	AuthorityServiceInvocation      NativeAuthorityKind = "service_invocation"
	AuthorityLocalInstallation      NativeAuthorityKind = "local_installation"
	// Dispatch reservations are domain-wide invocation replay receipts and
	// physical-worker sequence counters, never endpoint metadata or task state.
	AuthorityDispatch   NativeAuthorityKind = "dispatch"
	AuthorityBinding    NativeAuthorityKind = "binding"
	AuthorityAdmission  NativeAuthorityKind = "admission"
	AuthorityOrigin     NativeAuthorityKind = "origin"
	AuthoritySource     NativeAuthorityKind = "source"
	AuthorityRetirement NativeAuthorityKind = "retirement"
)

func validAuthorityKind(k NativeAuthorityKind) bool {
	switch k {
	case AuthorityLocalInstallation, AuthorityServiceBinding, AuthorityServiceInvocation, AuthorityFederationInvocation, AuthorityFederationPeer, AuthorityNativeCheckpoint, AuthorityExtensionConfiguration, AuthorityController, AuthorityDispatch, AuthorityBinding, AuthorityAdmission, AuthorityOrigin, AuthoritySource, AuthorityRetirement:
		return true
	}
	return false
}

func globalAuthorityKind(k NativeAuthorityKind) bool {
	return k == AuthorityLocalInstallation || k == AuthorityServiceInvocation || k == AuthorityFederationInvocation || k == AuthorityFederationPeer || k == AuthorityController || k == AuthorityDispatch || k == AuthorityExtensionConfiguration || k == AuthorityNativeCheckpoint
}

// AuthorityIdentity is public verification material, never a signing capability.
// This first implementation explicitly supports the original immutable revision1;
// it does not fabricate key rotation or distributed rollback protection.
type AuthorityIdentity struct {
	Namespace   string           `json:"namespace"`
	StoreID     string           `json:"storeId"`
	Owner       fabric.Principal `json:"owner"`
	PublicKey   []byte           `json:"publicKey"`
	KeyRevision uint64           `json:"keyRevision"`
}

func (s *Store) AuthorityIdentity() AuthorityIdentity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return AuthorityIdentity{s.identity.Namespace, s.identity.StoreID, s.identity.Owner, bytes.Clone(s.identity.PublicKey), 1}
}

type AuthorityScope struct {
	Endpoint         fabric.EndpointRef
	ExpectedRevision fabric.Revision
	BindingID        string
	HistoryOnly      bool
	// Callbacks are trusted bounded infrastructure, not extension application code.
	// Each method observes the finite deadline and operation budget. Go code inside
	// this process is trusted; the port is not a sandbox for malicious callbacks.
	MaxOperations int
	Timeout       time.Duration
}
type AuthorityKey struct {
	Kind     NativeAuthorityKind `json:"kind"`
	Endpoint fabric.EndpointRef  `json:"endpoint,omitempty"`
	ID       string              `json:"id"`
}

func (k AuthorityKey) string() string {
	return string(k.Kind) + "\x00" + k.Endpoint.String() + "\x00" + k.ID
}
func (k AuthorityKey) valid(domain string) bool {
	if !validAuthorityKind(k.Kind) || !text(k.ID, 256, false) {
		return false
	}
	if globalAuthorityKind(k.Kind) {
		return k.Endpoint.String() == ""
	}
	return !k.Endpoint.IsOffer() && k.Endpoint.Domain() == domain && k.Endpoint.String() != ""
}

type AuthorityRecord struct {
	Format           uint32       `json:"format"`
	Namespace        string       `json:"namespace"`
	StoreID          string       `json:"storeId"`
	KeyRevision      uint64       `json:"keyRevision"`
	Key              AuthorityKey `json:"key"`
	Revision         uint64       `json:"revision,string"`
	PreviousRevision uint64       `json:"previousRevision,string"`
	Sequence         uint64       `json:"sequence,string"`
	PreviousHead     [32]byte     `json:"previousHead"`
	Retired          bool         `json:"retired"`
	Value            []byte       `json:"value"`
	Signature        []byte       `json:"signature"`
}
type nativeStatement struct {
	Format           uint32       `json:"format"`
	Namespace        string       `json:"namespace"`
	StoreID          string       `json:"storeId"`
	KeyRevision      uint64       `json:"keyRevision"`
	Key              AuthorityKey `json:"key"`
	Revision         uint64       `json:"revision,string"`
	PreviousRevision uint64       `json:"previousRevision,string"`
	Sequence         uint64       `json:"sequence,string"`
	PreviousHead     [32]byte     `json:"previousHead"`
	Retired          bool         `json:"retired"`
	ValueDigest      [32]byte     `json:"valueDigest"`
}

func (r AuthorityRecord) signingBytes() ([]byte, error) {
	if r.Format != 1 || r.KeyRevision != 1 || r.Revision < 1 || r.Revision > math.MaxInt64 || r.Sequence < 1 || r.Sequence > math.MaxInt64 || r.PreviousRevision != r.Revision-1 || !r.Key.valid(r.Namespace) || len(r.StoreID) != 64 {
		return nil, invalid("Invalid typed native authority record")
	}
	id, e := hex.DecodeString(r.StoreID)
	if e != nil || len(id) != 32 || hex.EncodeToString(id) != r.StoreID {
		return nil, invalid("Invalid native authority store identity")
	}
	h := nativeStatement{r.Format, r.Namespace, r.StoreID, r.KeyRevision, r.Key, r.Revision, r.PreviousRevision, r.Sequence, r.PreviousHead, r.Retired, sha256.Sum256(r.Value)}
	raw, e := json.Marshal(h)
	if e != nil || len(raw) > fabric.MaxSigningFrameBytes {
		return nil, invalid("Native authority signing profile exceeds bound")
	}
	// Closed purpose derived from validated Kind. Never genesis/registry signing,
	// nor an arbitrary caller-provided byte string prefixed as another purpose.
	return append([]byte("pagnet.fabric.local-native-record."+string(r.Key.Kind)+".v1\x00"), raw...), nil
}
func VerifyAuthorityRecord(identity AuthorityIdentity, r AuthorityRecord) error {
	namespace, e := fabric.DomainNamespace(identity.PublicKey)
	if e != nil || namespace != identity.Namespace || identity.KeyRevision != 1 || r.Namespace != namespace || r.StoreID != identity.StoreID || r.KeyRevision != identity.KeyRevision || len(r.Signature) != ed25519.SignatureSize {
		return invalid("Native authority issuer mismatch")
	}
	raw, e := r.signingBytes()
	if e != nil || !ed25519.Verify(identity.PublicKey, raw, r.Signature) {
		return invalid("Native authority record signature invalid")
	}
	return nil
}
func cloneAuthorityRecord(r AuthorityRecord) AuthorityRecord {
	r.Value = bytes.Clone(r.Value)
	r.Signature = bytes.Clone(r.Signature)
	return r
}

const nativeAuthoritySchema = `CREATE TABLE native_authority_head(singleton INTEGER PRIMARY KEY CHECK(singleton=1),sequence INTEGER NOT NULL,head BLOB NOT NULL,records INTEGER NOT NULL,bytes INTEGER NOT NULL);
INSERT INTO native_authority_head VALUES(1,0,zeroblob(32),0,0);
CREATE TABLE native_authority_log(sequence INTEGER PRIMARY KEY,record BLOB NOT NULL);
CREATE TABLE native_authority_state(key TEXT PRIMARY KEY,revision INTEGER NOT NULL,retired INTEGER NOT NULL,record BLOB NOT NULL);
PRAGMA user_version=2;`

// AuthorityTx exposes no SQL, root key, generic signer or deletion. Its private
// methods are bound to the declared scope and become unusable after callback exit.
type AuthorityTx struct {
	mu            sync.Mutex
	tx            *sql.Tx
	store         *Store
	ctx           context.Context
	scope         AuthorityScope
	active        bool
	operations    int
	maxOperations int
}

func (a *AuthorityTx) guard() error {
	if !a.active {
		return invalid("Native authority transaction is closed")
	}
	if e := a.ctx.Err(); e != nil {
		return e
	}
	a.operations++
	if a.operations > a.maxOperations {
		return invalid("Native authority transaction operation budget exceeded")
	}
	return nil
}
func (a *AuthorityTx) close() { a.mu.Lock(); a.active = false; a.mu.Unlock() }
func (a *AuthorityTx) key(k AuthorityKey) error {
	if !k.valid(a.store.identity.Namespace) || !globalAuthorityKind(k.Kind) && k.Endpoint != a.scope.Endpoint {
		return invalid("Native authority key outside declared scope")
	}
	return nil
}
func (a *AuthorityTx) get(k AuthorityKey) (AuthorityRecord, error) {
	var raw []byte
	e := a.tx.QueryRowContext(a.ctx, "SELECT CASE WHEN length(record)<=? THEN record END FROM native_authority_state WHERE key=?", a.store.options.Limits.MaxPayloadBytes*2+65536, k.string()).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return AuthorityRecord{}, fabric.NewError(fabric.CodeNotFound, "Native authority record absent")
	}
	if e != nil {
		return AuthorityRecord{}, e
	}
	var r AuthorityRecord
	if e = a.store.decodeAuthority(raw, &r); e != nil {
		return r, e
	}
	if r.Key != k {
		return r, invalid("Native authority key mismatch")
	}
	return r, nil
}
func (a *AuthorityTx) Get(k AuthorityKey) (AuthorityRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.guard(); e != nil {
		return AuthorityRecord{}, e
	}
	if e := a.key(k); e != nil {
		return AuthorityRecord{}, e
	}
	r, e := a.get(k)
	return cloneAuthorityRecord(r), e
}
func (a *AuthorityTx) CAS(k AuthorityKey, expected uint64, value []byte, retire bool) (AuthorityRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.guard(); e != nil {
		return AuthorityRecord{}, e
	}
	if e := a.key(k); e != nil {
		return AuthorityRecord{}, e
	}
	if a.scope.HistoryOnly && k.Kind != AuthoritySource && k.Kind != AuthorityRetirement {
		return AuthorityRecord{}, invalid("History-only scope cannot publish new native authority")
	}
	if expected >= math.MaxInt64 || len(value) > a.store.options.Limits.MaxPayloadBytes {
		return AuthorityRecord{}, invalid("Native authority mutation exceeds bounds")
	}
	var v any
	if e := a.store.decode(value, &v); e != nil {
		return AuthorityRecord{}, e
	}
	old, e := a.get(k)
	exists := e == nil
	if e != nil {
		var fe *fabric.Error
		if !errors.As(e, &fe) || fe.Code != fabric.CodeNotFound {
			return AuthorityRecord{}, e
		}
	}
	if exists && old.PreviousRevision == expected && old.Retired == retire && bytes.Equal(old.Value, value) {
		return cloneAuthorityRecord(old), nil
	}
	if exists && (old.Retired || old.Revision != expected) || !exists && expected != 0 || !exists && retire {
		return AuthorityRecord{}, conflict("Native authority CAS or tombstone conflict")
	}
	var sequence, count, total int64
	var prev []byte
	if e = a.tx.QueryRowContext(a.ctx, "SELECT sequence,head,records,bytes FROM native_authority_head WHERE singleton=1").Scan(&sequence, &prev, &count, &total); e != nil {
		return AuthorityRecord{}, e
	}
	if sequence < 0 || sequence >= math.MaxInt64 || len(prev) != 32 || count < 0 || total < 0 {
		return AuthorityRecord{}, invalid("Native authority head invalid")
	}
	r := AuthorityRecord{Format: 1, Namespace: a.store.identity.Namespace, StoreID: a.store.identity.StoreID, KeyRevision: 1, Key: k, Revision: expected + 1, PreviousRevision: expected, Sequence: uint64(sequence) + 1, Retired: retire, Value: bytes.Clone(value)}
	copy(r.PreviousHead[:], prev)
	sign, e := r.signingBytes()
	if e != nil {
		return AuthorityRecord{}, e
	}
	r.Signature = ed25519.Sign(a.store.key, sign)
	raw, e := json.Marshal(r)
	if e != nil {
		return AuthorityRecord{}, e
	}
	if uint64(count) >= a.store.options.Limits.MaxRecords || int64(len(raw)) > a.store.options.Limits.MaxLedgerBytes-total {
		return AuthorityRecord{}, invalid("Native authority ledger capacity reached")
	}
	head := sha256.Sum256(raw)
	if _, e = a.tx.ExecContext(a.ctx, "INSERT INTO native_authority_log VALUES(?,?)", r.Sequence, raw); e != nil {
		return AuthorityRecord{}, e
	}
	if _, e = a.tx.ExecContext(a.ctx, "INSERT INTO native_authority_state VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET revision=excluded.revision,retired=excluded.retired,record=excluded.record", k.string(), r.Revision, retire, raw); e != nil {
		return AuthorityRecord{}, e
	}
	if _, e = a.tx.ExecContext(a.ctx, "UPDATE native_authority_head SET sequence=?,head=?,records=records+1,bytes=bytes+? WHERE singleton=1", r.Sequence, head[:], len(raw)); e != nil {
		return AuthorityRecord{}, e
	}
	return cloneAuthorityRecord(r), nil
}

// SignCallerProof verifies ORIGINAL exact bytes against an authenticated context.
// A signature alone is not a committed/current native admission.
func (a *AuthorityTx) SignCallerProof(c fabric.ExecutionContext, original []byte, f fabric.CallerProofFrame) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.guard(); e != nil {
		return nil, e
	}
	if a.scope.HistoryOnly {
		return nil, invalid("History-only scope cannot sign caller admission")
	}
	env, e := c.DecodeVerifiedEnvelope(original, a.store.identity.Namespace)
	if e != nil {
		return nil, e
	}
	if f.SourceDomain != a.store.identity.Namespace || f.AudienceDomain != a.store.identity.Namespace || f.IssuerKeyRevision != 1 || f.CallerRef != c.PrincipalView().Ref || f.Operation != env.Operation || f.OriginalEnvelopeID != env.ID || f.OriginalEnvelopeDigest != sha256.Sum256(original) || f.Deadline != authorityDeadline(env) {
		return nil, invalid("Original caller signing profile mismatch")
	}
	frame, e := f.SigningBytes()
	if e != nil {
		return nil, e
	}
	return ed25519.Sign(a.store.key, frame), nil
}

// SignDispatchAdmission verifies the finalized view and exact current registered
// target/binding. Caller identity/system fields remain bound to original bytes.
func (a *AuthorityTx) SignDispatchAdmission(c fabric.ExecutionContext, original, finalized []byte, f fabric.DispatchAdmissionFrame, prepared ...*PreparedInvocationTarget) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.guard(); e != nil {
		return nil, e
	}
	if a.scope.HistoryOnly {
		return nil, invalid("History-only scope cannot sign dispatch admission")
	}
	before, e := c.DecodeVerifiedEnvelope(original, a.store.identity.Namespace)
	if e != nil {
		return nil, e
	}
	var after fabric.Envelope
	if e = fabric.DecodeJSON(finalized, &after); e != nil || after.Validate() != nil {
		return nil, invalid("Finalized invocation malformed")
	}
	if after.Target == nil || after.Operation != fabric.OperationInvoke {
		return nil, invalid("Finalized target outside registered scope")
	}
	if _, e = a.verifyInvocationTarget(*after.Target, after.ExpectedRevision, after.Payload, prepared...); e != nil {
		return nil, e
	}
	x, y := before, after
	x.Payload = nil
	y.Payload = nil
	x.Metadata = nil
	y.Metadata = nil
	x.Target = nil
	y.Target = nil
	x.ExpectedRevision = ""
	y.ExpectedRevision = ""
	if !reflect.DeepEqual(x, y) {
		return nil, invalid("Finalized caller/system binding changed")
	}
	if f.SourceDomain != a.store.identity.Namespace || f.AudienceDomain != a.store.identity.Namespace || f.CallerRef != c.PrincipalView().Ref || f.InvocationID != after.ID || f.FinalizedDispatchDigest != sha256.Sum256(finalized) || f.Deadline != authorityDeadline(after) {
		return nil, invalid("Finalized dispatch signing profile mismatch")
	}
	frame, e := f.SigningBytes()
	if e != nil {
		return nil, e
	}
	return ed25519.Sign(a.store.key, frame), nil
}
func authorityDeadline(env fabric.Envelope) string {
	if env.Context.Deadline == nil {
		return ""
	}
	return env.Context.Deadline.UTC().Format(time.RFC3339Nano)
}

func (s *Store) WithNativeAuthority(ctx context.Context, owner fabric.ExecutionContext, scope AuthorityScope, callback func(*AuthorityTx) error) (err error) {
	if ctx == nil || callback == nil {
		return invalid("Missing native authority transaction")
	}
	if scope.MaxOperations == 0 {
		scope.MaxOperations = 128
	}
	if scope.Timeout == 0 {
		scope.Timeout = 5 * time.Second
	}
	if scope.MaxOperations < 1 || scope.MaxOperations > 4096 || scope.Timeout <= 0 || scope.Timeout > time.Minute {
		return invalid("Invalid native authority transaction bounds")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.authorize(owner); e != nil {
		return e
	}
	lifetime, cancel := context.WithTimeout(ctx, scope.Timeout)
	defer cancel()
	tx, e := s.db.BeginTx(lifetime, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	// Pinned owner/issuer/key and descriptor binding checks precede any schema or
	// arbitrary callback mutation. Registry owner/key are immutable revision1.
	if scope.Endpoint.String() != "" {
		if scope.Endpoint.IsOffer() || scope.Endpoint.Domain() != s.identity.Namespace || scope.ExpectedRevision == "" || scope.BindingID == "" {
			return invalid("Incomplete native authority endpoint scope")
		}
		o, e := loadObject(lifetime, tx, scope.Endpoint.String())
		if e != nil || !scope.HistoryOnly && (o.retired || o.revision != scope.ExpectedRevision) {
			return conflict("Native authority endpoint retired or stale")
		}
		var d fabric.EndpointDescriptor
		if e = s.decode(o.payload, &d); e != nil {
			return e
		}
		found := false
		for _, binding := range d.Bindings {
			found = found || binding.ID == scope.BindingID
		}
		if !found && !scope.HistoryOnly {
			return invalid("Native authority binding absent")
		}
	} else if scope.ExpectedRevision != "" || scope.BindingID != "" {
		return invalid("Global controller scope contains endpoint assertions")
	}
	var version int
	if e = tx.QueryRowContext(lifetime, "PRAGMA user_version").Scan(&version); e != nil {
		return e
	}
	if version == 1 {
		if _, e = tx.ExecContext(lifetime, nativeAuthoritySchema); e != nil {
			return e
		}
	} else if version != 2 {
		return invalid("Unsupported native authority format")
	}
	a := &AuthorityTx{tx: tx, store: s, ctx: lifetime, scope: scope, active: true, maxOperations: scope.MaxOperations}
	defer a.close()
	defer func() {
		if recover() != nil {
			err = fabric.NewError(fabric.CodeProtocolError, "Native authority transaction panicked and rolled back")
		}
	}()
	if err = callback(a); err != nil {
		return err
	}
	a.close()
	if err = lifetime.Err(); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) decodeAuthority(raw []byte, out any) error {
	return fabric.DecodeJSONWithLimits(raw, out, fabric.WireLimits{MaxBytes: s.options.Limits.MaxPayloadBytes*2 + 65536, MaxDepth: 64, MaxMembers: 4096})
}
