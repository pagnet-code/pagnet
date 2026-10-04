// Package identity provides local native authority backed by the domain's
// existing signed registry root. It supplies no cloud identity or native liveness
// assertion; authenticated owner/peer contexts come from trusted composition.
package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type Scope struct {
	Endpoint           fabric.EndpointRef `json:"endpoint"`
	DescriptorRevision fabric.Revision    `json:"descriptorRevision"`
	BindingID          string             `json:"bindingId"`
}
type WorkerBinding struct {
	WorkerID            string   `json:"workerId"`
	StateDirectoryID    string   `json:"stateDirectoryId"`
	OwnershipGeneration string   `json:"ownershipGeneration"`
	ActualRuntime       string   `json:"actualRuntime"`
	ProfileDigest       [32]byte `json:"profileDigest"`
}
type Controller struct {
	Scope         Scope                    `json:"scope"`
	ControllerID  string                   `json:"controllerId"`
	RequestID     string                   `json:"requestId"`
	ExpectedEpoch uint64                   `json:"expectedEpoch,string"`
	Proof         registry.AuthorityRecord `json:"proof"`
}

func (c Controller) Epoch() uint64 { return c.Proof.Revision }

type Binding struct {
	Scope  Scope                    `json:"scope"`
	Worker WorkerBinding            `json:"worker"`
	Proof  registry.AuthorityRecord `json:"proof"`
}

// AdmissionFacts are exact finalized ENGINE facts, not caller assertions. Byte
// slices are private ephemeral input to the configured fence, never persisted.
type AdmissionFacts struct {
	Scope           Scope
	OriginalCaller  fabric.Principal
	Provenance      fabric.Provenance
	OriginalDigest  [32]byte
	FinalizedDigest [32]byte
	OriginalBytes   []byte
	FinalizedBytes  []byte
	InvocationID    string
	AttemptID       string
	ReplayID        string
}
type Witness struct {
	Version         string          `json:"version"`
	FinalizedDigest [32]byte        `json:"finalizedDigest"`
	Value           json.RawMessage `json:"value"`
}

// AdmissionFence is trusted infrastructure. It validates current authorization
// and holds its supported revocation fence through commit. Arbitrary external
// databases are not atomically locked by the registry SQLite transaction. An
// implementation must document its linearization and rollback guarantees;
// signed opaque witnesses alone do not establish authorization.
type AdmissionFence interface {
	WithAdmission(context.Context, AdmissionFacts, func(Witness) error) error
}
type Admission struct {
	ID                      string                        `json:"id"`
	Scope                   Scope                         `json:"scope"`
	OriginalCaller          fabric.Principal              `json:"originalCaller"`
	Provenance              fabric.Provenance             `json:"provenance"`
	OriginalDigest          [32]byte                      `json:"originalDigest"`
	FinalizedDigest         [32]byte                      `json:"finalizedDigest"`
	InvocationID            string                        `json:"invocationId"`
	AttemptID               string                        `json:"attemptId"`
	ReplayID                string                        `json:"replayId"`
	Deadline                string                        `json:"deadline,omitempty"`
	OriginalControllerEpoch uint64                        `json:"originalControllerEpoch,string"`
	BindingDigest           [32]byte                      `json:"bindingDigest"`
	CallerFrame             fabric.CallerProofFrame       `json:"callerFrame"`
	CallerSignature         []byte                        `json:"callerSignature"`
	DispatchFrame           fabric.DispatchAdmissionFrame `json:"dispatchFrame"`
	DispatchSignature       []byte                        `json:"dispatchSignature"`
	Witness                 Witness                       `json:"witness"`
	Proof                   registry.AuthorityRecord      `json:"proof"`
}
type Origin struct {
	ID                        string                   `json:"id"`
	Scope                     Scope                    `json:"scope"`
	AdmissionID               string                   `json:"admissionId"`
	AdmissionDigest           [32]byte                 `json:"admissionDigest"`
	OriginalControllerEpoch   uint64                   `json:"originalControllerEpoch,string"`
	RegisteredControllerEpoch uint64                   `json:"registeredControllerEpoch,string"`
	Worker                    WorkerBinding            `json:"worker"`
	NativeGeneration          string                   `json:"nativeGeneration"`
	Witness                   Witness                  `json:"witness"`
	Proof                     registry.AuthorityRecord `json:"proof"`
}

// SourceOutcome carries exact commitments to actual source evidence. It does
// not infer native completion from arbitrary model output, controller EOF or a
// cloud receipt. Trusted native adapters establish this evidence separately.
type SourceOutcome struct {
	OriginID             string             `json:"originId"`
	NativeGeneration     string             `json:"nativeGeneration"`
	NativeSessionID      string             `json:"nativeSessionId"`
	SourceID             string             `json:"sourceId"`
	CiphertextCommitment [32]byte           `json:"ciphertextCommitment"`
	Effect               fabric.EffectState `json:"effect"`
}
type Authority struct {
	store *registry.Store
	root  registry.AuthorityIdentity
	fence AdmissionFence
}

func New(store *registry.Store, fence AdmissionFence) (*Authority, error) {
	if store == nil || fence == nil {
		return nil, invalid("Missing local registry or admission fence")
	}
	root := store.AuthorityIdentity()
	if root.KeyRevision != 1 {
		return nil, invalid("Unsupported local authority key revision")
	}
	return &Authority{store: store, root: root, fence: fence}, nil
}
func (a *Authority) Identity() registry.AuthorityIdentity {
	r := a.root
	r.PublicKey = append([]byte(nil), r.PublicKey...)
	return r
}
func invalid(msg string) error       { return fabric.NewError(fabric.CodeInvalidInput, msg) }
func conflict(msg string) error      { return fabric.NewError(fabric.CodeStaleReference, msg) }
func text(s string) bool             { return s != "" && len(s) <= 256 && utf8.ValidString(s) }
func digest(v any) ([32]byte, error) { raw, e := json.Marshal(v); return sha256.Sum256(raw), e }
func keyID(prefix string, fields ...string) string {
	raw, _ := json.Marshal(fields)
	d := sha256.Sum256(raw)
	return prefix + hex.EncodeToString(d[:])
}
func (s Scope) tx(history bool) registry.AuthorityScope {
	return registry.AuthorityScope{Endpoint: s.Endpoint, ExpectedRevision: s.DescriptorRevision, BindingID: s.BindingID, HistoryOnly: history}
}
func (a *Authority) transact(ctx context.Context, owner fabric.ExecutionContext, s Scope, history bool, fn func(*registry.AuthorityTx) error) error {
	if ctx == nil || s.Endpoint.String() == "" || s.Endpoint.IsOffer() || s.Endpoint.Domain() != a.root.Namespace || s.DescriptorRevision == "" || !text(s.BindingID) {
		return invalid("Incomplete local authority endpoint scope")
	}
	return a.store.WithNativeAuthority(ctx, owner, s.tx(history), fn)
}
func controllerKey(s Scope) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityController, ID: keyID("current:", s.Endpoint.String(), s.BindingID)}
}
func bindingKey(s Scope) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityBinding, Endpoint: s.Endpoint, ID: s.BindingID}
}
func admissionKey(s Scope, id string) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityAdmission, Endpoint: s.Endpoint, ID: id}
}
func originKey(s Scope, id string) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityOrigin, Endpoint: s.Endpoint, ID: id}
}
func exactRecord(tx *registry.AuthorityTx, root registry.AuthorityIdentity, provided registry.AuthorityRecord, key registry.AuthorityKey) (registry.AuthorityRecord, error) {
	if provided.Key != key || registry.VerifyAuthorityRecord(root, provided) != nil {
		return registry.AuthorityRecord{}, invalid("Local authority proof scope or issuer mismatch")
	}
	current, e := tx.Get(key)
	if e != nil {
		return current, e
	}
	p, _ := digest(provided)
	c, _ := digest(current)
	if p != c || current.Retired {
		return current, conflict("Local authority proof stale or retired")
	}
	return current, nil
}
func decodeValue(r registry.AuthorityRecord, out any) error { return fabric.DecodeJSON(r.Value, out) }
func encode(v any) ([]byte, error)                          { return json.Marshal(v) }

// storedValue excludes the outer receipt: that receipt is the signed record
// containing this value, never a recursive placeholder proof on the wire.
func storedValue(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(raw, &fields); e != nil {
		return nil, e
	}
	delete(fields, "proof")
	return json.Marshal(fields)
}

// withFence seals callback lifetime even on a panicking configured adapter.
// All wire ingress must have already passed trusted peer authentication.
func (a *Authority) withFence(ctx context.Context, facts AdmissionFacts, commit func(Witness) error) (err error) {
	if ctx == nil {
		return invalid("Missing local admission context")
	}
	var gate sync.Mutex
	active := true
	calls := 0
	defer func() {
		gate.Lock()
		active = false
		gate.Unlock()
		if recover() != nil {
			err = fabric.NewError(fabric.CodeProtocolError, "Local admission fence panicked")
		}
	}()
	err = a.fence.WithAdmission(ctx, facts, func(w Witness) error {
		gate.Lock()
		defer gate.Unlock()
		if !active {
			return invalid("Local admission fence callback is closed")
		}
		calls++
		if calls != 1 {
			return invalid("Local admission fence attempted multiple commits")
		}
		if e := validWitness(w, facts); e != nil {
			return e
		}
		return commit(w)
	})
	gate.Lock()
	active = false
	if err == nil && calls != 1 {
		err = invalid("Local admission fence did not authorize a commit")
	}
	gate.Unlock()
	if err != nil {
		var typed *fabric.Error
		if !errors.As(err, &typed) {
			return fabric.NewError(fabric.CodeProtocolError, "Local admission fence failed")
		}
	}
	return err
}
