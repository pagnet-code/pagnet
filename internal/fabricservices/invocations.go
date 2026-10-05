package fabricservices

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// InvocationPolicy is trusted current local policy/version validation, not a
// network/provider callback. It must finish under the bounded SAME root TX.
// Subject is the retained original caller; caller is fresh authenticated context.
type InvocationPolicy interface {
	AuthorizeTx(context.Context, *registry.AuthorityTx, fabric.ExecutionContext, InvocationFacts, string) error
}
type InvocationConfig struct {
	MaxInvocations, MaxFrames, MaxBytes uint64
	MaxFramesPerInvocation              uint64
}

func DefaultInvocationConfig() InvocationConfig {
	return InvocationConfig{65536, 262144, 256 << 20, 4096}
}
func validInvocationConfig(c InvocationConfig) bool {
	return c.MaxInvocations > 0 && c.MaxInvocations <= 1<<20 && c.MaxFrames > 0 && c.MaxFrames <= 1<<24 && c.MaxBytes >= 64<<10 && c.MaxBytes <= 1<<40 && c.MaxFramesPerInvocation > 0 && c.MaxFramesPerInvocation <= 1<<16
}

type InvocationFacts struct {
	Principal    fabric.Principal              `json:"principal"`
	InvocationID string                        `json:"invocationId"`
	Target       fabric.EndpointRef            `json:"target"`
	Revision     fabric.Revision               `json:"revision"`
	Scope        registry.DescriptorBatchScope `json:"scope"`
	Fingerprint  [32]byte                      `json:"fingerprint"`
	OriginalSHA  [32]byte                      `json:"originalSha"`
	FinalizedSHA [32]byte                      `json:"finalizedSha"`
	InputSHA     [32]byte                      `json:"inputSha"`
}
type Receipt struct {
	Facts              InvocationFacts               `json:"facts"`
	Dispatch           fabric.DispatchAdmissionFrame `json:"dispatch"`
	Signature          []byte                        `json:"signature"`
	Frames             uint64                        `json:"frames"`
	Terminal           bool                          `json:"terminal"`
	TaskID             string                        `json:"taskId,omitempty"`
	ContextID          string                        `json:"contextId,omitempty"`
	AssociationBinding string                        `json:"associationBinding,omitempty"`
	Operation          string                        `json:"operation,omitempty"`
	Mode               string                        `json:"mode,omitempty"`
}
type invocationState struct {
	Format                     int
	Key                        durable.KeyReference
	Config                     InvocationConfig
	Invocations, Frames, Bytes uint64
}
type Invocations struct {
	profiles *ProfileStore
	policy   InvocationPolicy
	config   InvocationConfig
}

func invocationKey(principal fabric.Principal, id string) string {
	raw, _ := json.Marshal(struct {
		Purpose      string
		Principal    fabric.Principal
		InvocationID string
	}{"pagnet.service.original.v1", principal, id})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func serviceKey(id string) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityServiceInvocation, ID: id}
}
func (i *Invocations) aad(id string) []byte {
	raw, _ := json.Marshal(struct{ Purpose, Domain, Store, ID string }{"pagnet.service.invocation.v1", i.profiles.root.Namespace, i.profiles.root.StoreID, id})
	return raw
}
func (i *Invocations) encode(id string, v any) ([]byte, error) {
	if !boundedValue(v, 32<<10, 2048) {
		return nil, denied()
	}
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 32<<10 {
		return nil, denied()
	}
	defer clear(raw)
	cipher, e := i.profiles.protector.Seal(i.aad(id), raw)
	if e != nil || len(cipher) > 40<<10 {
		return nil, denied()
	}
	out, _ := json.Marshal(struct{ Cipher []byte }{cipher})
	clear(cipher)
	if len(out) > 64<<10 {
		return nil, denied()
	}
	return out, nil
}
func (i *Invocations) decode(tx *registry.AuthorityTx, id string, v any) (registry.AuthorityRecord, error) {
	r, e := tx.Get(serviceKey(id))
	if e != nil {
		return r, e
	}
	if r.Retired || registry.VerifyAuthorityRecord(i.profiles.root, r) != nil || len(r.Value) > 64<<10 {
		return r, denied()
	}
	var box struct{ Cipher []byte }
	if fabric.DecodeJSONWithLimits(r.Value, &box, fabric.WireLimits{MaxBytes: 64 << 10, MaxDepth: 4, MaxMembers: 4}) != nil || len(box.Cipher) > 40<<10 {
		return r, denied()
	}
	raw, e := i.profiles.protector.Open(i.aad(id), box.Cipher)
	if e != nil {
		return r, denied()
	}
	defer clear(raw)
	if fabric.DecodeJSONWithLimits(raw, v, fabric.WireLimits{MaxBytes: 32 << 10, MaxDepth: 32, MaxMembers: 2048}) != nil {
		return r, denied()
	}
	return r, nil
}
func (i *Invocations) state(tx *registry.AuthorityTx) (invocationState, registry.AuthorityRecord, error) {
	var s invocationState
	r, e := i.decode(tx, "configuration", &s)
	if e != nil {
		return s, r, e
	}
	if s.Format != 1 || s.Key != i.profiles.protector.Reference() || s.Config != i.config || s.Invocations > s.Config.MaxInvocations || s.Frames > s.Config.MaxFrames || s.Bytes > s.Config.MaxBytes {
		return s, r, denied()
	}
	return s, r, nil
}
func (i *Invocations) with(ctx context.Context, scope registry.DescriptorBatchScope, fn func(context.Context, *registry.AuthorityTx) error) error {
	if i == nil || ctx == nil {
		return denied()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	owner, e := i.profiles.owner(ctx)
	if e != nil {
		return e
	}
	a := registry.AuthorityScope{Endpoint: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, BindingID: scope.BindingID, MaxOperations: 32, Timeout: 5 * time.Second}
	return i.profiles.store.WithNativeAuthority(ctx, owner, a, func(tx *registry.AuthorityTx) error { return fn(ctx, tx) })
}
func newInvocations(p *ProfileStore, c InvocationConfig, policy InvocationPolicy) (*Invocations, error) {
	if p == nil || !validInvocationConfig(c) || policy == nil {
		return nil, denied()
	}
	return &Invocations{p, policy, c}, nil
}

// Bootstrap is explicit. Missing or changed key/config never opens as a fresh
// replay fence. Shared signed root quotas additionally bound journal growth.
func BootstrapInvocations(ctx context.Context, p *ProfileStore, c InvocationConfig, policy InvocationPolicy) (*Invocations, error) {
	i, e := newInvocations(p, c, policy)
	if e != nil {
		return nil, e
	}
	value, e := i.encode("configuration", invocationState{Format: 1, Key: p.protector.Reference(), Config: c})
	if e != nil {
		return nil, e
	}
	e = i.with(ctx, registry.DescriptorBatchScope{}, func(_ context.Context, tx *registry.AuthorityTx) error {
		if _, e := tx.Get(serviceKey("configuration")); !missing(e) {
			return denied()
		}
		_, e := tx.CAS(serviceKey("configuration"), 0, value, false)
		return e
	})
	if e != nil {
		return nil, e
	}
	return i, nil
}
func OpenInvocations(ctx context.Context, p *ProfileStore, c InvocationConfig, policy InvocationPolicy) (*Invocations, error) {
	i, e := newInvocations(p, c, policy)
	if e != nil {
		return nil, e
	}
	e = i.with(ctx, registry.DescriptorBatchScope{}, func(_ context.Context, tx *registry.AuthorityTx) error { _, _, e := i.state(tx); return e })
	if e != nil {
		return nil, e
	}
	return i, nil
}
func (i *Invocations) original(ctx context.Context, caller fabric.ExecutionContext, scope registry.DescriptorBatchScope, fingerprint [32]byte) (InvocationFacts, fabric.Envelope, []byte, []byte, error) {
	trusted, original, finalized, ok := node.FinalizedRequestFromContext(ctx)
	if !ok || trusted.PrincipalView() != caller.PrincipalView() || trusted.VerifyAuthenticated(i.profiles.root.Namespace) != nil {
		return InvocationFacts{}, fabric.Envelope{}, nil, nil, denied()
	}
	before, e := caller.DecodeVerifiedEnvelope(original, i.profiles.root.Namespace)
	if e != nil {
		return InvocationFacts{}, fabric.Envelope{}, nil, nil, e
	}
	var after fabric.Envelope
	if fabric.DecodeJSON(finalized, &after) != nil || after.Validate() != nil || after.Operation != fabric.OperationInvoke || after.Target == nil || after.ID != before.ID || after.Principal != before.Principal || after.Target.Endpoint() != scope.Endpoint || fingerprint == ([32]byte{}) {
		return InvocationFacts{}, fabric.Envelope{}, nil, nil, denied()
	}
	facts := InvocationFacts{caller.PrincipalView(), after.ID, *after.Target, after.ExpectedRevision, scope, fingerprint, sha256.Sum256(original), sha256.Sum256(finalized), sha256.Sum256(after.Payload)}
	return facts, after, original, finalized, nil
}

// Reserve records the first uncertain effect BEFORE invoking an adapter. The
// full original principal+invocation identity is global, independent of target,
// revision, private account, replay labels or protocol. False never permits send.
func (i *Invocations) Reserve(ctx context.Context, caller fabric.ExecutionContext, scope registry.DescriptorBatchScope, fingerprint [32]byte, request fabric.InvokeRequest) (Receipt, bool, error) {
	facts, env, original, finalized, e := i.original(ctx, caller, scope, fingerprint)
	if e != nil {
		return Receipt{}, false, e
	}
	defer clear(original)
	defer clear(finalized)
	if request.Validate() != nil || request.InvocationID != env.ID || env.Target == nil || request.Target != *env.Target || request.ExpectedRevision != env.ExpectedRevision || !bytes.Equal(request.Input, env.Payload) || request.IdempotencyKey != env.Context.IdempotencyKey || !equalDeadline(request.Deadline, env.Context.Deadline) {
		return Receipt{}, false, denied()
	}
	prepared, e := i.profiles.store.PrepareInvocationTarget(ctx, facts.Target, facts.Revision, env.Payload)
	if e != nil {
		return Receipt{}, false, e
	}
	id := invocationKey(facts.Principal, facts.InvocationID)
	var result Receipt
	fresh := false
	e = i.with(ctx, scope, func(ctx context.Context, tx *registry.AuthorityTx) error {
		s, stateRow, e := i.state(tx)
		if e != nil {
			return e
		}
		var old Receipt
		_, e = i.decode(tx, "invocation/"+id, &old)
		if e == nil {
			if old.Facts != facts {
				return fabric.NewError(fabric.CodeStaleReference, "Original service invocation is pinned to different input or binding")
			}
			if e = i.policy.AuthorizeTx(ctx, tx, caller, old.Facts, "replay"); e != nil {
				return e
			}
			result = old
			return nil
		}
		if !missing(e) {
			return e
		}
		if ctx.Err() != nil || env.Context.Deadline != nil && !time.Now().Before(*env.Context.Deadline) {
			return fabric.NewError(fabric.CodeCancelled, "Service invocation deadline ended")
		}
		p, gen, e := i.profiles.GetTx(tx, scope)
		if e != nil || Fingerprint(scope, p, gen) != fingerprint {
			return denied()
		}
		if e = i.policy.AuthorizeTx(ctx, tx, caller, facts, "reserve"); e != nil {
			return e
		}
		frame := fabric.DispatchAdmissionFrame{SourceDomain: i.profiles.root.Namespace, CallerRef: facts.Principal.Ref, AudienceDomain: i.profiles.root.Namespace, InvocationID: facts.InvocationID, AttemptID: id, ReplayID: id, FinalizedDispatchDigest: facts.FinalizedSHA}
		if env.Context.Deadline != nil {
			frame.Deadline = env.Context.Deadline.UTC().Format(time.RFC3339Nano)
		}
		signature, e := tx.SignDispatchAdmission(caller, original, finalized, frame, prepared)
		if e != nil {
			return e
		}
		r := Receipt{Facts: facts, Dispatch: frame, Signature: signature}
		value, e := i.encode("invocation/"+id, r)
		if e != nil {
			return e
		}
		if s.Invocations >= s.Config.MaxInvocations || uint64(len(value)) > s.Config.MaxBytes-s.Bytes {
			return fabric.NewError(fabric.CodeTargetUnavailable, "Retained service replay capacity exhausted")
		}
		if _, e = tx.CAS(serviceKey("invocation/"+id), 0, value, false); e != nil {
			return e
		}
		s.Invocations++
		s.Bytes += uint64(len(value))
		value, e = i.encode("configuration", s)
		if e != nil {
			return e
		}
		if _, e = tx.CAS(serviceKey("configuration"), stateRow.Revision, value, false); e != nil {
			return e
		}
		result = r
		fresh = true
		return nil
	})
	return result, fresh, e
}
func (i *Invocations) read(ctx context.Context, caller fabric.ExecutionContext, subject fabric.Principal, id string, scope registry.DescriptorBatchScope, action string, fn func(context.Context, *registry.AuthorityTx, Receipt, registry.AuthorityRecord) error) error {
	if caller.VerifyAuthenticated(i.profiles.root.Namespace) != nil {
		return denied()
	}
	trusted, exact, final, ok := node.FinalizedRequestFromContext(ctx)
	defer clear(exact)
	defer clear(final)
	if !ok || trusted.PrincipalView() != caller.PrincipalView() {
		return denied()
	}
	if _, e := caller.DecodeVerifiedEnvelope(exact, i.profiles.root.Namespace); e != nil {
		return e
	}
	return i.with(ctx, scope, func(ctx context.Context, tx *registry.AuthorityTx) error {
		if _, _, e := i.state(tx); e != nil {
			return e
		}
		var r Receipt
		row, e := i.decode(tx, "invocation/"+invocationKey(subject, id), &r)
		if e != nil {
			return e
		}
		if r.Facts.Principal != subject || r.Facts.InvocationID != id || r.Facts.Scope != scope {
			return denied()
		}
		if e = i.policy.AuthorizeTx(ctx, tx, caller, r.Facts, action); e != nil {
			return e
		}
		return fn(ctx, tx, r, row)
	})
}

// Append preserves actual returned frames before delivery, in one FULL commit.
// Large frames are bounded sealed chunks; chunks are never public extra events.
func (i *Invocations) Append(ctx context.Context, caller fabric.ExecutionContext, receipt Receipt, f fabric.InvocationFrame) error {
	if !boundedValue(f, 96<<10, 2048) || f.InvocationID != receipt.Facts.InvocationID || len(f.Data) > fabric.MaxFrameBytes {
		return denied()
	}
	raw, e := json.Marshal(f)
	if e != nil || len(raw) > 96<<10 {
		return denied()
	}
	defer clear(raw)
	id := invocationKey(receipt.Facts.Principal, receipt.Facts.InvocationID)
	frameID := fmt.Sprintf("frame/%s/%d", id, f.Sequence)
	chunks := (len(raw) + (16 << 10) - 1) / (16 << 10)
	values := make([][]byte, chunks)
	for n := 0; n < chunks; n++ {
		end := (n + 1) * (16 << 10)
		if end > len(raw) {
			end = len(raw)
		}
		values[n], e = i.encode(fmt.Sprintf("%s/%d", frameID, n), struct{ Data []byte }{raw[n*(16<<10) : end]})
		if e != nil {
			return e
		}
	}
	return i.read(ctx, caller, receipt.Facts.Principal, receipt.Facts.InvocationID, receipt.Facts.Scope, "append", func(_ context.Context, tx *registry.AuthorityTx, r Receipt, row registry.AuthorityRecord) error {
		if r.Facts != receipt.Facts {
			return denied()
		}
		if f.Sequence < r.Frames {
			old, e := i.frameTx(tx, r, f.Sequence)
			if e != nil {
				return e
			}
			exact, _ := json.Marshal(old)
			defer clear(exact)
			if !bytes.Equal(exact, raw) {
				return denied()
			}
			return nil
		}
		if r.Terminal || f.Sequence != r.Frames || r.Frames >= i.config.MaxFramesPerInvocation {
			return denied()
		}
		if r.Frames == 0 && f.Kind != fabric.FrameStart || r.Frames > 0 && f.Kind == fabric.FrameStart {
			return denied()
		}
		switch f.Kind {
		case fabric.FrameStart, fabric.FrameChunk, fabric.FrameProgress, fabric.FrameComplete, fabric.FrameError:
		default:
			return denied()
		}
		if f.Kind == fabric.FrameStart && len(f.Data) != 0 || f.Kind == fabric.FrameError && len(f.Data) != 0 || f.Kind == fabric.FrameError && f.Error == nil || f.Kind != fabric.FrameError && f.Error != nil {
			return denied()
		}
		s, srow, e := i.state(tx)
		if e != nil {
			return e
		}
		needed := uint64(0)
		for _, v := range values {
			needed += uint64(len(v))
		}
		if s.Frames >= s.Config.MaxFrames || needed > s.Config.MaxBytes-s.Bytes {
			return fabric.NewError(fabric.CodeTargetUnavailable, "Retained service stream capacity exhausted")
		}
		for n, v := range values {
			if _, e = tx.CAS(serviceKey(fmt.Sprintf("%s/%d", frameID, n)), 0, v, false); e != nil {
				return e
			}
		}
		meta, e := i.encode(frameID, struct {
			Chunks int
			Bytes  int
			SHA    [32]byte
		}{chunks, len(raw), sha256.Sum256(raw)})
		if e != nil {
			return e
		}
		if _, e = tx.CAS(serviceKey(frameID), 0, meta, false); e != nil {
			return e
		}
		r.Frames++
		r.Terminal = f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError
		value, e := i.encode("invocation/"+id, r)
		if e != nil {
			return e
		}
		if _, e = tx.CAS(serviceKey("invocation/"+id), row.Revision, value, false); e != nil {
			return e
		}
		s.Frames++
		s.Bytes += needed + uint64(len(meta)) + uint64(len(value))
		if s.Bytes > s.Config.MaxBytes {
			return denied()
		}
		value, e = i.encode("configuration", s)
		if e != nil {
			return e
		}
		_, e = tx.CAS(serviceKey("configuration"), srow.Revision, value, false)
		return e
	})
}

// Frame loads one exact ordinal, never scans history or infers EOF completion.
func (i *Invocations) Frame(ctx context.Context, caller fabric.ExecutionContext, receipt Receipt, ordinal uint64) (fabric.InvocationFrame, error) {
	var f fabric.InvocationFrame
	e := i.read(ctx, caller, receipt.Facts.Principal, receipt.Facts.InvocationID, receipt.Facts.Scope, "pull", func(_ context.Context, tx *registry.AuthorityTx, r Receipt, _ registry.AuthorityRecord) error {
		var e error
		f, e = i.frameTx(tx, r, ordinal)
		return e
	})
	return f, e
}
func (i *Invocations) frameTx(tx *registry.AuthorityTx, r Receipt, ordinal uint64) (fabric.InvocationFrame, error) {
	var f fabric.InvocationFrame
	if ordinal >= r.Frames {
		return f, fabric.NewError(fabric.CodeTargetUnavailable, "Original service frame is not retained yet")
	}
	id := fmt.Sprintf("frame/%s/%d", invocationKey(r.Facts.Principal, r.Facts.InvocationID), ordinal)
	var m struct {
		Chunks int
		Bytes  int
		SHA    [32]byte
	}
	if _, e := i.decode(tx, id, &m); e != nil {
		return f, e
	}
	if m.Chunks < 1 || m.Chunks > 6 || m.Bytes < 1 || m.Bytes > 96<<10 {
		return f, denied()
	}
	var raw bytes.Buffer
	defer func() { clear(raw.Bytes()) }()
	for n := 0; n < m.Chunks; n++ {
		var c struct{ Data []byte }
		if _, e := i.decode(tx, fmt.Sprintf("%s/%d", id, n), &c); e != nil {
			return f, e
		}
		if len(c.Data) > 16<<10 || raw.Len()+len(c.Data) > m.Bytes {
			return f, denied()
		}
		raw.Write(c.Data)
		clear(c.Data)
	}
	if raw.Len() != m.Bytes || sha256.Sum256(raw.Bytes()) != m.SHA || fabric.DecodeJSON(raw.Bytes(), &f) != nil || f.Sequence != ordinal || f.InvocationID != r.Facts.InvocationID {
		return f, denied()
	}
	return f, nil
}

func equalDeadline(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// FindExact is a current-policy lookup, not a new admission or permission to
// retry. Missing and uncertain receipts remain distinct.
func (i *Invocations) FindExact(ctx context.Context, caller fabric.ExecutionContext, scope registry.DescriptorBatchScope, fingerprint [32]byte, request fabric.InvokeRequest) (Receipt, error) {
	facts, env, original, finalized, e := i.original(ctx, caller, scope, fingerprint)
	defer clear(original)
	defer clear(finalized)
	if e != nil {
		return Receipt{}, e
	}
	if request.Validate() != nil || request.InvocationID != env.ID || env.Target == nil || request.Target != *env.Target || request.ExpectedRevision != env.ExpectedRevision || !bytes.Equal(request.Input, env.Payload) || request.IdempotencyKey != env.Context.IdempotencyKey || !equalDeadline(request.Deadline, env.Context.Deadline) {
		return Receipt{}, denied()
	}
	var out Receipt
	e = i.read(ctx, caller, facts.Principal, facts.InvocationID, scope, "replay", func(_ context.Context, _ *registry.AuthorityTx, r Receipt, _ registry.AuthorityRecord) error {
		if r.Facts != facts {
			return denied()
		}
		out = r
		return nil
	})
	return out, e
}
