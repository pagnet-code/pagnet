package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

// FinalOutputs retains final node-pipeline projections, never raw SDK output.
// Attempt markers commit BEFORE outer Next/hooks. An unresolved marker is an
// honest unknown result and MUST NOT be replayed through nondeterministic hooks.
// This infrastructure does not authenticate callers or admit endpoint effects.
type FinalOutputs struct {
	boundary  *RemoteBoundary
	ledger    *fabricservices.Invocations
	native    *fabricnative.Adapter
	protector durable.DataProtector
	mu        sync.Mutex
	active    map[string]bool
}
type FinalOutputLimits struct {
	MaxSources uint64
	MaxBytes   uint64
	MaxFrames  uint64
}

var DefaultFinalOutputLimits = FinalOutputLimits{64, 64 << 20, 4096}

type finalOutputState struct {
	Version        uint32
	Key            durable.KeyReference
	Limits         FinalOutputLimits
	Sources, Bytes uint64
}
type finalOutputHead struct {
	Version                         uint32
	Principal                       fabric.Principal
	InvocationID                    string
	OriginalSHA                     [32]byte
	BundleDigest                    [32]byte
	FinalizedSHA                    [32]byte
	Source                          *fabricservices.SourceReference
	NativeSource                    *fabricnative.SourceReference
	Target                          *fabric.EndpointRef `json:",omitempty"`
	Revision                        fabric.Revision
	BindingID                       string
	Facts                           *fabricservices.InvocationFacts
	PlanRevision, PlanDigest        string
	Frames                          uint64
	Attempted, Terminal, Incomplete bool
	LastDigest                      [32]byte
}
type finalOutputCipher struct {
	Version uint32
	Key     durable.KeyReference
	Cipher  []byte
}
type finalOutputFrame struct {
	Parts  uint32
	Digest [32]byte
}

func finalOutputKey(id string) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityFederationInvocation, ID: "final-output/" + id}
}
func finalOutputID(p fabric.Principal, id string) string {
	raw, _ := json.Marshal(struct {
		P  fabric.Principal
		ID string
	}{p, id})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func (f *FinalOutputs) aad(id string) []byte {
	raw, _ := json.Marshal(struct {
		Purpose, Domain, Store, ID string
		Key                        durable.KeyReference
	}{"pagnet.final-output.v1", f.boundary.local.root.Namespace, f.boundary.local.root.StoreID, id, f.protector.Reference()})
	return raw
}
func (f *FinalOutputs) encode(id string, v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 32<<10 {
		return nil, localDenied()
	}
	defer clear(raw)
	cipher, e := f.protector.Seal(f.aad(id), raw)
	if e != nil {
		return nil, e
	}
	defer clear(cipher)
	out, e := json.Marshal(finalOutputCipher{1, f.protector.Reference(), cipher})
	if e != nil || len(out) > 64<<10 {
		return nil, localDenied()
	}
	return out, nil
}
func (f *FinalOutputs) read(tx *registry.AuthorityTx, id string, out any) (registry.AuthorityRecord, error) {
	r, e := tx.Get(finalOutputKey(id))
	if e != nil {
		return r, e
	}
	if r.Retired || registry.VerifyAuthorityRecord(f.boundary.local.root, r) != nil || len(r.Value) > 64<<10 {
		return r, localDenied()
	}
	var cipher finalOutputCipher
	if fabric.DecodeJSONWithLimits(r.Value, &cipher, fabric.WireLimits{MaxBytes: 64 << 10, MaxDepth: 8, MaxMembers: 32}) != nil || cipher.Version != 1 || cipher.Key != f.protector.Reference() {
		return r, localDenied()
	}
	raw, e := f.protector.Open(f.aad(id), cipher.Cipher)
	if e != nil {
		return r, e
	}
	defer clear(raw)
	if fabric.DecodeJSONWithLimits(raw, out, fabric.WireLimits{MaxBytes: 32 << 10, MaxDepth: 24, MaxMembers: 2048}) != nil {
		return r, localDenied()
	}
	return r, nil
}
func (f *FinalOutputs) cas(tx *registry.AuthorityTx, id string, rev uint64, value any) (int, error) {
	raw, e := f.encode(id, value)
	if e != nil {
		return 0, e
	}
	defer clear(raw)
	_, e = tx.CAS(finalOutputKey(id), rev, raw, false)
	return len(raw), e
}
func (f *FinalOutputs) with(ctx context.Context, next func(*registry.AuthorityTx) error) error {
	return f.withScope(ctx, registry.AuthorityScope{}, next)
}
func (f *FinalOutputs) withScope(ctx context.Context, scope registry.AuthorityScope, next func(*registry.AuthorityTx) error) error {
	owner := f.boundary.local.owner
	return f.boundary.local.operatorCurrent(ctx, owner, func(current context.Context) error {
		return f.boundary.local.store.WithNativeAuthority(current, owner, scope, next)
	})
}
func newFinalOutputs(b *RemoteBoundary, l *fabricservices.Invocations, p durable.DataProtector) (*FinalOutputs, error) {
	return newFinalOutputsWithNative(b, l, nil, p)
}
func newFinalOutputsWithNative(b *RemoteBoundary, l *fabricservices.Invocations, n *fabricnative.Adapter, p durable.DataProtector) (*FinalOutputs, error) {
	if b == nil || (l == nil && n == nil) || p == nil || p.Reference().ID == "" || p.Reference().Version == "" {
		return nil, localDenied()
	}
	return &FinalOutputs{boundary: b, ledger: l, native: n, protector: p, active: map[string]bool{}}, nil
}
func BootstrapFinalOutputs(ctx context.Context, b *RemoteBoundary, l *fabricservices.Invocations, p durable.DataProtector, limits FinalOutputLimits) (*FinalOutputs, error) {
	return bootstrapFinalOutputs(ctx, b, l, nil, p, limits)
}
func BootstrapNativeFinalOutputs(ctx context.Context, b *RemoteBoundary, n *fabricnative.Adapter, p durable.DataProtector, limits FinalOutputLimits) (*FinalOutputs, error) {
	return bootstrapFinalOutputs(ctx, b, nil, n, p, limits)
}
func bootstrapFinalOutputs(ctx context.Context, b *RemoteBoundary, l *fabricservices.Invocations, n *fabricnative.Adapter, p durable.DataProtector, limits FinalOutputLimits) (*FinalOutputs, error) {
	if limits.MaxSources < 1 || limits.MaxSources > 256 || limits.MaxBytes < 4096 || limits.MaxBytes > 1<<30 || limits.MaxFrames < 1 || limits.MaxFrames > 65536 {
		return nil, localDenied()
	}
	f, e := newFinalOutputsWithNative(b, l, n, p)
	if e != nil {
		return nil, e
	}
	e = f.with(ctx, func(tx *registry.AuthorityTx) error {
		if _, e := tx.Get(finalOutputKey("configuration")); e == nil {
			return fabric.NewError(fabric.CodeStaleReference, "Final output configuration already exists")
		} else {
			var x *fabric.Error
			if !errors.As(e, &x) || x.Code != fabric.CodeNotFound {
				return e
			}
		}
		_, e := f.cas(tx, "configuration", 0, finalOutputState{Version: 1, Key: p.Reference(), Limits: limits})
		return e
	})
	if e != nil {
		return nil, e
	}
	return f, nil
}
func OpenFinalOutputs(ctx context.Context, b *RemoteBoundary, l *fabricservices.Invocations, p durable.DataProtector) (*FinalOutputs, error) {
	return openFinalOutputs(ctx, b, l, nil, p)
}

func OpenNativeFinalOutputs(ctx context.Context, b *RemoteBoundary, n *fabricnative.Adapter, p durable.DataProtector) (*FinalOutputs, error) {
	return openFinalOutputs(ctx, b, nil, n, p)
}

func openFinalOutputs(ctx context.Context, b *RemoteBoundary, l *fabricservices.Invocations, n *fabricnative.Adapter, p durable.DataProtector) (*FinalOutputs, error) {
	f, e := newFinalOutputsWithNative(b, l, n, p)
	if e != nil {
		return nil, e
	}
	e = f.with(ctx, func(tx *registry.AuthorityTx) error { _, _, e := f.state(tx); return e })
	if e != nil {
		return nil, e
	}
	return f, nil
}
func (f *FinalOutputs) state(tx *registry.AuthorityTx) (registry.AuthorityRecord, finalOutputState, error) {
	var s finalOutputState
	r, e := f.read(tx, "configuration", &s)
	if e == nil && (s.Version != 1 || s.Key != f.protector.Reference() || s.Limits.MaxSources < 1 || s.Limits.MaxSources > 256 || s.Limits.MaxBytes < 4096 || s.Limits.MaxBytes > 1<<30 || s.Limits.MaxFrames < 1 || s.Limits.MaxFrames > 65536 || s.Sources > s.Limits.MaxSources || s.Bytes > s.Limits.MaxBytes) {
		e = localDenied()
	}
	return r, s, e
}
func (f *FinalOutputs) charge(tx *registry.AuthorityTx, row registry.AuthorityRecord, state finalOutputState, n int) error {
	if n < 0 || uint64(n) > state.Limits.MaxBytes-state.Bytes {
		return fabric.NewError(fabric.CodeTargetUnavailable, "Final output retention budget exhausted")
	}
	state.Bytes += uint64(n)
	_, e := f.cas(tx, "configuration", row.Revision, state)
	return e
}

// Reserve commits a finite initial execution/transform attempt BEFORE node
// execution. Existing ID, whether ambiguous or complete, never authorizes resend.
func (f *FinalOutputs) Reserve(ctx context.Context, principal fabric.Principal, invocation string, original []byte, bundleDigest [32]byte) (bool, error) {
	var env fabric.Envelope
	if bundleDigest == ([32]byte{}) {
		return false, localDenied()
	}
	if fabric.DecodeJSON(original, &env) != nil || env.Validate() != nil || env.Principal != principal || env.ID != invocation || env.Operation != fabric.OperationInvoke {
		return false, localDenied()
	}
	id := finalOutputID(principal, invocation)
	fresh := false
	e := f.with(ctx, func(tx *registry.AuthorityTx) error {
		row, s, e := f.state(tx)
		if e != nil {
			return e
		}
		var head finalOutputHead
		if _, e = f.read(tx, id, &head); e == nil {
			if head.BundleDigest != bundleDigest || head.OriginalSHA != sha256.Sum256(original) || head.Principal != principal || head.InvocationID != invocation {
				return localDenied()
			}
			return nil
		} else {
			var x *fabric.Error
			if !errors.As(e, &x) || x.Code != fabric.CodeNotFound {
				return e
			}
		}
		if s.Sources >= s.Limits.MaxSources {
			return fabric.NewError(fabric.CodeTargetUnavailable, "Final output source capacity exhausted")
		}
		n, e := f.cas(tx, id, 0, finalOutputHead{Version: 1, Principal: principal, InvocationID: invocation, OriginalSHA: sha256.Sum256(original), BundleDigest: bundleDigest, Attempted: true})
		if e != nil {
			return e
		}
		s.Sources++
		if e = f.charge(tx, row, s, n); e != nil {
			return e
		}
		fresh = true
		return nil
	})
	return fresh, e
}

// capture binds the actual original paid receipt and its engine-finalized
// request/selected plan BEFORE consuming the first outer frame. No interface or
// claimed protocol label can mint the real service ownership capability.
func (f *FinalOutputs) capture(ctx context.Context, owner *fabricservices.OriginalCaptureOwnership) error {
	facts, e := owner.Facts()
	if e != nil {
		return e
	}
	ref, e := owner.Reference()
	if e != nil {
		return e
	}
	caller, original, final, ok := node.FinalizedRequestFromContext(ctx)
	if !ok || caller.PrincipalView() != facts.Principal || sha256.Sum256(original) != facts.OriginalSHA || sha256.Sum256(final) != facts.FinalizedSHA {
		return localDenied()
	}
	revision, digest := "", ""
	var plan *extensionPlanSelection
	if f.boundary.local.planGate != nil {
		plan, e = f.boundary.local.planGate.fromContext(ctx)
		if e != nil {
			return e
		}
		revision = plan.snapshot.Plan.Revision()
		digest = plan.digest
	}
	return f.with(ctx, func(tx *registry.AuthorityTx) error {
		if e = f.ledger.VerifyOriginalCaptureTx(ctx, tx, owner); e != nil {
			return e
		}
		if plan != nil {
			if e = plan.verify(tx); e != nil {
				return e
			}
		}
		id := finalOutputID(facts.Principal, facts.InvocationID)
		var h finalOutputHead
		row, e := f.read(tx, id, &h)
		if e != nil {
			return e
		}
		if h.Version != 1 || h.Principal != facts.Principal || h.InvocationID != facts.InvocationID || h.OriginalSHA != facts.OriginalSHA || h.Source != nil || !h.Attempted {
			return localDenied()
		}
		h.Source = &ref
		h.Facts = &facts
		h.Target = &facts.Target
		h.Revision = facts.Revision
		h.BindingID = facts.Scope.BindingID
		h.FinalizedSHA = facts.FinalizedSHA
		h.PlanRevision = revision
		h.PlanDigest = digest
		h.Attempted = false
		cfg, s, e := f.state(tx)
		if e != nil {
			return e
		}
		n, e := f.cas(tx, id, row.Revision, h)
		if e != nil {
			return e
		}
		return f.charge(tx, cfg, s, n)
	})
}
func (f *FinalOutputs) step(ctx context.Context, p fabric.Principal, invocation string, frame *fabric.InvocationFrame, incomplete bool) error {
	return f.with(ctx, func(tx *registry.AuthorityTx) error {
		cfg, s, e := f.state(tx)
		if e != nil {
			return e
		}
		id := finalOutputID(p, invocation)
		var h finalOutputHead
		row, e := f.read(tx, id, &h)
		if e != nil {
			return e
		}
		if (h.Source == nil && h.NativeSource == nil) || h.Principal != p || h.InvocationID != invocation || h.Terminal || h.Incomplete {
			return localDenied()
		}
		charge := 0
		if frame == nil {
			if h.Attempted {
				return &fabric.Error{Code: "federation.FINALIZATION_UNKNOWN", Message: "Original output finalization was attempted; its result is unknown", Effect: fabric.EffectUnknown}
			}
			h.Attempted = true
		} else {
			if !h.Attempted || frame.InvocationID != h.InvocationID || frame.Sequence != h.Frames || h.Frames >= s.Limits.MaxFrames || len(frame.Data) > fabric.MaxFrameBytes {
				return localDenied()
			}
			if h.Frames == 0 && frame.Kind != fabric.FrameStart || h.Frames > 0 && frame.Kind == fabric.FrameStart {
				return localDenied()
			}
			raw, e := json.Marshal(frame)
			if e != nil || len(raw) > 128<<10 {
				return localDenied()
			}
			defer clear(raw)
			prefix := id + "/frame/" + hex.EncodeToString([]byte(fmtUint(frame.Sequence)))
			parts := (len(raw) + (22 << 10) - 1) / (22 << 10)
			for n := 0; n < parts; n++ {
				end := (n + 1) * (22 << 10)
				if end > len(raw) {
					end = len(raw)
				}
				size, e := f.cas(tx, prefix+"/"+fmtUint(uint64(n)), 0, raw[n*(22<<10):end])
				if e != nil {
					return e
				}
				charge += size
			}
			size, e := f.cas(tx, prefix, 0, finalOutputFrame{uint32(parts), sha256.Sum256(raw)})
			if e != nil {
				return e
			}
			charge += size
			h.Attempted = false
			h.Frames++
			h.LastDigest = sha256.Sum256(raw)
			h.Terminal = frame.Kind == fabric.FrameComplete || frame.Kind == fabric.FrameError
		}
		if incomplete {
			h.Incomplete = true
		}
		n, e := f.cas(tx, id, row.Revision, h)
		if e != nil {
			return e
		}
		return f.charge(tx, cfg, s, charge+n)
	})
}
func fmtUint(n uint64) string { return strconv.FormatUint(n, 10) }

// Drain consumes the genuine FINAL outer pipeline once. It does not take over
// by reading beneath interceptors or reapplying hooks on resumed raw history.
func (f *FinalOutputs) Drain(ctx context.Context, stream fabric.InvocationStream) error {
	return f.DrainWithSource(ctx, stream, nil)
}

func (f *FinalOutputs) DrainWithSource(ctx context.Context, stream fabric.InvocationStream, bound func(FinalOutputReference) error) error {
	if f == nil || ctx == nil || stream == nil {
		return localDenied()
	}
	ownership, e := fabric.OriginalStreamOwnership(ctx, stream)
	if e != nil {
		return e
	}
	var principal fabric.Principal
	var invocation string
	var captureSource func(context.Context) error
	switch owner := ownership.(type) {
	case *fabricservices.OriginalCaptureOwnership:
		if f.ledger == nil {
			return fabric.NewError(fabric.CodeUnsupported, "Selected service original capture unavailable")
		}
		facts, err := owner.Facts()
		if err != nil {
			return err
		}
		principal, invocation = facts.Principal, facts.InvocationID
		captureSource = func(c context.Context) error { return f.capture(c, owner) }
	case *fabricnative.OriginalCaptureOwnership:
		if f.native == nil {
			return fabric.NewError(fabric.CodeUnsupported, "Selected native original capture unavailable")
		}
		checkpoint, err := owner.Checkpoint()
		if err != nil {
			return err
		}
		principal, invocation = checkpoint.Admission.OriginalCaller, checkpoint.Admission.InvocationID
		captureSource = func(c context.Context) error { return f.captureNative(c, owner) }
	default:
		return fabric.NewError(fabric.CodeUnsupported, "Final source capture adapter unavailable")
	}
	id := finalOutputID(principal, invocation)
	f.mu.Lock()
	if f.active[id] {
		f.mu.Unlock()
		return localDenied()
	}
	f.active[id] = true
	f.mu.Unlock()
	defer func() { f.mu.Lock(); delete(f.active, id); f.mu.Unlock() }()
	defer func() { _ = ownership.Close(); _ = stream.Close() }()
	return fabric.WithOriginalSourceCapture(ctx, stream, func(capture context.Context) error {
		if e = captureSource(capture); e != nil {
			return e
		}
		if bound != nil {
			ref, err := f.Reference(ctx, principal, invocation)
			if err != nil {
				return err
			}
			if err = bound(ref); err != nil {
				return err
			}
		}
		for {
			if e = f.step(ctx, principal, invocation, nil, false); e != nil {
				return e
			}
			frame, e := stream.Next(capture)
			if e != nil {
				// Keep the already committed unresolved transform marker. Neither EOF,
				// disconnect nor callback failure fabricates a final frame or a retry.
				if errors.Is(e, io.EOF) {
					return &fabric.Error{Code: "federation.FINALIZATION_UNKNOWN", Message: "Original final pipeline ended without committed completion", Effect: fabric.EffectUnknown}
				}
				return e
			}
			if e = f.step(ctx, principal, invocation, &frame, false); e != nil {
				return e
			}
			if frame.Kind == fabric.FrameComplete || frame.Kind == fabric.FrameError {
				return nil
			}
		}
	})
}

// FinalOutputReference is encrypted private association metadata, not current
// authority. Its immutable digest includes original source and selected plan.
type FinalOutputReference struct {
	Version      uint32
	Principal    fabric.Principal `json:"-"`
	InvocationID string           `json:"-"`
	SourceKey    string           `json:"sourceKey"`
	Commitment   [32]byte
}

func finalOutputCommitment(h finalOutputHead) [32]byte {
	h.Frames = 0
	h.Attempted = false
	h.Terminal = false
	h.Incomplete = false
	h.LastDigest = [32]byte{}
	raw, _ := json.Marshal(h)
	return sha256.Sum256(raw)
}
func (f *FinalOutputs) Reference(ctx context.Context, p fabric.Principal, id string) (FinalOutputReference, error) {
	var ref FinalOutputReference
	e := f.with(ctx, func(tx *registry.AuthorityTx) error {
		var h finalOutputHead
		if _, e := f.read(tx, finalOutputID(p, id), &h); e != nil {
			return e
		}
		if h.Source == nil && h.NativeSource == nil {
			return localDenied()
		}
		ref = FinalOutputReference{Version: 1, Principal: p, InvocationID: id, SourceKey: finalOutputID(p, id), Commitment: finalOutputCommitment(h)}
		return nil
	})
	return ref, e
}
func (f *FinalOutputs) currentPlanTx(tx *registry.AuthorityTx, h finalOutputHead) error {
	gate := f.boundary.local.planGate
	if gate == nil {
		if h.PlanRevision != "" || h.PlanDigest != "" {
			return localDenied()
		}
		return nil
	}
	p := gate.current.Load()
	if p == nil || p.snapshot.Plan.Revision() != h.PlanRevision || p.digest != h.PlanDigest {
		return fabric.NewError(fabric.CodeStaleReference, "Original final output plan is no longer current")
	}
	return p.verify(tx)
}

// Frame returns only a persisted FINAL projection, never raw SDK frames and
// never a reexecuted transformer. Unknown/incomplete tails are explicit errors.
func (f *FinalOutputs) Frame(ctx context.Context, caller fabric.ExecutionContext, ref FinalOutputReference, ordinal uint64) (fabric.InvocationFrame, error) {
	var frame fabric.InvocationFrame
	if f == nil || ref.Version != 1 || ref.Principal.Ref == "" || ref.Principal.Issuer == "" || ref.InvocationID == "" || len(ref.InvocationID) > 256 || ref.Commitment == ([32]byte{}) {
		return frame, localDenied()
	}
	id := finalOutputID(ref.Principal, ref.InvocationID)
	if ref.SourceKey != id {
		return frame, localDenied()
	}
	var head finalOutputHead
	if e := f.with(ctx, func(tx *registry.AuthorityTx) error { _, e := f.read(tx, id, &head); return e }); e != nil {
		return frame, e
	}
	request, e := f.boundary.binding(caller)
	if e != nil || request.control == nil || request.control.OriginalPrincipal != ref.Principal || request.control.InvocationID != ref.InvocationID || request.control.ReceiptDigest != head.BundleDigest {
		return frame, localDenied()
	}
	if (head.Source == nil && head.NativeSource == nil) || finalOutputCommitment(head) != ref.Commitment {
		return frame, localDenied()
	}
	var sourceVerify func(*registry.AuthorityTx) error
	verificationScope := registry.AuthorityScope{}
	if head.Source != nil && head.NativeSource == nil && f.ledger != nil {
		source, err := f.ledger.OpenRetainedSource(ctx, caller, *head.Source)
		if err != nil {
			return frame, err
		}
		defer source.Close()
		sourceVerify = func(tx *registry.AuthorityTx) error { return source.VerifyReferenceTx(ctx, tx, caller) }
	} else if head.NativeSource != nil && head.Source == nil && f.native != nil {
		source, err := f.native.OpenRetainedSource(ctx, caller, *head.NativeSource)
		if err != nil {
			return frame, err
		}
		defer source.Close()
		verifier, err := source.PrepareReferenceVerifier(ctx, caller)
		if err != nil {
			return frame, err
		}
		sourceVerify = verifier.VerifyTx
		scope := verifier.Scope()
		verificationScope = registry.AuthorityScope{Endpoint: scope.Endpoint, ExpectedRevision: scope.DescriptorRevision, BindingID: scope.BindingID}
	} else {
		return frame, localDenied()
	}
	e = f.withScope(ctx, verificationScope, func(tx *registry.AuthorityTx) error {
		var h finalOutputHead
		if _, e := f.read(tx, id, &h); e != nil {
			return e
		}
		if h.Principal != ref.Principal || h.InvocationID != ref.InvocationID || (h.Source == nil && h.NativeSource == nil) || finalOutputCommitment(h) != ref.Commitment {
			return localDenied()
		}
		if e := sourceVerify(tx); e != nil {
			return e
		}
		if h.Target == nil {
			return localDenied()
		}
		if e := f.boundary.checkTx(ctx, tx, caller, *h.Target, h.Revision, h.BindingID); e != nil {
			return e
		}
		if e := f.currentPlanTx(tx, h); e != nil {
			return e
		}
		if ordinal >= h.Frames {
			if h.Attempted || h.Incomplete {
				return &fabric.Error{Code: "federation.FINALIZATION_UNKNOWN", Message: "Original output finalization is incomplete; it cannot be rerun", Effect: fabric.EffectUnknown}
			}
			if h.Terminal {
				return io.EOF
			}
			return fabric.NewError(fabric.CodeTargetUnavailable, "Original final output is not ready")
		}
		prefix := id + "/frame/" + hex.EncodeToString([]byte(fmtUint(ordinal)))
		var meta finalOutputFrame
		if _, e := f.read(tx, prefix, &meta); e != nil {
			return e
		}
		if meta.Parts < 1 || meta.Parts > 6 || meta.Digest == ([32]byte{}) {
			return localDenied()
		}
		var raw []byte
		defer func() { clear(raw) }()
		for n := uint32(0); n < meta.Parts; n++ {
			var part []byte
			if _, e := f.read(tx, prefix+"/"+fmtUint(uint64(n)), &part); e != nil {
				return e
			}
			if len(part) == 0 || len(part) > 22<<10 || len(raw)+len(part) > 128<<10 {
				clear(part)
				return localDenied()
			}
			raw = append(raw, part...)
			clear(part)
		}
		if sha256.Sum256(raw) != meta.Digest || fabric.DecodeJSONWithLimits(raw, &frame, fabric.WireLimits{MaxBytes: 128 << 10, MaxDepth: 16, MaxMembers: 512}) != nil || frame.InvocationID != h.InvocationID || frame.Sequence != ordinal || len(frame.Data) > fabric.MaxFrameBytes {
			return localDenied()
		}
		return nil
	})
	return frame, e
}

func (f *FinalOutputs) captureNative(ctx context.Context, owner *fabricnative.OriginalCaptureOwnership) error {
	checkpoint, err := owner.Checkpoint()
	if err != nil {
		return err
	}
	ref, err := owner.Reference()
	if err != nil {
		return err
	}
	source := checkpoint.Admission
	caller, original, final, ok := node.FinalizedRequestFromContext(ctx)
	if !ok || caller.PrincipalView() != source.OriginalCaller || sha256.Sum256(original) != source.OriginalDigest || sha256.Sum256(final) != source.FinalizedDigest {
		return localDenied()
	}
	revision, digest := "", ""
	var plan *extensionPlanSelection
	if f.boundary.local.planGate != nil {
		plan, err = f.boundary.local.planGate.fromContext(ctx)
		if err != nil {
			return err
		}
		revision = plan.snapshot.Plan.Revision()
		digest = plan.digest
	}
	return f.withScope(ctx, registry.AuthorityScope{Endpoint: source.Scope.Endpoint, ExpectedRevision: source.Scope.DescriptorRevision, BindingID: source.Scope.BindingID}, func(tx *registry.AuthorityTx) error {
		if err = f.native.VerifyOriginalCaptureTx(ctx, tx, owner); err != nil {
			return err
		}
		if plan != nil {
			if err = plan.verify(tx); err != nil {
				return err
			}
		}
		id := finalOutputID(source.OriginalCaller, source.InvocationID)
		var h finalOutputHead
		row, err := f.read(tx, id, &h)
		if err != nil {
			return err
		}
		if h.Version != 1 || h.Principal != source.OriginalCaller || h.InvocationID != source.InvocationID || h.OriginalSHA != source.OriginalDigest || h.Source != nil || h.NativeSource != nil || !h.Attempted {
			return localDenied()
		}
		h.NativeSource = &ref
		h.Target = &source.Target
		h.Revision = source.TargetRevision
		h.BindingID = source.Scope.BindingID
		h.FinalizedSHA = source.FinalizedDigest
		h.PlanRevision = revision
		h.PlanDigest = digest
		h.Attempted = false
		cfg, state, err := f.state(tx)
		if err != nil {
			return err
		}
		n, err := f.cas(tx, id, row.Revision, h)
		if err != nil {
			return err
		}
		return f.charge(tx, cfg, state, n)
	})
}
