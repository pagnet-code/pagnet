package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"

	"github.com/pagnet-code/pagnet/fabric"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type extensionPlanContextKey struct{}
type extensionPlanSelection struct {
	gate     *extensionPlanGate
	snapshot extregistry.ConfiguredSnapshot
	digest   string
}
type extensionPlanGate struct {
	registry *extregistry.Store
	current  atomic.Pointer[extensionPlanSelection]
}

// SelectedPlanCapture is private infrastructure evidence from the actual stage
// context. It is never a caller-supplied revision or a public response field.
type SelectedPlanCapture struct{ selection *extensionPlanSelection }

func (*SelectedPlanCapture) MarshalJSON() ([]byte, error) { return nil, localDenied() }
func (*SelectedPlanCapture) UnmarshalJSON([]byte) error   { return localDenied() }
func SelectedExtensionPlan(ctx context.Context) (*SelectedPlanCapture, bool) {
	if ctx == nil {
		return nil, false
	}
	p, ok := ctx.Value(extensionPlanContextKey{}).(*extensionPlanSelection)
	if !ok || p == nil || p.gate == nil || p.snapshot.Plan == nil {
		return nil, false
	}
	return &SelectedPlanCapture{p}, true
}
func (p *SelectedPlanCapture) Revision() string {
	if p == nil || p.selection == nil {
		return ""
	}
	return p.selection.snapshot.Plan.Revision()
}
func (p *SelectedPlanCapture) EvidenceDigest() [32]byte {
	if p == nil || p.selection == nil {
		return [32]byte{}
	}
	return sha256.Sum256(p.selection.snapshot.Evidence)
}

// PrivateCheckpoint returns owned exact signed configuration evidence for a
// protected final-output ledger. Its presence grants no new invocation rights.
func (p *SelectedPlanCapture) PrivateCheckpoint() []byte {
	if p == nil || p.selection == nil {
		return nil
	}
	return append([]byte(nil), p.selection.snapshot.Evidence...)
}
func (p *SelectedPlanCapture) VerifyTx(tx *registry.AuthorityTx) error {
	if p == nil || p.selection == nil {
		return localDenied()
	}
	return p.selection.verify(tx)
}

type extensionPlanMarker struct {
	Format      uint32          `json:"format"`
	Underlying  json.RawMessage `json:"underlying"`
	Revision    string          `json:"configuredPlanRevision"`
	EvidenceSHA string          `json:"configuredPlanEvidenceSHA256"`
}

func (g *extensionPlanGate) selection(snapshot extregistry.ConfiguredSnapshot) *extensionPlanSelection {
	h := sha256.Sum256(snapshot.Evidence)
	return &extensionPlanSelection{g, snapshot, hex.EncodeToString(h[:])}
}
func (p *extensionPlanSelection) verify(tx *registry.AuthorityTx) error {
	if p == nil || p.gate == nil || p.snapshot.Plan == nil {
		return localDenied()
	}
	return p.gate.registry.VerifyConfiguredPlanTx(tx, p.snapshot.Plan.Revision(), p.snapshot.Evidence)
}
func (g *extensionPlanGate) fromContext(ctx context.Context) (*extensionPlanSelection, error) {
	p, ok := ctx.Value(extensionPlanContextKey{}).(*extensionPlanSelection)
	if !ok || p == nil || p.gate != g {
		return nil, localDenied()
	}
	return p, nil
}
func (g *extensionPlanGate) witness(ctx context.Context, source *identity.Admission, w identity.Witness, next func(identity.Witness) error) error {
	var p *extensionPlanSelection
	var e error
	if source == nil {
		p, e = g.fromContext(ctx)
		if e != nil {
			return e
		}
	} else {
		var marker extensionPlanMarker
		if fabric.DecodeJSONWithLimits(source.Witness.Value, &marker, fabric.WireLimits{MaxBytes: 16384, MaxDepth: 16, MaxMembers: 512}) != nil || marker.Format != 1 {
			return localDenied()
		}
		p = g.current.Load()
		if p == nil || p.snapshot.Plan.Revision() != marker.Revision || p.digest != marker.EvidenceSHA {
			return fabric.NewError(fabric.CodeStaleContinuation, "Original selected extension plan is stale")
		}
	}
	previous := w.CurrentPlanVerifier
	w.CurrentPlanVerifier = func(tx *registry.AuthorityTx) error {
		if previous != nil {
			if e := previous(tx); e != nil {
				return e
			}
		}
		return p.verify(tx)
	}
	w.Value, e = json.Marshal(extensionPlanMarker{1, w.Value, p.snapshot.Plan.Revision(), p.digest})
	if e != nil {
		return e
	}
	return next(w)
}
func (b *LocalBoundary) selectedPlanWitness(ctx context.Context, source *identity.Admission, w identity.Witness, next func(identity.Witness) error) error {
	if b.planGate == nil {
		return next(w)
	}
	return b.planGate.witness(ctx, source, w, next)
}
func (b *LocalBoundary) verifyExtensionPlanTx(ctx context.Context, tx *registry.AuthorityTx) error {
	if b.planGate == nil {
		return nil
	}
	p, e := b.planGate.fromContext(ctx)
	if e != nil {
		return e
	}
	return p.verify(tx)
}

// Source-specific current disclosure consumes the actual original admitted
// plan marker. Cleanup cancellation deliberately uses its independent stop
// purpose and may retire accepted work after configuration has changed.
func (b *LocalBoundary) CurrentNativeSourceCallerWitness(ctx context.Context, caller fabric.ExecutionContext, f identity.NativeSourceReadFacts) (identity.Witness, error) {
	w, e := b.CurrentNativeCallerWitness(ctx, caller)
	if e != nil {
		return identity.Witness{}, e
	}
	var result identity.Witness
	e = b.selectedPlanWitness(ctx, &f.Admission, w, func(selected identity.Witness) error { result = selected; return nil })
	return result, e
}
