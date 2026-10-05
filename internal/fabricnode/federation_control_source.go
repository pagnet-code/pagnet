package fabricnode

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricfederation"
)

// SourceControlGate binds a fresh exact control proof to actual source kernel
// authentication and current bilateral pins. Old paid receipts cannot sign it.
type SourceControlGate struct {
	peers         *fabricfederation.PeerGate
	sessions      *fabricauth.Authority
	caller        fabric.ExecutionContext
	local, remote federation.PeerBinding
}
type sourceControlFactsKey struct{}
type sourceControlFacts struct {
	gate  *SourceControlGate
	facts fabricauth.CurrentCallerFacts
}

func NewSourceControlGate(p *fabricfederation.PeerGate, a *fabricauth.Authority, c fabric.ExecutionContext, local, remote federation.PeerBinding) (*SourceControlGate, error) {
	if p == nil || a == nil || c.AuthenticationEvidence() == nil || c.VerifyAuthenticated(local.Authority.Namespace) != nil {
		return nil, localDenied()
	}
	return &SourceControlGate{p, a, c, local, remote}, nil
}
func (g *SourceControlGate) valid(f registry.ControlFacts) error {
	raw, e := f.Frame.SigningBytes()
	if e != nil {
		return e
	}
	x := f.Frame
	if x.SourceDomain != g.local.Authority.Namespace || x.SourceStoreID != g.local.Authority.StoreID || x.SourceKeyRevision != g.local.Authority.KeyRevision || x.DestinationDomain != g.remote.Authority.Namespace || x.DestinationStoreID != g.remote.Authority.StoreID || x.SourcePeerBindingDigest != g.local.BindingDigest || x.DestinationPeerBindingDigest != g.remote.BindingDigest || x.Principal != g.caller.PrincipalView() || g.caller.VerifyAuthenticatedData(raw, g.local.Authority.Namespace) != nil {
		return localDenied()
	}
	return nil
}
func (g *SourceControlGate) WithControl(ctx context.Context, f registry.ControlFacts, next func(context.Context) error) error {
	if g == nil || next == nil {
		return localDenied()
	}
	if e := g.valid(f); e != nil {
		return e
	}
	return g.sessions.WithCurrentFacts(ctx, g.caller, func(ctx context.Context, facts fabricauth.CurrentCallerFacts) error {
		if facts.Principal != g.caller.PrincipalView() || !g.sessions.AssociationOpen(g.caller) {
			return localDenied()
		}
		// Current peer operator gate is independent of the later root SQL fence.
		if e := g.peers.WithCurrent(ctx, g.local, g.remote, func(context.Context) error { return nil }); e != nil {
			return e
		}
		return next(context.WithValue(ctx, sourceControlFactsKey{}, sourceControlFacts{g, facts}))
	})
}
func (g *SourceControlGate) CheckControlTx(ctx context.Context, tx *registry.AuthorityTx, f registry.ControlFacts) error {
	facts, ok := ctx.Value(sourceControlFactsKey{}).(sourceControlFacts)
	if !ok || facts.gate != g || facts.facts.Principal != g.caller.PrincipalView() || !g.sessions.AssociationOpen(g.caller) {
		return localDenied()
	}
	if e := g.valid(f); e != nil {
		return e
	}
	return g.peers.WithCurrentTx(ctx, tx, g.local, g.remote, func(context.Context) error {
		if facts.facts.Managed != nil {
			if e := tx.VerifyCurrentNativeCaller(facts.facts.Managed.Authority); e != nil {
				return e
			}
		}
		if facts.facts.Hosted != nil {
			if e := facts.facts.Hosted.VerifyTx(tx); e != nil {
				return e
			}
		}
		if !g.sessions.AssociationOpen(g.caller) {
			return localDenied()
		}
		return nil
	})
}
