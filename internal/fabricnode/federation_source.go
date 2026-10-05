package fabricnode

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricfederation"
)

// SourceForwardGate verifies actual current kernel source evidence before the
// closed retained root signer. Peer pinning alone never authenticates a caller.
// Managed retirement is rechecked in the SAME signing transaction. No peer SQL
// or Session.mu is held recursively across signing/provider work.
type SourceForwardGate struct {
	peers    *fabricfederation.PeerGate
	sessions *fabricauth.Authority
	caller   fabric.ExecutionContext
}

// NewSourceForwardGate selects actual immutable composition ports, not wire
// assertions. Each signing operation still rechecks current kernel evidence.
func NewSourceForwardGate(peers *fabricfederation.PeerGate, sessions *fabricauth.Authority, caller fabric.ExecutionContext) (*SourceForwardGate, error) {
	if peers == nil || sessions == nil || caller.AuthenticationEvidence() == nil {
		return nil, localDenied()
	}
	return &SourceForwardGate{peers: peers, sessions: sessions, caller: caller}, nil
}

type sourceForwardFactsKey struct{}
type sourceForwardFacts struct {
	gate  *SourceForwardGate
	facts fabricauth.CurrentCallerFacts
}

func (g *SourceForwardGate) WithForward(ctx context.Context, f registry.ForwardFacts, next func(context.Context) error) error {
	if g == nil || g.peers == nil || g.sessions == nil || next == nil || g.caller.PrincipalView() != f.Frame.Principal || g.caller.VerifyAuthenticatedData(f.Original, f.Frame.SourceDomain) != nil {
		return localDenied()
	}
	return g.sessions.WithCurrentFacts(ctx, g.caller, func(ctx context.Context, facts fabricauth.CurrentCallerFacts) error {
		if facts.Principal != f.Frame.Principal || !g.sessions.AssociationOpen(g.caller) {
			return localDenied()
		}
		return g.peers.WithForward(context.WithValue(ctx, sourceForwardFactsKey{}, sourceForwardFacts{g, facts}), f, next)
	})
}
func (g *SourceForwardGate) CheckForwardTx(ctx context.Context, tx *registry.AuthorityTx, f registry.ForwardFacts) error {
	source, ok := ctx.Value(sourceForwardFactsKey{}).(sourceForwardFacts)
	if !ok || source.gate != g || source.facts.Principal != f.Frame.Principal || !g.sessions.AssociationOpen(g.caller) {
		return localDenied()
	}
	if e := g.peers.CheckForwardTx(ctx, tx, f); e != nil {
		return e
	}
	if source.facts.Managed != nil {
		if e := tx.VerifyCurrentNativeCaller(source.facts.Managed.Authority); e != nil {
			return e
		}
	}
	if source.facts.Hosted != nil {
		if e := source.facts.Hosted.VerifyTx(tx); e != nil {
			return e
		}
	}
	if !g.sessions.AssociationOpen(g.caller) {
		return localDenied()
	}
	return nil
}
