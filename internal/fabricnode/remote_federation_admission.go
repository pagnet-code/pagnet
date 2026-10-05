package fabricnode

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// AuthorizeTx verifies infrastructure exposure/current bilateral links for the
// exact retained federation admission. It is not business authorization: the
// destination's configured interceptors still run before paid dispatch.
type remoteFederationAdmissionPolicy struct{ boundary *RemoteBoundary }

func (b *RemoteBoundary) FederationAdmissionPolicy() federation.CurrentCallerPolicy {
	return remoteFederationAdmissionPolicy{b}
}

func (p remoteFederationAdmissionPolicy) AuthorizeTx(ctx context.Context, tx *registry.AuthorityTx, action federation.AdmissionAction, caller fabric.ExecutionContext, f federation.AdmissionFacts) error {
	b := p.boundary
	r, e := b.binding(caller)
	if e != nil {
		return e
	}
	if f.Principal != r.principal || f.InvocationID != r.invocation || f.Target == nil || f.Source.BindingDigest != b.config.Remote.BindingDigest || f.Destination.BindingDigest != b.config.Local.BindingDigest || f.Source.Authority.Namespace != b.config.Remote.Authority.Namespace || f.Source.Authority.StoreID != b.config.Remote.Authority.StoreID || f.Destination.Authority.Namespace != b.local.root.Namespace || f.Destination.Authority.StoreID != b.local.root.StoreID {
		return localDenied()
	}
	switch action {
	case federation.ActionAdmit, federation.ActionAttempt:
		if f.BundleDigest != r.assertion {
			return localDenied()
		}
	case federation.ActionAssociate, federation.ActionRead, federation.ActionCancel, federation.ActionCheckpoint:
	default:
		return localDenied()
	}
	return b.peers.WithCurrentTx(ctx, tx, b.config.Local, b.config.Remote, func(context.Context) error {
		return b.exposures.CheckTargetTx(tx, b.config.Remote.Authority.Namespace, *f.Target, f.ExpectedRevision)
	})
}
