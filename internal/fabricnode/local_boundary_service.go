package fabricnode

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

type dispatchStampKey struct{}
type dispatchStamp struct {
	associationInvocation               string
	association                         *fabricauth.Authority
	authenticatedCaller                 fabric.ExecutionContext
	boundary                            *LocalBoundary
	caller                              fabric.Principal
	originalSHA, finalizedSHA, inputSHA [32]byte
	invocationID                        string
	target                              fabric.EndpointRef
	revision                            fabric.Revision
	scope                               registry.DescriptorBatchScope
	fingerprint                         [32]byte
	managed                             *registry.NativeCallerAuthority
}

// AuthorizeTx consumes only the private stamp minted by this boundary from an
// actual current local session and exact dispatcher request. Managed source
// retirement is linearized with the destination reservation/frame transaction;
// no native IPC, kernel inspection or authenticator callback runs under SQL.
func (b *LocalBoundary) AuthorizeTx(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext, f fabricservices.InvocationFacts, action string) error {
	if b == nil || ctx == nil || ctx.Err() != nil || tx == nil {
		return localDenied()
	}
	s, ok := ctx.Value(dispatchStampKey{}).(*dispatchStamp)
	if !ok || s == nil || s.boundary != b || s.caller != caller.PrincipalView() || caller.VerifyAuthenticatedDigest(s.originalSHA, b.root.Namespace) != nil || f.Principal != s.caller || f.Target != s.target || f.Revision != s.revision || f.Scope != s.scope || f.Fingerprint != s.fingerprint {
		return localDenied()
	}
	if action == "association_read" && s.associationInvocation != "" {
		if f.InvocationID != s.associationInvocation {
			return localDenied()
		}
	} else if f.InvocationID != s.invocationID || f.OriginalSHA != s.originalSHA || f.FinalizedSHA != s.finalizedSHA || f.InputSHA != s.inputSHA {
		return localDenied()
	}
	switch action {
	case "reserve", "replay", "append", "frame", "read", "find", "pull", "association_read", "associate", "associate_admission":
	default:
		return fabric.NewError(fabric.CodeUnsupported, "Local service action is not supported")
	}
	return b.authorizeStampTx(tx, s)
}
