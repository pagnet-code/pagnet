package fabric

import (
	"context"
	"encoding/json"
)

// MaxReplayAssociationBytes bounds encoded transport metadata independently
// of original frame bytes and retained source data.
const MaxReplayAssociationBytes = 128 << 10

// ReplayAssociation is a public view of a retained execution association, NOT
// authorization. Proof must be checked against the current trusted same-root
// alias ledger and original receipt, not merely a historical public signature.
// Frames retain ExecutionID and their original sequence and source evidence.
type ReplayAssociation struct {
	Version              uint32      `json:"version"`
	AuthorityNamespace   string      `json:"authorityNamespace"`
	AuthorityStoreID     string      `json:"authorityStoreId"`
	AuthorityKeyRevision uint64      `json:"authorityKeyRevision,string"`
	Principal            Principal   `json:"principal"`
	RequestID            string      `json:"requestId"`
	ExecutionID          string      `json:"executionId"`
	Target               EndpointRef `json:"target"`
	ExpectedRevision     Revision    `json:"expectedRevision"`
	OriginalRequestSHA   [32]byte    `json:"originalRequestSha"`
	FinalizedRequestSHA  [32]byte    `json:"finalizedRequestSha"`
	InputSHA             [32]byte    `json:"inputSha"`
	IdempotencySHA       [32]byte    `json:"idempotencySha"`
	BindingFingerprint   [32]byte    `json:"bindingFingerprint"`
	OriginalReceiptSHA   [32]byte    `json:"originalReceiptSha"`
	Proof                []byte      `json:"proof"`
}

// ReplayRequest describes only the freshly authenticated, finalized request.
// Original execution expiry and effect state remain separately retained.
type ReplayRequest struct {
	Principal                                                         Principal
	RequestID                                                         string
	Target                                                            EndpointRef
	ExpectedRevision                                                  Revision
	OriginalRequestSHA, FinalizedRequestSHA, InputSHA, IdempotencySHA [32]byte
}

// ReplayVerifier is mandatory trusted composition for replay. Implementations
// check exact current alias/receipt records, target/profile/account and fresh
// caller authorization; a valid public signature alone is insufficient.
type ReplayVerifier interface {
	VerifyReplay(context.Context, ExecutionContext, ReplayRequest, ReplayAssociation) error
}

// ReplayAssociatedStream advertises an association before ANY source pull.
// nil denotes a fresh execution, not permission to relabel frames.
type ReplayAssociatedStream interface {
	InvocationStream
	ReplayAssociation() *ReplayAssociation
}

func (a ReplayAssociation) Clone() ReplayAssociation {
	a.Proof = append([]byte(nil), a.Proof...)
	return a
}

func (a ReplayAssociation) Validate() error {
	var zero [32]byte
	if a.Version != 1 || !validText(a.AuthorityNamespace, 4096) || !validText(a.AuthorityStoreID, 256) || a.AuthorityKeyRevision == 0 ||
		!validText(a.Principal.Ref, 4096) || !ValidNamespacedName(a.Principal.Kind) || !validText(a.Principal.Issuer, 4096) ||
		!validText(a.RequestID, 256) || !validText(a.ExecutionID, 256) || a.RequestID == a.ExecutionID ||
		a.Target.String() == "" || (a.ExpectedRevision != "" && !validText(string(a.ExpectedRevision), 256)) ||
		a.OriginalRequestSHA == zero || a.FinalizedRequestSHA == zero || a.InputSHA == zero || a.IdempotencySHA == zero ||
		a.BindingFingerprint == zero || a.OriginalReceiptSHA == zero || len(a.Proof) == 0 || len(a.Proof) > 8192 {
		return NewError(CodeProtocolError, "Invalid retained replay association")
	}
	encoded, err := json.Marshal(a)
	if err != nil || len(encoded) > MaxReplayAssociationBytes {
		return NewError(CodeProtocolError, "Replay metadata exceeds transport bounds")
	}
	return nil
}

// VerifiedReplayCorrelation has no exported fields. It can only be produced
// through a mandatory trusted verifier and exact current-request comparison.
type VerifiedReplayCorrelation struct{ association ReplayAssociation }

func VerifyReplayCorrelation(ctx context.Context, caller ExecutionContext, current ReplayRequest, association ReplayAssociation, verifier ReplayVerifier) (*VerifiedReplayCorrelation, error) {
	if ctx == nil || verifier == nil {
		return nil, NewError(CodeUnauthenticated, "Replay verification is not configured")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if caller.PrincipalView() != current.Principal || caller.VerifyAuthenticatedDigest(current.OriginalRequestSHA, caller.Audience()) != nil {
		return nil, NewError(CodeUnauthenticated, "Replay requires the fresh authenticated original")
	}
	a := association.Clone()
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if a.Principal != current.Principal || a.RequestID != current.RequestID || a.Target != current.Target || a.ExpectedRevision != current.ExpectedRevision ||
		a.OriginalRequestSHA != current.OriginalRequestSHA || a.FinalizedRequestSHA != current.FinalizedRequestSHA || a.InputSHA != current.InputSHA || a.IdempotencySHA != current.IdempotencySHA {
		return nil, NewError(CodeUnauthenticated, "Replay association does not match current request")
	}
	if err := verifier.VerifyReplay(ctx, caller, current, a.Clone()); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &VerifiedReplayCorrelation{association: a}, nil
}

func (v *VerifiedReplayCorrelation) Association() *ReplayAssociation {
	if v == nil {
		return nil
	}
	a := v.association.Clone()
	return &a
}
