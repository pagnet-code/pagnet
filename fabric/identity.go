package fabric

import (
	"context"
	"crypto/sha256"
	"encoding/json"
)

// ExecutionContext is an opaque authenticated in-process capability. It cannot
// be decoded from wire JSON. Code installed in this process is trusted code;
// this is not a sandbox against a malicious Go plugin.
type ExecutionContext struct {
	principal      Principal
	audience       string
	originalDigest [32]byte
	verified       bool
}

func (ExecutionContext) MarshalJSON() ([]byte, error) {
	return nil, NewError(CodeProtocolError, "Authenticated execution context is not a wire value")
}

func (*ExecutionContext) UnmarshalJSON([]byte) error {
	return NewError(CodeUnauthenticated, "Wire data cannot create authenticated execution context")
}

// NewAuthenticatedContext is for trusted authenticator implementations ONLY,
// after verifying the exact bytes, issuer, audience, replay identity and caller.
// Every wire entry point must call its configured Authenticator, never this
// constructor with unverified request fields. Extensions get PrincipalView.
func NewAuthenticatedContext(principal Principal, audience string, originalBytes []byte) (ExecutionContext, error) {
	if !validText(principal.Ref, 4096) || !validText(principal.Issuer, 4096) || !ValidNamespacedName(principal.Kind) || !validText(audience, 4096) || len(originalBytes) == 0 {
		return ExecutionContext{}, NewError(CodeUnauthenticated, "Invalid authenticated context")
	}
	return ExecutionContext{principal: principal, audience: audience, originalDigest: sha256.Sum256(originalBytes), verified: true}, nil
}

func (c ExecutionContext) PrincipalView() Principal { return c.principal }
func (c ExecutionContext) Audience() string         { return c.audience }

// VerifyAuthenticated is for trusted infrastructure admission calls after
// ingress authentication. It proves identity/audience only, not authority for
// an operation: the current authority/policy and exact mutation still require
// validation at their own dispatch boundary.
func (c ExecutionContext) VerifyAuthenticated(audience string) error {
	if !c.verified || c.audience != audience {
		return NewError(CodeUnauthenticated, "Invalid authenticated infrastructure admission")
	}
	return nil
}

// VerifyBinding checks context against the ORIGINAL envelope and bytes. The
// engine separately authorizes finalized transformed/redirected dispatch.
func (c ExecutionContext) VerifyBinding(original Envelope, exactBytes []byte, audience string) error {
	decoded, err := c.DecodeVerifiedEnvelope(exactBytes, audience)
	if err != nil {
		return err
	}
	// Compare the actual typed representation, including raw payload precision,
	// against the supplied original. Never validate one target and execute a
	// differently decoded or caller-modified representation.
	a, err := json.Marshal(decoded)
	if err != nil {
		return NewError(CodeProtocolError, "Invalid original envelope")
	}
	b, err := json.Marshal(original)
	if err != nil || string(a) != string(b) {
		return NewError(CodeUnauthenticated, "Authenticated request binding mismatch")
	}
	return nil
}

// DecodeVerifiedEnvelope is the mandatory ingress after Authenticate. It
// validates and returns the same exact authenticated document's interpretation.
func (c ExecutionContext) DecodeVerifiedEnvelope(exactBytes []byte, audience string) (Envelope, error) {
	if !c.verified || c.audience != audience || c.originalDigest != sha256.Sum256(exactBytes) {
		return Envelope{}, NewError(CodeUnauthenticated, "Authenticated request binding mismatch")
	}
	var envelope Envelope
	if err := DecodeJSON(exactBytes, &envelope); err != nil {
		return Envelope{}, err
	}
	if c.principal != envelope.Principal || c.principal.Ref != envelope.Source {
		return Envelope{}, NewError(CodeUnauthenticated, "Authenticated principal mismatch")
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

type AuthenticationRequest struct {
	ExactEnvelope []byte
	Audience      string
	// PeerEvidence is transport-private verified evidence. It is never inserted
	// into an envelope, descriptor, event or search index.
	PeerEvidence any
}

type Authenticator interface {
	Authenticate(context.Context, AuthenticationRequest) (ExecutionContext, error)
}
