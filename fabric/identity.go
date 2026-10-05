package fabric

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
)

// ExecutionContext is an opaque authenticated in-process capability. It cannot
// be decoded from wire JSON. Code installed in this process is trusted code;
// this is not a sandbox against a malicious Go plugin.
type ExecutionContext struct {
	authenticationEvidence any
	principal              Principal
	audience               string
	originalDigest         [32]byte
	verified               bool
	provenance             Provenance
}

// Provenance is authenticated ENGINE lineage, not an arbitrary assertion
// signed by the caller. It provides loop safety and self-interceptor exclusion.
type Provenance struct {
	Origin         string
	ParentID       string
	Ancestry       []string
	Hops           uint32
	ExtensionChain []string
	TriggerLineage []string
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
	return ExecutionContext{principal: principal, audience: audience, originalDigest: sha256.Sum256(originalBytes), verified: true, provenance: Provenance{Origin: principal.Ref}}, nil
}

// NewAuthenticatedContextWithEvidence is for trusted ingress authenticators only.
// Evidence is an in-process capability belonging to that authenticator, never
// caller assertions or a protocol value. Consumers must verify its concrete
// private type and actual current source; its presence alone grants no authority.
func NewAuthenticatedContextWithEvidence(principal Principal, audience string, exactOriginal []byte, evidence any) (ExecutionContext, error) {
	if evidence == nil {
		return ExecutionContext{}, NewError(CodeUnauthenticated, "Missing private authentication evidence")
	}
	c, err := NewAuthenticatedContext(principal, audience, exactOriginal)
	if err != nil {
		return c, err
	}
	c.authenticationEvidence = evidence
	return c, nil
}

// AuthenticationEvidence is for trusted infrastructure only. It must never be
// copied into envelopes, search, events, telemetry or extension wire payloads.
func (c ExecutionContext) AuthenticationEvidence() any { return c.authenticationEvidence }

// NewAuthenticatedForwardContextWithEvidence is trusted composition only. It
// retains verified historical identity/lineage while attaching a private,
// purpose-specific capability. It does not create a current ingress session.
func NewAuthenticatedForwardContextWithEvidence(principal Principal, audience string, exactOriginal []byte, provenance Provenance, evidence any) (ExecutionContext, error) {
	if evidence == nil {
		return ExecutionContext{}, NewError(CodeUnauthenticated, "Missing private forward evidence")
	}
	c, err := NewAuthenticatedForwardContext(principal, audience, exactOriginal, provenance)
	if err != nil {
		return c, err
	}
	c.authenticationEvidence = evidence
	return c, nil
}

// VerifyAuthenticatedDigest checks an authenticator's private original binding
// without exposing its payload fingerprint as protocol data.
func (c ExecutionContext) VerifyAuthenticatedDigest(expected [32]byte, audience string) error {
	if c.VerifyAuthenticated(audience) != nil || c.originalDigest != expected {
		return NewError(CodeUnauthenticated, "Private authenticated original binding mismatch")
	}
	return nil
}

// NewAuthenticatedForwardContext is for a trusted authenticator AFTER verifying
// an engine/authority forwarding attestation and its exact request commitment.
// An ordinary caller's own signature is insufficient to establish this lineage.
func NewAuthenticatedForwardContext(principal Principal, audience string, exactBytes []byte, verifiedProvenance Provenance) (ExecutionContext, error) {
	c, err := NewAuthenticatedContext(principal, audience, exactBytes)
	if err != nil {
		return ExecutionContext{}, err
	}
	if err = validateProvenance(verifiedProvenance); err != nil {
		return ExecutionContext{}, err
	}
	verifiedProvenance.Ancestry = slices.Clone(verifiedProvenance.Ancestry)
	verifiedProvenance.ExtensionChain = slices.Clone(verifiedProvenance.ExtensionChain)
	verifiedProvenance.TriggerLineage = slices.Clone(verifiedProvenance.TriggerLineage)
	c.provenance = verifiedProvenance
	return c, nil
}

// Shape validation alone never authenticates lineage or constructs authority.
func validateProvenance(p Provenance) error {
	if !validText(p.Origin, 4096) || p.Hops > 64 || len(p.Ancestry) > 64 || len(p.ExtensionChain) > 64 || len(p.TriggerLineage) > 64 {
		return NewError(CodeUnauthenticated, "Invalid authenticated engine lineage")
	}
	for _, list := range [][]string{p.Ancestry, p.ExtensionChain, p.TriggerLineage} {
		for _, value := range list {
			if !validText(value, 256) {
				return NewError(CodeUnauthenticated, "Invalid authenticated engine lineage")
			}
		}
	}
	if p.ParentID != "" && !validText(p.ParentID, 256) {
		return NewError(CodeUnauthenticated, "Invalid authenticated parent")
	}
	return nil
}

func (c ExecutionContext) ProvenanceView() Provenance {
	p := c.provenance
	p.Ancestry = slices.Clone(p.Ancestry)
	p.ExtensionChain = slices.Clone(p.ExtensionChain)
	p.TriggerLineage = slices.Clone(p.TriggerLineage)
	return p
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

// VerifyAuthenticatedData verifies exact bytes for private infrastructure control
// protocols. It does not parse an envelope or grant current operation authority.
// Trusted transport authentication and a current control gate remain mandatory.
func (c ExecutionContext) VerifyAuthenticatedData(exact []byte, audience string) error {
	if !c.verified || c.audience != audience || len(exact) == 0 || c.originalDigest != sha256.Sum256(exact) {
		return NewError(CodeUnauthenticated, "Authenticated control binding mismatch")
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
	p := c.provenance
	asserted := envelope.Context
	if p.Origin != asserted.Origin || p.ParentID != asserted.ParentID || p.Hops != asserted.Hops || !slices.Equal(p.Ancestry, asserted.Ancestry) || !slices.Equal(p.ExtensionChain, asserted.ExtensionChain) || !slices.Equal(p.TriggerLineage, asserted.TriggerLineage) {
		return Envelope{}, NewError(CodeUnauthenticated, "Caller assertion cannot manufacture engine lineage")
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
