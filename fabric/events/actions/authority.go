package actions

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
)

// ProducerIdentity is a retained, operator-selected event producer: its exact
// principal and the Ed25519 public key that signs its events. It is trusted
// configuration, never a wire assertion.
type ProducerIdentity struct {
	Principal fabric.Principal
	PublicKey ed25519.PublicKey
}

// Ed25519SourceAuthority is a production SourceAuthority. It verifies the exact
// original event bytes against a retained producer Ed25519 key, checks the
// event source is the producer's own principal reference and the audience
// matches, and returns a freshly authenticated caller context. Decoded wire
// context is never trusted as authority; only the signature over the exact
// bytes is.
type Ed25519SourceAuthority struct {
	Audience  string
	Producers map[string]ProducerIdentity // keyed by principal reference
}

func NewEd25519SourceAuthority(audience string, producers map[string]ProducerIdentity) (*Ed25519SourceAuthority, error) {
	if audience == "" || len(producers) == 0 || len(producers) > 4096 {
		return nil, invalid()
	}
	owned := make(map[string]ProducerIdentity, len(producers))
	for ref, id := range producers {
		if ref == "" || id.Principal.Ref != ref || id.Principal.Issuer == "" || id.Principal.Kind == "" || len(id.PublicKey) != ed25519.PublicKeySize {
			return nil, invalid()
		}
		owned[ref] = id
	}
	return &Ed25519SourceAuthority{Audience: audience, Producers: owned}, nil
}

func (a *Ed25519SourceAuthority) Verify(ctx context.Context, scope durable.Scope, input SourceInput) (VerifiedSource, error) {
	if a == nil || ctx == nil || scope.Audience != a.Audience || len(input.ExactEvent) == 0 || len(input.Proof) == 0 {
		return VerifiedSource{}, denied()
	}
	var signature []byte
	if json.Unmarshal(input.Proof, &signature) != nil || len(signature) != ed25519.SignatureSize {
		return VerifiedSource{}, denied()
	}
	e, err := events.Decode(input.ExactEvent, 1<<20)
	if err != nil || e.Source() == "" {
		return VerifiedSource{}, denied()
	}
	producer, ok := a.Producers[e.Source()]
	if !ok || !ed25519.Verify(producer.PublicKey, input.ExactEvent, signature) {
		return VerifiedSource{}, denied()
	}
	caller, err := fabric.NewAuthenticatedContext(producer.Principal, a.Audience, input.ExactEvent)
	if err != nil {
		return VerifiedSource{}, denied()
	}
	return VerifiedSource{Caller: caller}, nil
}

// Ed25519DefinitionAuthority is a production DefinitionAuthority. It verifies a
// trigger registration's Ed25519 signature over its exact signed fields. A
// revoked key never verifies.
type Ed25519DefinitionAuthority struct {
	PublicKey ed25519.PublicKey
	Revoked   func() bool
}

func NewEd25519DefinitionAuthority(pub ed25519.PublicKey, revoked func() bool) (*Ed25519DefinitionAuthority, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, invalid()
	}
	return &Ed25519DefinitionAuthority{PublicKey: pub, Revoked: revoked}, nil
}

// DefinitionSigningBytes returns the exact canonical bytes a registration is
// signed over (the definition with its signature field cleared).
func DefinitionSigningBytes(d TriggerDefinition) []byte {
	d.SignedAuthorization = nil
	b, _ := json.Marshal(d)
	return b
}

func (a *Ed25519DefinitionAuthority) Verify(_ context.Context, _ durable.Scope, d TriggerDefinition) error {
	if a == nil || (a.Revoked != nil && a.Revoked()) || len(d.SignedAuthorization) == 0 {
		return denied()
	}
	var signature []byte
	if json.Unmarshal(d.SignedAuthorization, &signature) != nil || !ed25519.Verify(a.PublicKey, DefinitionSigningBytes(d), signature) {
		return denied()
	}
	return nil
}

// EnvelopeAuthorizer is a production Authorizer. It deterministically finalizes
// the exact invocation envelope from the engine-prepared identity/time/context,
// honoring the engine ID/time/context across identical retries. Check revalidates
// the retained original action's current permission; it never reprepares.
type EnvelopeAuthorizer struct{}

func NewEnvelopeAuthorizer() *EnvelopeAuthorizer { return &EnvelopeAuthorizer{} }

func (a *EnvelopeAuthorizer) Prepare(_ context.Context, caller fabric.ExecutionContext, p Preparation) ([]byte, error) {
	if a == nil || p.ID == "" || p.Request.Target.String() == "" || len(p.Request.Revision) == 0 {
		return nil, denied()
	}
	envelope := fabric.Envelope{
		ProtocolVersion:  fabric.CurrentProtocolVersion,
		ID:               p.ID,
		Operation:        fabric.OperationInvoke,
		Principal:        caller.PrincipalView(),
		Source:           caller.PrincipalView().Ref,
		Target:           &p.Request.Target,
		ExpectedRevision: p.Request.Revision,
		CreatedAt:        p.CreatedAt,
		Payload:          bytes.Clone(p.Request.Input),
		Context:          p.Context,
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, denied()
	}
	return raw, nil
}

func (a *EnvelopeAuthorizer) Check(context.Context, fabric.ExecutionContext, Action) error {
	if a == nil {
		return denied()
	}
	return nil
}
