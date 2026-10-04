package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"slices"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

const MaxForwardEnvelopeBytes = 1 << 20
const MaxForwardProofBytes = 128 << 10
const MaxForwardBundleBytes = 3 << 20

// ForwardBundle is PRIVATE encrypted content. Original bytes retain the caller
// commitment; Forwarded bytes are the exact separately signed engine view.
// This shape is not permission to send, admit, execute or replay an operation.
type ForwardBundle struct {
	Proof     fabric.SignedForwardProof `json:"proof"`
	Original  []byte                    `json:"original"`
	Forwarded []byte                    `json:"forwarded"`
}
type VerifyLimits struct {
	MaxLifetime  time.Duration
	MaxClockSkew time.Duration
}

func (l VerifyLimits) valid() bool {
	return l.MaxLifetime > 0 && l.MaxLifetime <= 24*time.Hour && l.MaxClockSkew >= 0 && l.MaxClockSkew <= 30*time.Second
}

func DecodeForwardBundle(raw []byte) (ForwardBundle, error) {
	var b ForwardBundle
	if e := fabric.DecodeJSONWithLimits(raw, &b, fabric.WireLimits{MaxBytes: MaxForwardBundleBytes, MaxDepth: 16, MaxMembers: 2048}); e != nil {
		return ForwardBundle{}, e
	}
	if e := boundedBundle(b); e != nil {
		return ForwardBundle{}, e
	}
	return b, nil
}
func EncodeForwardBundle(b ForwardBundle) ([]byte, error) {
	if e := boundedBundle(b); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(b)
	if e != nil || len(raw) > MaxForwardBundleBytes {
		return nil, protocolError()
	}
	return raw, nil
}
func boundedBundle(b ForwardBundle) error {
	if len(b.Original) == 0 || len(b.Original) > MaxForwardEnvelopeBytes || len(b.Forwarded) == 0 || len(b.Forwarded) > MaxForwardEnvelopeBytes || len(b.Proof.Signature) != ed25519.SignatureSize {
		return protocolError()
	}
	raw, e := json.Marshal(b.Proof)
	if e != nil || len(raw) > MaxForwardProofBytes {
		return protocolError()
	}
	if _, e = b.Proof.Frame.SigningBytes(); e != nil {
		return e
	}
	return nil
}
func contextProvenance(c fabric.EnvelopeContext) fabric.Provenance {
	return fabric.Provenance{Origin: c.Origin, ParentID: c.ParentID, Ancestry: c.Ancestry, Hops: c.Hops, ExtensionChain: c.ExtensionChain, TriggerLineage: c.TriggerLineage}
}
func equalDeadline(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}
func equalTarget(a, b *fabric.EndpointRef) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func equalStrings(a, b []string) bool {
	return slices.Equal(a, b)
}
func lineageExact(a, b fabric.Provenance) bool {
	return a.Origin == b.Origin && a.ParentID == b.ParentID && a.Hops == b.Hops && equalStrings(a.Ancestry, b.Ancestry) && equalStrings(a.ExtensionChain, b.ExtensionChain) && equalStrings(a.TriggerLineage, b.TriggerLineage)
}
func forwardLineage(original, forwarded fabric.Provenance) bool {
	if original.Hops >= 64 || forwarded.Hops != original.Hops+1 || original.Origin != forwarded.Origin || original.ParentID != forwarded.ParentID || !equalStrings(original.Ancestry, forwarded.Ancestry) || !equalStrings(original.TriggerLineage, forwarded.TriggerLineage) || len(forwarded.ExtensionChain) < len(original.ExtensionChain) {
		return false
	}
	return equalStrings(original.ExtensionChain, forwarded.ExtensionChain[:len(original.ExtensionChain)])
}

// VerifyForwardBundle authenticates only an ENGINE forwarding attestation under
// actual explicitly trusted current source/destination peer roots. The callback
// runs inside that current-trust fence. It must complete destination durable
// original-invocation admission/current operation policy before invocation.
// Ordinary caller signatures/received roots cannot substitute for this proof.
// A rejected gate never returns a captured authenticated context.
func VerifyForwardBundle(ctx context.Context, c Config, b ForwardBundle, limits VerifyLimits, accept func(context.Context, fabric.ExecutionContext) error) error {
	c = cloneConfig(c)
	if c.SourceRole || !limits.valid() || accept == nil || boundedBundle(b) != nil {
		return authError()
	}
	// Own all mutable buffers before a trusted gate callback can inspect them.
	raw, e := EncodeForwardBundle(b)
	if e != nil {
		return e
	}
	defer clear(raw)
	b, e = DecodeForwardBundle(raw)
	if e != nil {
		return e
	}
	return guarded(ctx, c, func(current context.Context) error {
		return verifyForwardContent(current, c, b, limits, false, accept)
	})
}

// Historical validation is private to the retained ledger. The independently
// current peer/caller fence remains mandatory; old proof is not current auth.
func verifyForwardContent(current context.Context, c Config, b ForwardBundle, limits VerifyLimits, historical bool, accept func(context.Context, fabric.ExecutionContext) error) error {
	f := b.Proof.Frame
	if f.SourceDomain != c.Remote.Authority.Namespace || f.SourceStoreID != c.Remote.Authority.StoreID || f.SourceKeyRevision != c.Remote.Authority.KeyRevision || f.DestinationDomain != c.Local.Authority.Namespace || f.DestinationStoreID != c.Local.Authority.StoreID || f.SourcePeerBindingDigest != c.Remote.BindingDigest || f.DestinationPeerBindingDigest != c.Local.BindingDigest || f.BindingProfile != Profile || sha256.Sum256(b.Original) != f.OriginalEnvelopeDigest || sha256.Sum256(b.Forwarded) != f.ForwardedEnvelopeDigest {
		return authError()
	}
	signed, e := f.SigningBytes()
	if e != nil || len(c.Remote.Authority.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(c.Remote.Authority.PublicKey, signed, b.Proof.Signature) {
		return authError()
	}
	issued, e := time.Parse(time.RFC3339Nano, f.IssuedAt)
	if e != nil {
		return authError()
	}
	expires, e := time.Parse(time.RFC3339Nano, f.ExpiresAt)
	now := time.Now()
	if e != nil || (!historical && !expires.After(now)) || issued.After(now.Add(limits.MaxClockSkew)) || expires.Sub(issued) > limits.MaxLifetime {
		return authError()
	}
	var original, forwarded fabric.Envelope
	if fabric.DecodeJSON(b.Original, &original) != nil || fabric.DecodeJSON(b.Forwarded, &forwarded) != nil || original.Validate() != nil || forwarded.Validate() != nil {
		return authError()
	}
	if original.ID != f.InvocationID || forwarded.ID != original.ID || original.Principal != f.Principal || forwarded.Principal != original.Principal || original.Operation != f.Operation || forwarded.Operation != original.Operation || original.ProtocolVersion != forwarded.ProtocolVersion || original.Source != forwarded.Source || !original.CreatedAt.Equal(forwarded.CreatedAt) || !reflect.DeepEqual(original.Trace, forwarded.Trace) || !reflect.DeepEqual(original.RequiredFeatures, forwarded.RequiredFeatures) || original.Context.IdempotencyKey != forwarded.Context.IdempotencyKey || !equalDeadline(original.Context.Deadline, forwarded.Context.Deadline) {
		return authError()
	}
	if !lineageExact(contextProvenance(original.Context), f.OriginalProvenance) || !lineageExact(contextProvenance(forwarded.Context), f.ForwardedProvenance) || !forwardLineage(f.OriginalProvenance, f.ForwardedProvenance) {
		return authError()
	}
	deadline := ""
	if original.Context.Deadline != nil {
		deadline = original.Context.Deadline.UTC().Format(time.RFC3339Nano)
	}
	if deadline != f.Deadline || !equalTarget(f.Target, forwarded.Target) || f.ExpectedRevision != forwarded.ExpectedRevision {
		return authError()
	}
	caller, e := fabric.NewAuthenticatedForwardContext(f.Principal, c.Local.Authority.Namespace, b.Forwarded, f.ForwardedProvenance)
	if e != nil {
		return e
	}
	if e = caller.VerifyBinding(forwarded, b.Forwarded, c.Local.Authority.Namespace); e != nil {
		return e
	}
	return accept(current, caller)
}
