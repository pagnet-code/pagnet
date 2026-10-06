// The hosted-native router link (step 6b): the BindingProvider and adapter
// for the installed hosted actor's canonical invoke chain. The provider
// resolves ONLY the single installed hosted endpoint (single-hosted-actor
// model) and only for that endpoint's own actor principal; the adapter
// validates the engine-finalized request, enforces the exact retained-prompt
// grammar BEFORE any seal, journals the first effect via the signed
// initial-effect journal, admits it to the server through the daemon, and
// returns the admission receipt on a unary stream. Failure semantics: a
// reserve conflict propagates (no send); an admit failure returns an honest
// error and the sealed record REMAINS — an exact retry returns the retained
// receipt and retries the admission.

package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	fabnode "github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/internal/daemon"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/transport"
)

// hostedNativeProvider resolves the installed hosted actor's binding. It is
// fail-closed through the deferred holder pattern until the product and the
// daemon are wired: an unwired resolution is an honest refusal, never a
// fabricated adapter or principal.
type hostedNativeProvider struct {
	node      *InstalledNode
	deferred  *hostedDeferred
	mu        sync.RWMutex
	installed *InstalledHosted
}

func newHostedNativeProvider(node *InstalledNode, deferred *hostedDeferred) *hostedNativeProvider {
	return &hostedNativeProvider{node: node, deferred: deferred}
}

// setProduct wires the composed installed hosted product (post newInstalledHosted).
func (p *hostedNativeProvider) setProduct(h *InstalledHosted) {
	if p == nil || h == nil {
		return
	}
	p.mu.Lock()
	p.installed = h
	p.mu.Unlock()
}

func (p *hostedNativeProvider) product() *InstalledHosted {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.installed
}

// ResolveBinding serves the installed endpoint only: exactly one installed
// hosted binding must exist, the target must be that endpoint with that
// binding, and the caller must be that endpoint's own actor. The selection
// fingerprint is the installed profile's pinned native profile digest.
func (p *hostedNativeProvider) ResolveBinding(ctx context.Context, caller fabric.ExecutionContext, endpoint fabric.EndpointDescriptor, binding fabric.BindingSummary, offer *fabric.OfferDescriptor) (fabric.EndpointAdapter, [32]byte, error) {
	if p == nil || p.node == nil || p.node.Installation == nil || p.deferred == nil {
		return nil, [32]byte{}, hostedNotWired("router")
	}
	if offer != nil {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeStaleReference, "Hosted native binding serves the installed endpoint only")
	}
	if err := caller.VerifyAuthenticated(endpoint.Ref.Domain()); err != nil {
		return nil, [32]byte{}, err
	}
	product := p.product()
	if product == nil {
		return nil, [32]byte{}, hostedNotWired("router")
	}
	if p.deferred.daemon() == nil {
		return nil, [32]byte{}, hostedNotWired("daemon")
	}
	bindings, err := p.node.hostedNativeBindings(ctx, product.Profiles)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if len(bindings) != 1 {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeTargetUnavailable, "Hosted native router requires exactly one installed hosted binding")
	}
	b := bindings[0]
	if b.Descriptor.Ref != endpoint.Ref || b.Descriptor.Revision != endpoint.Revision || b.Scope.BindingID != binding.ID {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeStaleReference, "Hosted native target differs from the installed endpoint")
	}
	// Defense in depth: the sideport-authenticated hosted session already
	// binds this principal; the journal and the boundary re-verify it.
	store := p.node.Installation.Store
	want := fabric.Principal{Ref: endpoint.Ref.String(), Kind: endpoint.Kind, Issuer: store.Namespace()}
	if caller.PrincipalView() != want {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeUnauthenticated, "Caller is not the installed hosted actor")
	}
	if b.Profile.NativeProfile == ([32]byte{}) {
		return nil, [32]byte{}, fabric.NewError(fabric.CodeStaleReference, "Hosted native selection fingerprint is unavailable")
	}
	return &hostedNativeAdapter{node: p.node, deferred: p.deferred, product: product, namespace: store.Namespace()}, b.Profile.NativeProfile, nil
}

// hostedNativeAdapter bridges the engine-finalized invoke of the installed
// hosted actor to the local admission chain: sealed input, signed initial
// journal, daemon admit, unary receipt.
type hostedNativeAdapter struct {
	node      *InstalledNode
	deferred  *hostedDeferred
	product   *InstalledHosted
	namespace string
}

// hostedInvocationPromptBinding is the exact retained-prompt binding for a
// hosted invoke payload, mirrored from the daemon's delivery guard
// (hostedInvocationPromptInput): a JSON object with a single nonempty "input"
// string field (up to 128 KiB), no unknown fields. An undeliverable prompt is
// refused BEFORE any seal or journal write.
func hostedInvocationPromptBinding(plain []byte) (string, error) {
	var input struct {
		Input string `json:"input"`
	}
	if e := fabric.DecodeJSONWithLimits(plain, &input, fabric.WireLimits{MaxBytes: nativeauthority.MaxNativeOperationBytes, MaxDepth: 2, MaxMembers: 8}); e != nil {
		return "", e
	}
	strict := json.NewDecoder(bytes.NewReader(plain))
	strict.DisallowUnknownFields()
	if strict.Decode(&input) != nil || !utf8.ValidString(input.Input) || input.Input == "" || len(input.Input) > 128<<10 {
		return "", errors.New("hosted invocation input is not a single input string field")
	}
	return input.Input, nil
}

func sameHostedNativeValue(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

// Invoke is only reachable under the engine's dispatch admission: the original
// and finalized exact bytes come from the engine's private context, never from
// tool arguments.
func (a *hostedNativeAdapter) Invoke(ctx context.Context, caller fabric.ExecutionContext, endpoint fabric.EndpointDescriptor, request fabric.InvokeRequest) (fabric.InvocationStream, error) {
	if a == nil || ctx == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted native invocation missing")
	}
	authenticated, original, finalized, ok := fabnode.FinalizedRequestFromContext(ctx)
	if !ok || authenticated.PrincipalView() != caller.PrincipalView() || !sameHostedNativeValue(authenticated.ProvenanceView(), caller.ProvenanceView()) || caller.VerifyAuthenticated(a.namespace) != nil || request.Validate() != nil {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Hosted native invocation requires finalized node admission")
	}
	if _, e := caller.DecodeVerifiedEnvelope(original, a.namespace); e != nil {
		return nil, e
	}
	var env fabric.Envelope
	if fabric.DecodeJSON(finalized, &env) != nil || env.Validate() != nil || env.Operation != fabric.OperationInvoke || env.Target == nil || *env.Target != request.Target || endpoint.Ref != env.Target.Endpoint() || env.Target.IsOffer() || endpoint.Revision != env.ExpectedRevision || request.ExpectedRevision != env.ExpectedRevision || request.InvocationID != env.ID || request.IdempotencyKey != env.Context.IdempotencyKey || !bytes.Equal(request.Input, env.Payload) || !sameHostedNativeValue(request.Deadline, env.Context.Deadline) {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted native request differs from finalized dispatch")
	}
	// Prompt grammar FIRST: an undeliverable prompt is never sealed and never
	// reaches the journal.
	if _, e := hostedInvocationPromptBinding(env.Payload); e != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted native prompt is not the exact retained-prompt binding")
	}
	// Re-resolve through the node's selection authority: the installed
	// endpoint, its selected binding and its installed profile.
	bindings, e := a.node.hostedNativeBindings(ctx, a.product.Profiles)
	if e != nil {
		return nil, e
	}
	if len(bindings) != 1 {
		return nil, fabric.NewError(fabric.CodeTargetUnavailable, "Hosted native invocation requires exactly one installed hosted binding")
	}
	b := bindings[0]
	if b.Descriptor.Ref != endpoint.Ref || b.Descriptor.Revision != endpoint.Revision {
		return nil, fabric.NewError(fabric.CodeStaleReference, "Hosted native descriptor changed")
	}
	store := a.node.Installation.Store
	want := fabric.Principal{Ref: endpoint.Ref.String(), Kind: endpoint.Kind, Issuer: store.Namespace()}
	if caller.PrincipalView() != want {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Caller is not the installed hosted actor")
	}
	d := a.deferred.daemon()
	if d == nil {
		return nil, hostedNotWired("daemon")
	}
	// The command identity is deterministic in (principal, invocation ID):
	// stable across exact retries (server idempotency + journal compare).
	commandID := daemon.HostedInvocationCommandID(want, env.ID)
	// Seal the RAW payload bytes under the cloud network key epoch.
	cipher, aad, e := d.PrepareHostedInvocation(ctx, b.Profile, env.ID, env.Payload)
	if e != nil {
		return nil, e
	}
	deadline := ""
	if env.Context.Deadline != nil {
		deadline = env.Context.Deadline.UTC().Format(time.RFC3339Nano)
	}
	frame := fabric.DispatchAdmissionFrame{
		SourceDomain:            a.namespace,
		CallerRef:               want.Ref,
		AudienceDomain:          a.namespace,
		InvocationID:            env.ID,
		AttemptID:               commandID,
		ReplayID:                commandID,
		FinalizedDispatchDigest: sha256.Sum256(finalized),
		Deadline:                deadline,
	}
	// Journal the first uncertain effect BEFORE any send. prepared is unused
	// for non-offer targets (verifyInvocationTarget checks the revision only),
	// and offers are refused above, so no prepared schema applies.
	receipt, fresh, e := a.product.Invocations.Reserve(ctx, b.Scope, caller, original, finalized, frame, fabricagent.InvokedInput{Ciphertext: cipher, AAD: aad, CommandID: commandID}, b.Profile.NativeProfile)
	if e != nil {
		return nil, e
	}
	// Admit the retained bytes (the journal receipt drives retries; the
	// request ID is fresh per attempt and is correlation only). On failure
	// the sealed record REMAINS: an exact retry returns the retained receipt
	// and retries the admission.
	p := transport.FabricHostedInvocation{
		RequestID:           domain.NewID().String(),
		CommandID:           receipt.CommandID,
		Ref:                 b.Scope.Endpoint,
		Revision:            b.Scope.ExpectedEndpointRevision,
		InvocationID:        receipt.InvocationID,
		NetworkID:           b.Profile.NetworkID,
		InstanceID:          b.Profile.Scope.InstanceID,
		OwnershipID:         b.Profile.OwnershipID,
		OwnershipGeneration: b.Profile.Scope.Generation,
		Envelope:            receipt.Ciphertext,
		AAD:                 receipt.AAD,
	}
	proof, e := d.AdmitHostedFabric(ctx, b.Profile, p)
	if e != nil {
		return nil, e
	}
	receiptJSON, e := json.Marshal(hostedInvocationReceipt{
		InvocationID:        receipt.InvocationID,
		CommandID:           receipt.CommandID,
		Fresh:               fresh,
		State:               "admitted",
		OwnershipID:         proof.OwnershipID,
		OwnershipGeneration: proof.OwnershipGeneration,
		DispatchSequence:    proof.DispatchSequence,
	})
	if e != nil {
		return nil, fabric.NewError(fabric.CodeProtocolError, "Hosted native admission receipt is malformed")
	}
	return newHostedUnaryStream(env.ID, receiptJSON), nil
}

// hostedInvocationReceipt is the bounded unary admission result. The paid
// effect arrives asynchronously as the worker's own turn; the tool call is not
// held open waiting for the loopback delivery.
type hostedInvocationReceipt struct {
	InvocationID        string `json:"invocationId"`
	CommandID           string `json:"commandId"`
	Fresh               bool   `json:"fresh"`
	State               string `json:"state"`
	OwnershipID         string `json:"ownershipId"`
	OwnershipGeneration string `json:"ownershipGeneration"`
	DispatchSequence    int64  `json:"dispatchSequence"`
}

// hostedUnaryStream carries exactly one bounded result: start, one JSON chunk,
// complete. Close is safe concurrently with Next.
type hostedUnaryStream struct {
	id      string
	receipt []byte
	mu      sync.Mutex
	next    uint64
}

func newHostedUnaryStream(id string, receipt []byte) *hostedUnaryStream {
	return &hostedUnaryStream{id: id, receipt: receipt}
}

func (s *hostedUnaryStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	if ctx == nil {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeInvalidInput, "Missing stream context")
	}
	if err := ctx.Err(); err != nil {
		return fabric.InvocationFrame{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.next {
	case 0:
		s.next++
		return fabric.InvocationFrame{InvocationID: s.id, Sequence: 0, Kind: fabric.FrameStart}, nil
	case 1:
		s.next++
		return fabric.InvocationFrame{InvocationID: s.id, Sequence: 1, Kind: fabric.FrameChunk, ContentType: "application/json", Data: s.receipt}, nil
	case 2:
		s.next++
		return fabric.InvocationFrame{InvocationID: s.id, Sequence: 2, Kind: fabric.FrameComplete}, nil
	default:
		return fabric.InvocationFrame{}, io.EOF
	}
}

func (s *hostedUnaryStream) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next = ^uint64(0)
	clear(s.receipt)
	return nil
}

var _ fabric.EndpointAdapter = (*hostedNativeAdapter)(nil)
