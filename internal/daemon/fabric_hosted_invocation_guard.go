package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// HostedInvocationGuard is the explicit original-invocation composition: the
// same actual node authority, signed initial-effect journal, private
// association and network keys as the rest of the hosted native path. The
// caller port supplies the node-composed authenticated context of the LOCAL
// hosted actor (the principal bound to the local endpoint that reserved the
// retained original — never the installation owner, which the journal
// rejects as a hosted caller); the resolve port carries the node's selected
// descriptor binding for an instance. Neither is ever derived from a delivery
// payload. A nil guard refuses kind="invocation" delivery fail-closed; it
// never falls back to the legacy wrapper path.
type HostedInvocationGuard struct {
	journal *fabricagent.HostedInvocations
	caller  fabricagent.HostedOwner
	resolve func(ctx context.Context, instanceID string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error)
}

// NewHostedInvocationGuard composes the daemon delivery guard over the step-1
// signed initial-effect journal. A nil journal, caller or resolver yields
// nil: the daemon then refuses hosted invocation delivery instead of
// inventing authority.
func NewHostedInvocationGuard(journal *fabricagent.HostedInvocations, caller fabricagent.HostedOwner, resolve func(ctx context.Context, instanceID string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error)) *HostedInvocationGuard {
	if journal == nil || caller == nil || resolve == nil {
		return nil
	}
	return &HostedInvocationGuard{journal: journal, caller: caller, resolve: resolve}
}

// deliverHostedInvocation verifies a transported original hosted invocation
// against the signed initial-effect journal and accepts the retained prompt
// text as a native prompt. A canonical invocation NEVER falls through the
// legacy wrapper path: every mismatch is a conflict, never a deferral, a
// retry or a wrapped fallback. Ordinary delivery kinds do not reach here.
func (d *Daemon) deliverHostedInvocation(conn *websocket.Conn, p transport.NetworkEventPayload) error {
	if d.HostedInvocationGuard == nil {
		return ErrNativeObservationConflict
	}
	// The server contract for kind="invocation": the accepted original
	// association carries the invocation source (never a task source), and no
	// message/task/conversation/event references exist for the delivery.
	source := p.NativeDispatch.InvocationSource
	if source == nil || source.Validate() != nil || p.NativeDispatch.TaskSource != nil ||
		p.MessageID != "" || p.TaskID != "" || p.ConversationID != "" || p.EventID != "" ||
		p.Envelope == nil || p.AAD == nil {
		return ErrNativeObservationConflict
	}
	// The relayed protected content must be the EXACT original the accepted
	// association carries: a regenerated or re-wrapped ciphertext or AAD is a
	// conflict, never accepted.
	if !bytes.Equal(p.AAD.CanonicalBytes(), source.InputAAD.CanonicalBytes()) ||
		p.AAD.Recipient != p.InstanceID || p.AAD.ObjectType != e2ee.ObjectTypeInvocationInput {
		return ErrNativeObservationConflict
	}
	scope, profile, err := d.HostedInvocationGuard.resolve(d.turnCtx, p.InstanceID)
	if err != nil {
		return err
	}
	if profile.Validate() != nil || profile.Scope.InstanceID != p.InstanceID || profile.NetworkID != p.NetworkID ||
		p.NativeDispatch.OwnershipID != profile.OwnershipID || p.NativeDispatch.OwnershipGeneration != profile.Scope.Generation {
		return ErrNativeObservationConflict
	}
	caller, err := d.HostedInvocationGuard.caller(d.turnCtx)
	if err != nil {
		return err
	}
	// The request identifier only satisfies the transport shape validation;
	// the binding to the retained original is the command ID plus the exact
	// sealed AAD and ciphertext checked by the journal.
	delivered := transport.FabricHostedInvocation{
		RequestID:           p.CommandID,
		CommandID:           p.CommandID,
		Ref:                 scope.Endpoint,
		Revision:            scope.ExpectedEndpointRevision,
		InvocationID:        source.InvocationID,
		NetworkID:           p.NetworkID,
		InstanceID:          p.InstanceID,
		OwnershipID:         profile.OwnershipID,
		OwnershipGeneration: profile.Scope.Generation,
		Envelope:            *p.Envelope,
		AAD:                 *p.AAD,
	}
	// The journal is the missing local root finalization proof: it admits the
	// delivery only when it is the exact sealed original for this genuine
	// current caller. Mismatch conflicts; it never defers or loops.
	if _, err := d.HostedInvocationGuard.journal.ValidateDelivered(d.turnCtx, scope, caller, delivered); err != nil {
		return err
	}
	// GCM re-authenticates the retained ciphertext against the retained AAD;
	// the journal already bound both to the sealed original.
	plain, err := d.decryptProtected(p.NetworkID, *p.Envelope, *p.AAD)
	if err != nil {
		return fmt.Errorf("decrypt retained hosted invocation: %w", err)
	}
	prompt, err := hostedInvocationPromptInput([]byte(plain))
	if err != nil {
		return fmt.Errorf("retained hosted invocation is not the exact prompt binding: %w", err)
	}
	if err := d.nativeAcceptOperation(conn, p.InstanceID, p.NativeDispatch, "prompt", sessionworker.Operation{Input: prompt, InputKind: "invocation"}); err != nil {
		return err
	}
	// The accepted original invocation's paid output is consumed by the DAEMON
	// as an async daemon-scoped task (bound to d.turnCtx, never to this
	// delivery connection): a control-plane detach — or a daemon restart —
	// must not stop the paid work or lose its retained final output. The
	// consumption is idempotent and restartable from daemon state; errors are
	// logged honestly and never panic the delivery path. The local admission
	// path (AdmitHostedFabric) reaches the SAME entry point in step 6.
	go func() {
		if err := d.ConsumeHostedInvocationFinalOutput(d.turnCtx, profile, *p.NativeDispatch); err != nil && !errors.Is(err, context.Canceled) {
			d.Log.Warn("hosted invocation final output consumption stopped", "instance", p.InstanceID, "command", p.CommandID, "err", err)
		}
	}()
	return nil
}

// hostedInvocationPromptInput is the exact BindHostedPrompt input grammar: a
// JSON object with a single nonempty "input" string field (up to 128 KiB),
// mirrored from nativeauthority.JSONPromptBinder so a retained hosted
// invocation prompt and a local native prompt are one schema. Anything else
// is not a retained hosted invocation prompt.
func hostedInvocationPromptInput(plain []byte) (string, error) {
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
