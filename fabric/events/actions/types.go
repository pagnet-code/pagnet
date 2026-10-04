// Package actions durably queues explicitly authorized emits and generic triggers.
// Queue receipts never assert target execution or completion.
package actions

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
)

type TriggerDefinition struct {
	ID                  string             `json:"id"`
	Revision            string             `json:"revision"`
	Source              string             `json:"source"`
	Type                string             `json:"type"`
	Target              fabric.EndpointRef `json:"target"`
	TargetRevision      fabric.Revision    `json:"targetRevision"`
	BindingDigest       string             `json:"bindingDigest"`
	SignedAuthorization []byte             `json:"signedAuthorization"`
}

// DefinitionAuthority verifies signed registrations and current permission on
// every enqueue/delivery. A public descriptor or asserted signature is not authority.
type DefinitionAuthority interface {
	Verify(context.Context, durable.Scope, TriggerDefinition) error
}

// Proof is bounded, persistable signature evidence, NOT a bearer/provider secret.
// SourceAuthority must verify exact original bytes, proof, audience, producer,
// and genuine parent lineage; it must not trust serialized ExecutionContext.
type SourceInput struct {
	ExactEvent []byte `json:"exactEvent"`
	Proof      []byte `json:"proof"`
}
type VerifiedSource struct {
	Caller fabric.ExecutionContext
	Parent *fabric.Envelope
}
type SourceAuthority interface {
	Verify(context.Context, durable.Scope, SourceInput) (VerifiedSource, error)
}
type EmitRequest struct {
	Target   fabric.EndpointRef `json:"target"`
	Revision fabric.Revision    `json:"revision"`
	Input    json.RawMessage    `json:"input"`
}
type Preparation struct {
	ID         string
	CreatedAt  time.Time
	Request    EmitRequest
	Context    fabric.EnvelopeContext
	Definition *TriggerDefinition
}

// Prepare authorizes exactly this action and builds exact finalized bytes. It
// must deterministically honor the engine ID/time/context across identical retries.
// Check revalidates current authority over the retained original action; it does
// not reprepare, repatch, or dispatch it.
type Authorizer interface {
	Prepare(context.Context, fabric.ExecutionContext, Preparation) ([]byte, error)
	Check(context.Context, fabric.ExecutionContext, Action) error
}
type Action struct {
	ID                 string `json:"id"`
	ExactEnvelope      []byte `json:"exactEnvelope"`
	DefinitionID       string `json:"definitionId,omitempty"`
	DefinitionRevision string `json:"definitionRevision,omitempty"`
	EventSource        string `json:"eventSource"`
	EventID            string `json:"eventId"`
	EventDigest        string `json:"eventDigest"`
}
type AdmissionReceipt struct {
	ActionID, EnvelopeDigest, AdmissionID string
	AcceptedAt                            time.Time
}

// Admitter is a genuine atomic infrastructure acceptance/query boundary. Retry
// the SAME action returns its exact durable receipt, never repeats an ambiguous
// adapter effect. Node.Execute alone does not implement this contract.
type AdmissionRequest struct {
	Action Action
	Source SourceInput
	Caller fabric.ExecutionContext
}
type Admitter interface {
	AdmitOrGet(context.Context, AdmissionRequest) (AdmissionReceipt, error)
}
type Config struct {
	Scope                                                      durable.Scope
	Definitions                                                []TriggerDefinition
	MaxDefinitions, MaxFanout, MaxProofBytes, MaxEnvelopeBytes int
	Queue                                                      durable.Config
	SourceAuthority                                            SourceAuthority
	DefinitionAuthority                                        DefinitionAuthority
	Authorizer                                                 Authorizer
	Admitter                                                   Admitter
	Protector                                                  durable.DataProtector
}

func DefaultConfig(scope durable.Scope) Config {
	return Config{Scope: scope, MaxDefinitions: 128, MaxFanout: 32, MaxProofBytes: 65536, MaxEnvelopeBytes: 65536, Queue: durable.DefaultConfig([]durable.Subscription{{ID: "actions.dispatch", Types: []string{"dev.pagnet.actions.queued"}}})}
}
