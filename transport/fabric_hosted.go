package transport

import (
	"encoding/json"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
)

// Hosted Fabric routes retain opaque catalog bodies. These are control-plane
// operations, never runtime tools or an alternate discovery/routing model.
const (
	FabricHostedProtocol       = "fabric-hosted-native-v1"
	MsgFabricHostedPublish     = "host.fabric_hosted_publish"
	MsgFabricHostedPublished   = "host.fabric_hosted_published"
	MsgFabricHostedInvoke      = "host.fabric_hosted_invoke"
	MsgFabricHostedInvoked     = "host.fabric_hosted_invoked"
	ObjectTypeFabricDescriptor = "fabric_descriptor"
)

type FabricHostedPublication struct {
	RequestID           string                  `json:"requestId"`
	Ref                 fabric.EndpointRef      `json:"ref"`
	Revision            fabric.Revision         `json:"revision"`
	ExpectedRevision    fabric.Revision         `json:"expectedRevision,omitempty"`
	DomainPublicKey     []byte                  `json:"domainPublicKey"`
	// Tombstone is routing metadata for the sealed record this publication
	// carries: true when that signed record's action kind ends in ".retire".
	// The publisher derives it from the signed record; the importer re-checks
	// it against the signed body — it is never a trust input.
	Tombstone           bool                    `json:"tombstone"`
	NetworkID           string                  `json:"networkId"`
	InstanceID          string                  `json:"instanceId"`
	OwnershipID         string                  `json:"ownershipId"`
	OwnershipGeneration string                  `json:"ownershipGeneration"`
	Envelope            e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD                 e2ee.AAD                `json:"aad"`
}

func (p FabricHostedPublication) Validate() error {
	namespace, err := fabric.DomainNamespace(p.DomainPublicKey)
	if err != nil || p.Ref.IsOffer() || p.Ref.Domain() != namespace || p.Revision == "" || len(p.Revision) > 256 || len(p.ExpectedRevision) > 256 || len(p.OwnershipGeneration) == 0 || len(p.OwnershipGeneration) > 256 {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid hosted catalog routing")
	}
	for _, id := range []string{p.RequestID, p.NetworkID, p.InstanceID, p.OwnershipID} {
		if _, err := domain.ParseID(id); err != nil {
			return fabric.NewError(fabric.CodeInvalidInput, "Invalid private hosted identity")
		}
	}
	if p.Envelope.Validate() != nil || p.AAD.ValidateScope() != nil || p.AAD.ProtocolVersion != ProtocolVersion || p.AAD.ObjectType != ObjectTypeFabricDescriptor || p.AAD.ObjectID != p.Ref.String() || p.AAD.Sender != p.InstanceID || p.AAD.Recipient != p.Ref.String() || p.AAD.NetworkID != p.NetworkID || p.AAD.KeyEpochID != p.Envelope.KeyEpochID || p.AAD.NativeContent != nil || p.AAD.ProtectedContext != nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid protected hosted descriptor")
	}
	if raw, err := json.Marshal(p); err != nil || len(raw) > 512<<10 {
		return fabric.NewError(fabric.CodeInvalidInput, "Hosted descriptor exceeds transport budget")
	}
	return nil
}

type FabricHostedInvocation struct {
	RequestID           string                  `json:"requestId"`
	CommandID           string                  `json:"commandId"`
	Ref                 fabric.EndpointRef      `json:"ref"`
	Revision            fabric.Revision         `json:"revision"`
	InvocationID        string                  `json:"invocationId"`
	NetworkID           string                  `json:"networkId"`
	InstanceID          string                  `json:"instanceId"`
	OwnershipID         string                  `json:"ownershipId"`
	OwnershipGeneration string                  `json:"ownershipGeneration"`
	Envelope            e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD                 e2ee.AAD                `json:"aad"`
}

func (p FabricHostedInvocation) Validate() error {
	if p.Ref.IsOffer() || p.Ref.Domain() == "" || p.Revision == "" || len(p.Revision) > 256 || p.OwnershipGeneration == "" || len(p.OwnershipGeneration) > 256 {
		return fabric.NewError(fabric.CodeInvalidInput, "Exact hosted target required")
	}
	for _, id := range []string{p.RequestID, p.CommandID, p.NetworkID, p.InstanceID, p.OwnershipID} {
		if _, err := domain.ParseID(id); err != nil {
			return fabric.NewError(fabric.CodeInvalidInput, "Invalid private hosted identity")
		}
	}
	source := NativeInvocationSource{InvocationID: p.InvocationID, InputAAD: p.AAD}
	if source.Validate() != nil || p.Envelope.Validate() != nil || p.AAD.ProtocolVersion != ProtocolVersion || p.AAD.NetworkID != p.NetworkID || p.AAD.KeyEpochID != p.Envelope.KeyEpochID || p.AAD.ProtectedContext != nil || p.AAD.Recipient != p.InstanceID {
		return fabric.NewError(fabric.CodeInvalidInput, "Exact protected hosted input required")
	}
	if raw, err := json.Marshal(p); err != nil || len(raw) > 512<<10 {
		return fabric.NewError(fabric.CodeInvalidInput, "Hosted invocation exceeds transport budget")
	}
	return nil
}

type FabricHostedResult struct {
	RequestID string               `json:"requestId"`
	Ref       fabric.EndpointRef   `json:"ref"`
	Revision  fabric.Revision      `json:"revision"`
	CommandID string               `json:"commandId,omitempty"`
	Proof     *NativeDispatchProof `json:"proof,omitempty"`
	Error     *fabric.Error        `json:"error,omitempty"`
}
