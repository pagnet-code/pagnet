package daemon

import (
	"context"
	"slices"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/transport"
)

func (c *NativeObservationConnection) hostedFabricDisposition(p transport.FabricHostedResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return
	default:
	}
	if ch := c.pendingHostedFabric[p.RequestID]; ch != nil {
		select {
		case ch <- p:
		default:
		}
	}
}

// Exact connection ownership and finite capacity apply to these new operations
// as to existing native admission. Disconnect never selects a new connection.
func (c *NativeObservationConnection) hostedFabricExchange(ctx context.Context, id, typ string, payload any) (transport.FabricHostedResult, error) {
	ctx, cancel := nativeDeliveryContext(ctx)
	defer cancel()
	ch := make(chan transport.FabricHostedResult, 1)
	c.mu.Lock()
	if err := c.deliveryReadyLocked(false); err != nil {
		c.mu.Unlock()
		return transport.FabricHostedResult{}, err
	}
	if !slices.Contains(c.session.ProtocolFeatures, transport.FabricHostedProtocol) {
		c.mu.Unlock()
		return transport.FabricHostedResult{}, fabric.NewError(fabric.CodeUnsupported, "Hosted Fabric protocol is not configured")
	}
	if c.pendingCountLocked() >= 64 {
		c.mu.Unlock()
		return transport.FabricHostedResult{}, ErrNativeObservationCapacity
	}
	if c.pendingHostedFabric == nil {
		c.pendingHostedFabric = map[string]chan transport.FabricHostedResult{}
	}
	if c.pendingHostedFabric[id] != nil {
		c.mu.Unlock()
		return transport.FabricHostedResult{}, ErrNativeObservationConflict
	}
	c.pendingHostedFabric[id] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pendingHostedFabric, id); c.mu.Unlock() }()
	if err := c.send(ctx, typ, payload); err != nil {
		return transport.FabricHostedResult{}, err
	}
	select {
	case <-ctx.Done():
		return transport.FabricHostedResult{}, ctx.Err()
	case <-c.closed:
		return transport.FabricHostedResult{}, ErrNativeOriginAdmissionDeferred
	case result := <-ch:
		if _, err := c.AuthenticatedNativeHostSession(); err != nil {
			return transport.FabricHostedResult{}, err
		}
		if err := ctx.Err(); err != nil {
			return transport.FabricHostedResult{}, err
		}
		if result.Error != nil {
			return transport.FabricHostedResult{}, result.Error
		}
		return result, nil
	}
}

func (c *NativeObservationConnection) PublishHostedFabric(ctx context.Context, p transport.FabricHostedPublication) error {
	if err := p.Validate(); err != nil {
		return err
	}
	result, err := c.hostedFabricExchange(ctx, p.RequestID, transport.MsgFabricHostedPublish, p)
	if err != nil {
		return err
	}
	if result.Ref != p.Ref || result.Revision != p.Revision || result.CommandID != "" || result.Proof != nil {
		return ErrNativeObservationConflict
	}
	return nil
}

func (c *NativeObservationConnection) AdmitHostedFabric(ctx context.Context, p transport.FabricHostedInvocation) (*transport.NativeDispatchProof, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	result, err := c.hostedFabricExchange(ctx, p.RequestID, transport.MsgFabricHostedInvoke, p)
	if err != nil {
		return nil, err
	}
	proof := result.Proof
	if result.Ref != p.Ref || result.Revision != p.Revision || result.CommandID != p.CommandID || proof == nil || proof.OwnershipID != p.OwnershipID || proof.OwnershipGeneration != p.OwnershipGeneration || proof.SourceCommandID != p.CommandID || proof.InvocationSource == nil || proof.InvocationSource.InvocationID != p.InvocationID || string(proof.InvocationSource.InputAAD.CanonicalBytes()) != string(p.AAD.CanonicalBytes()) || proof.DispatchSequence <= 0 {
		return nil, ErrNativeObservationConflict
	}
	return proof, nil
}
