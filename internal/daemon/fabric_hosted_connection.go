package daemon

import (
	"context"
	"encoding/json"
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

func (c *NativeObservationConnection) hostedFabricCatalogPageDisposition(p transport.FabricHostedCatalogPage) {
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
// The shared core returns the raw correlated reply; each typed exchange
// asserts the reply's type (a mixed-up correlation is a conflict, never a
// silent misparse).
func (c *NativeObservationConnection) hostedFabricExchangeCore(ctx context.Context, id, typ string, payload any) (any, error) {
	ctx, cancel := nativeDeliveryContext(ctx)
	defer cancel()
	ch := make(chan any, 1)
	c.mu.Lock()
	if err := c.deliveryReadyLocked(false); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if !slices.Contains(c.session.ProtocolFeatures, transport.FabricHostedProtocol) {
		c.mu.Unlock()
		return nil, fabric.NewError(fabric.CodeUnsupported, "Hosted Fabric protocol is not configured")
	}
	if c.pendingCountLocked() >= 64 {
		c.mu.Unlock()
		return nil, ErrNativeObservationCapacity
	}
	if c.pendingHostedFabric == nil {
		c.pendingHostedFabric = map[string]chan any{}
	}
	if c.pendingHostedFabric[id] != nil {
		c.mu.Unlock()
		return nil, ErrNativeObservationConflict
	}
	c.pendingHostedFabric[id] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pendingHostedFabric, id); c.mu.Unlock() }()
	if err := c.send(ctx, typ, payload); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, ErrNativeOriginAdmissionDeferred
	case reply := <-ch:
		if _, err := c.AuthenticatedNativeHostSession(); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return reply, nil
	}
}

func (c *NativeObservationConnection) hostedFabricExchange(ctx context.Context, id, typ string, payload any) (transport.FabricHostedResult, error) {
	reply, err := c.hostedFabricExchangeCore(ctx, id, typ, payload)
	if err != nil {
		return transport.FabricHostedResult{}, err
	}
	result, ok := reply.(transport.FabricHostedResult)
	if !ok {
		return transport.FabricHostedResult{}, ErrNativeObservationConflict
	}
	if result.Error != nil {
		return transport.FabricHostedResult{}, result.Error
	}
	return result, nil
}

// RequestHostedFabricCatalog is the daemon's bounded hosted-catalog import
// request over this exact authenticated connection: one page of the
// server-side hosted catalog, correlated by RequestID and re-checked against
// the request (network identity, the DECLARED byte/record bounds — an
// over-bound served page is a protocol violation, not data).
func (c *NativeObservationConnection) RequestHostedFabricCatalog(ctx context.Context, req transport.FabricHostedCatalogRequest) (transport.FabricHostedCatalogPage, error) {
	if err := req.Validate(); err != nil {
		return transport.FabricHostedCatalogPage{}, err
	}
	reply, err := c.hostedFabricExchangeCore(ctx, req.RequestID, transport.MsgFabricHostedCatalogRequest, req)
	if err != nil {
		return transport.FabricHostedCatalogPage{}, err
	}
	page, ok := reply.(transport.FabricHostedCatalogPage)
	if !ok {
		return transport.FabricHostedCatalogPage{}, ErrNativeObservationConflict
	}
	if err := page.Validate(); err != nil {
		return transport.FabricHostedCatalogPage{}, err
	}
	if page.RequestID != req.RequestID || page.NetworkID != req.NetworkID {
		return transport.FabricHostedCatalogPage{}, ErrNativeObservationConflict
	}
	if len(page.Records) > req.MaxRecords {
		return transport.FabricHostedCatalogPage{}, ErrNativeObservationConflict
	}
	if raw, err := json.Marshal(page.Records); err != nil || len(raw) > req.MaxBytes {
		return transport.FabricHostedCatalogPage{}, ErrNativeObservationConflict
	}
	if page.Error != nil {
		return transport.FabricHostedCatalogPage{}, page.Error
	}
	return page, nil
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
