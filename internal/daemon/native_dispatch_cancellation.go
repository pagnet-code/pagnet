package daemon

import (
	"context"
	"slices"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func (c *NativeObservationConnection) CancellationDisposition(env transport.Envelope) error {
	var header struct {
		RequestID string `json:"requestId"`
	}
	if err := env.DecodePayload(&header); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return nil
	default:
	}
	if ch := c.pendingCancellations[header.RequestID]; ch != nil {
		select {
		case ch <- env:
		default:
		}
	}
	return nil
}
func (c *NativeObservationConnection) cancellationExchange(ctx context.Context, requestID, typ string, payload any) (transport.Envelope, error) {
	ctx, cancel := nativeDeliveryContext(ctx)
	defer cancel()
	ch := make(chan transport.Envelope, 1)
	c.mu.Lock()
	if err := c.deliveryReadyLocked(false); err != nil {
		c.mu.Unlock()
		return transport.Envelope{}, err
	}
	if !slices.Contains(c.session.ProtocolFeatures, transport.NativeDispatchCancellationProtocol) {
		c.mu.Unlock()
		return transport.Envelope{}, ErrNativeSourceUnsupported
	}
	if c.pendingCountLocked() >= 64 {
		c.mu.Unlock()
		return transport.Envelope{}, ErrNativeObservationCapacity
	}
	if c.pendingCancellations == nil {
		c.pendingCancellations = map[string]chan transport.Envelope{}
	}
	if c.pendingCancellations[requestID] != nil {
		c.mu.Unlock()
		return transport.Envelope{}, ErrNativeObservationConflict
	}
	c.pendingCancellations[requestID] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pendingCancellations, requestID); c.mu.Unlock() }()
	if err := c.send(ctx, typ, payload); err != nil {
		return transport.Envelope{}, err
	}
	select {
	case <-ctx.Done():
		return transport.Envelope{}, ctx.Err()
	case <-c.closed:
		return transport.Envelope{}, ErrNativeOriginAdmissionDeferred
	case response := <-ch:
		if _, err := c.AuthenticatedNativeHostSession(); err != nil {
			return transport.Envelope{}, err
		}
		return response, nil
	}
}
func (c *NativeObservationConnection) DispatchCancellationProposals(ctx context.Context, ownership transport.NativeWorkerOwnership, after int64) (transport.NativeDispatchCancelProposedPayload, error) {
	request := transport.NativeDispatchCancelProposalsPayload{RequestID: domain.NewID().String(), OwnershipID: ownership.ID, OwnershipGeneration: ownership.OwnershipGeneration, AfterDispatchSequence: after, Limit: 16}
	env, err := c.cancellationExchange(ctx, request.RequestID, transport.MsgNativeDispatchCancelProposals, request)
	var response transport.NativeDispatchCancelProposedPayload
	if err != nil {
		return response, err
	}
	if env.Type != transport.MsgNativeDispatchCancelProposed || env.DecodePayload(&response) != nil || response.RequestID != request.RequestID || response.OwnershipID != ownership.ID || response.OwnershipGeneration != ownership.OwnershipGeneration {
		return response, ErrNativeObservationConflict
	}
	if response.PublicError != "" {
		if response.Retryable {
			return response, ErrNativeOriginAdmissionDeferred
		}
		return response, ErrNativeOriginAdmissionRejected
	}
	if len(response.Proposals) > request.Limit {
		return response, ErrNativeObservationConflict
	}
	previous := after
	for _, proposal := range response.Proposals {
		proof := proposal.Proof
		if proposal.InstanceID != ownership.InstanceID || proof.OwnershipID != ownership.ID || proof.OwnershipGeneration != ownership.OwnershipGeneration || proof.DispatchSequence <= previous || proof.SourceCommandID == "" || proof.SourceAdmissionID == "" || (proposal.Reason != "withdrawn" && proposal.Reason != "expired") {
			return response, ErrNativeObservationConflict
		}
		previous = proof.DispatchSequence
	}
	if response.NextAfter != nil && (*response.NextAfter <= after || *response.NextAfter < previous) {
		return response, ErrNativeObservationConflict
	}
	return response, nil
}
func (c *NativeObservationConnection) CommitDispatchCancellation(ctx context.Context, request transport.NativeDispatchCancelPayload) (transport.NativeDispatchCancelledPayload, error) {
	env, err := c.cancellationExchange(ctx, request.RequestID, transport.MsgNativeDispatchCancel, request)
	var response transport.NativeDispatchCancelledPayload
	if err != nil {
		return response, err
	}
	if env.Type != transport.MsgNativeDispatchCancelled || env.DecodePayload(&response) != nil || response.RequestID != request.RequestID || response.PreparationID != request.PreparationID || response.InstanceID != request.InstanceID {
		return response, ErrNativeObservationConflict
	}
	if response.PublicError != "" {
		if response.Retryable {
			return response, ErrNativeOriginAdmissionDeferred
		}
		return response, ErrNativeOriginAdmissionRejected
	}
	p := response.Proof
	if response.Disposition != "cancelled" || p == nil || p.OwnershipID != request.OwnershipID || p.OwnershipGeneration != request.OwnershipGeneration || p.DispatchSequence != request.DispatchSequence || p.SourceCommandID != request.SourceCommandID || p.SourceAdmissionID != request.SourceAdmissionID {
		return response, ErrNativeObservationConflict
	}
	return response, nil
}

// Each page is bounded. A prepared worker tombstone must fsync before remote
// cancellation, and its exact committed proof must return before local skip.
func (p *NativeWorkerProxy) ReconcileDispatchCancellations(ctx context.Context, ownership transport.NativeWorkerOwnership) error {
	if p.cancellationCursor < ownership.RetiredFloor {
		p.cancellationCursor = ownership.RetiredFloor
	}
	page, err := p.connection.DispatchCancellationProposals(ctx, ownership, p.cancellationCursor)
	if err != nil {
		return err
	}
	for _, proposal := range page.Proposals {
		prepared, err := p.call(ctx, sessionworker.Request{Type: "cancel_prepare", CancelProposal: &proposal})
		if err != nil {
			return err
		}
		if prepared.Cancellation == nil || prepared.Cancellation.Proposal.Proof.SourceCommandID != proposal.Proof.SourceCommandID {
			return ErrNativeObservationConflict
		}
		if prepared.Cancellation.State == "finalized" {
			continue
		}
		committed, err := p.connection.CommitDispatchCancellation(ctx, prepared.Cancellation.Request)
		if err != nil {
			return err
		}
		if _, err = p.call(ctx, sessionworker.Request{Type: "cancel_finalize", CancelReceipt: &committed}); err != nil {
			return err
		}
	}
	if page.NextAfter == nil {
		p.cancellationCursor = ownership.RetiredFloor
	} else {
		p.cancellationCursor = *page.NextAfter
	}
	return nil
}
