package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func (c *NativeObservationConnection) accountReplyReadyLocked() error {
	if err := c.deliveryReadyLocked(false); err != nil {
		return err
	}
	if !c.accountReplyEnabled || !slices.Contains(c.session.ProtocolFeatures, transport.NativeAccountReplyProtocol) {
		return ErrNativeOriginAdmissionDeferred
	}
	return nil
}

// Replies belong exclusively to the authenticated socket and the specialized
// lane. Neither generic content progress nor observation receipts enter it.
func (c *NativeObservationConnection) accountReplyDisposition(env transport.Envelope) error {
	var identity struct {
		ContentID string `json:"contentId"`
	}
	if len(env.Payload) > transport.NativeAccountReplyMaxWireBytes || json.Unmarshal(env.Payload, &identity) != nil || identity.ContentID == "" {
		return ErrNativeObservationConflict
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.accountReplyReadyLocked(); err != nil {
		return err
	}
	if ch := c.pendingAccountReplies[identity.ContentID]; ch != nil {
		select {
		case ch <- env:
		default:
		}
	}
	return nil
}

func (c *NativeObservationConnection) accountReplyExchange(ctx context.Context, typ string, payload any, ref transport.NativeContentReference) (transport.Envelope, error) {
	ctx, cancel := nativeDeliveryContext(ctx)
	defer cancel()
	ch := make(chan transport.Envelope, 1)
	c.mu.Lock()
	if err := c.accountReplyReadyLocked(); err != nil {
		c.mu.Unlock()
		return transport.Envelope{}, err
	}
	if c.pendingCountLocked() >= 64 {
		c.mu.Unlock()
		return transport.Envelope{}, ErrNativeObservationCapacity
	}
	if c.pendingAccountReplies == nil {
		c.pendingAccountReplies = make(map[string]chan transport.Envelope)
	}
	if c.pendingAccountReplies[ref.ContentID] != nil {
		c.mu.Unlock()
		return transport.Envelope{}, ErrNativeObservationConflict
	}
	c.pendingAccountReplies[ref.ContentID] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pendingAccountReplies, ref.ContentID); c.mu.Unlock() }()
	if err := c.send(ctx, typ, payload); err != nil {
		return transport.Envelope{}, err
	}
	select {
	case <-ctx.Done():
		return transport.Envelope{}, ctx.Err()
	case <-c.closed:
		return transport.Envelope{}, ErrNativeOriginAdmissionDeferred
	case env := <-ch:
		c.mu.Lock()
		err := c.accountReplyReadyLocked()
		c.mu.Unlock()
		if err != nil {
			return transport.Envelope{}, err
		}
		if env.Type == transport.MsgAccountReplyRejected {
			p, err := transport.DecodeNativeAccountReplyRejected(env.Payload, ref)
			if err != nil {
				return env, ErrNativeObservationConflict
			}
			if p.Retryable {
				return env, ErrNativeOriginAdmissionDeferred
			}
			return env, ErrNativeOriginAdmissionRejected
		}
		return env, nil
	}
}

func (c *NativeObservationConnection) deliverAccountReply(ctx context.Context, o sessionworker.NativeObservation, call func(context.Context, sessionworker.Request) (sessionworker.Response, error), budget *int) (bool, error) {
	p, err := sessionworker.NativeAccountReplyObservation(o)
	if err != nil {
		return false, err
	}
	ref := *o.OutputContent
	for {
		// Repeating begin is the bounded missing-fragment query. It always
		// reuses the original reference, including on a fresh connection.
		env, err := c.accountReplyExchange(ctx, transport.MsgAccountReplyBegin, ref, ref)
		if err != nil {
			return false, err
		}
		if env.Type != transport.MsgAccountReplyStaged {
			return false, ErrNativeObservationConflict
		}
		staged, err := transport.DecodeNativeAccountReplyStaged(env.Payload, ref)
		if err != nil {
			return false, ErrNativeObservationConflict
		}
		if len(staged.MissingOrdinals) == 0 {
			break
		}
		for _, ordinal := range staged.MissingOrdinals {
			if *budget <= 0 {
				return false, nil
			}
			response, err := call(ctx, sessionworker.Request{Type: "content_fragment", ObservationID: o.ID, SourceDigest: o.SourceDigest, ContentID: ref.ContentID, ContentOrdinal: ordinal})
			if err != nil {
				return false, err
			}
			if response.Error != "" {
				return false, errors.New(response.Error)
			}
			raw, err := transport.MarshalNativeJSON(response.ContentFragment)
			if err != nil {
				return false, ErrNativeObservationConflict
			}
			fragment, err := transport.DecodeNativeAccountReplyFragment(raw, ref)
			if err != nil || fragment.Ordinal != ordinal {
				return false, ErrNativeObservationConflict
			}
			c.mu.Lock()
			err = c.accountReplyReadyLocked()
			c.mu.Unlock()
			if err != nil {
				return false, err
			}
			if err := c.send(ctx, transport.MsgAccountReplyFragment, response.ContentFragment); err != nil {
				return false, err
			}
			*budget--
		}
	}
	env, err := c.accountReplyExchange(ctx, transport.MsgAccountReplyCommit, p, ref)
	if err != nil {
		return false, err
	}
	if env.Type != transport.MsgAccountReplyReceipt {
		return false, ErrNativeObservationConflict
	}
	receipt, err := transport.DecodeNativeAccountReplyReceipt(env.Payload, ref, p.Digest)
	if err != nil {
		return false, ErrNativeObservationConflict
	}
	response, err := call(ctx, sessionworker.Request{Type: "account_reply_ack", ObservationID: o.ID, SourceDigest: o.SourceDigest, AccountReplyReceipt: &receipt})
	if err != nil {
		return false, err
	}
	if response.Error != "" {
		return false, errors.New(response.Error)
	}
	return true, nil
}
