package sdk

import (
	"context"
	"errors"
)

const ownerTextProjectReceiveLimit = 256

// ErrOwnerTextProjectReceiveLimit reports that this bounded drain processed 256
// messages and may have more pending work. Call ReceiveOwnerTextProjectMessages
// again; the coordinator automatically queues another drain without a timer.
var ErrOwnerTextProjectReceiveLimit = errors.New("sdk: owner text project receive limit reached")

// OwnerTextProjectMessage contains authenticated plaintext and exact incoming
// wire, which can be retained as the predecessor for preparing a REPLY.
type OwnerTextProjectMessage struct {
	Header    OwnerTextProjectMessageHeader
	Plaintext []byte
	Wire      []byte
}

func invokeOwnerTextProjectHandler(ctx context.Context, handler func(context.Context, OwnerTextProjectMessage) error, message OwnerTextProjectMessage) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("sdk: owner text project message handler panicked")
		}
	}()
	return handler(ctx, message)
}

// ReceiveOwnerTextProjectMessages processes at most 256 pending messages, using
// pages of at most 50. Delivery is at least once: handler failure, panic or an
// uncertain ACK permits redelivery. Return nil from the handler only after
// durable processing. With maxInFlight=1, retain the ASK and schedule a REPLY
// after its ACK; sending a REPLY synchronously inside the handler can hit quota.
// Explicit callers can send after this method succeeds. The coordinator does
// not automatically prepare or send replies.
func (c *Client) ReceiveOwnerTextProjectMessages(ctx context.Context, project string, handler func(context.Context, OwnerTextProjectMessage) error) error {
	return c.receiveOwnerTextProjectMessages(ctx, project, handler, nil)
}
func (c *Client) receiveOwnerTextProjectMessages(ctx context.Context, project string, handler func(context.Context, OwnerTextProjectMessage) error, acknowledged func()) error {
	if handler == nil {
		return errors.New("sdk: owner text project handler is required")
	}
	s, err := c.ownerTextProjectTransportSession(ctx, project)
	if err != nil {
		return err
	}
	current := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return s.current(c)
	}
	authority := func() error {
		if err := current(); err != nil {
			return err
		}
		if _, err := c.ownerTextProjectTransportSession(ctx, project); err != nil {
			return err
		}
		return current()
	}
	cursor := ""
	processed := 0
	for {
		if err := current(); err != nil {
			return err
		}
		limit := 50
		if remaining := ownerTextProjectReceiveLimit - processed; remaining < limit {
			limit = remaining
		}
		page, err := c.OwnerTextProjectInbox(ctx, project, cursor, limit)
		if err != nil {
			return err
		}
		for _, wire := range page.Messages {
			message, err := c.DecryptOwnerTextProjectMessage(project, wire, nil, nil)
			if err != nil {
				return err
			}
			if err = authority(); err != nil {
				return err
			}
			if err = invokeOwnerTextProjectHandler(ctx, handler, OwnerTextProjectMessage{Header: message.Header, Plaintext: message.Plaintext, Wire: append([]byte(nil), wire...)}); err != nil {
				return err
			}
			if err = authority(); err != nil {
				return err
			}
			if err = c.AckOwnerTextProjectMessage(ctx, project, message.Header.ID); err != nil {
				return err
			}
			if acknowledged != nil {
				acknowledged()
			}
			if err = current(); err != nil {
				return err
			}
			processed++
		}
		if page.NextCursor == "" {
			return current()
		}
		if processed >= ownerTextProjectReceiveLimit {
			return ErrOwnerTextProjectReceiveLimit
		}
		cursor = page.NextCursor
	}
}
