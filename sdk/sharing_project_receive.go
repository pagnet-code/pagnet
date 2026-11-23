package sdk

import (
	"context"
	"errors"
	"net/http"
	"strconv"
)

// SharingProjectMessage contains an authenticated message and its exact incoming
// wire, which can be supplied as the predecessor when preparing a reply.
type SharingProjectMessage struct {
	Header    SharingProjectMessageHeader
	Plaintext []byte
	Wire      []byte
}

func invokeSharingProjectHandler(ctx context.Context, handler func(context.Context, SharingProjectMessage) error, message SharingProjectMessage) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("sdk: sharing project message handler panicked")
		}
	}()
	return handler(ctx, message)
}

// ReceiveSharingProjectMessages drains the current pending project inbox.
// Delivery is at least once: a handler failure or uncertain ACK permits redelivery.
func (c *Client) ReceiveSharingProjectMessages(ctx context.Context, project string, handler func(context.Context, SharingProjectMessage) error) error {
	if handler == nil {
		return errors.New("sdk: sharing project message handler is required")
	}
	s, err := c.projectTransportSession(ctx, project)
	if err != nil {
		return err
	}
	current := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return s.current(c)
	}
	cursor := ""
	var cursorNumber int64
	for {
		if err := current(); err != nil {
			return err
		}
		page, err := c.SharingProjectInbox(ctx, project, cursor, 50)
		if err != nil {
			return err
		}
		if len(page.Messages) > 50 {
			return errors.New("sdk: sharing project inbox page exceeds limit")
		}
		var nextNumber int64
		if page.NextCursor != "" {
			nextNumber, err = strconv.ParseInt(page.NextCursor, 10, 64)
			if err != nil || nextNumber <= cursorNumber || len(page.Messages) == 0 {
				return errors.New("sdk: invalid sharing project inbox cursor")
			}
		}
		for _, wire := range page.Messages {
			message, err := c.DecryptSharingProjectMessage(project, wire, nil)
			if err != nil {
				return err
			}
			if err := current(); err != nil {
				return err
			}
			if err := invokeSharingProjectHandler(ctx, handler, SharingProjectMessage{
				Header: message.Header, Plaintext: message.Plaintext, Wire: append([]byte(nil), wire...),
			}); err != nil {
				return err
			}
			if err := current(); err != nil {
				return err
			}
			var headers http.Header
			if err := c.rest.doWithHeaders(ctx, http.MethodPost, projectMessagesPath(project)+"/"+message.Header.ID+"/ack", map[string]string{"endpointId": s.endpoint}, nil, &headers); err != nil {
				return projectTransportError(err, headers)
			}
			if err := current(); err != nil {
				return err
			}
		}
		if page.NextCursor == "" {
			return current()
		}
		cursor, cursorNumber = page.NextCursor, nextNumber
	}
}
