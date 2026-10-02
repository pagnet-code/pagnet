package daemon

import (
	"fmt"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// doNativeDeliver accepts the actual original delivery in the durable owner.
// A task without its authenticated original crypto descriptor stays queued.
func (d *Daemon) doNativeDeliver(conn *websocket.Conn, p transport.NetworkEventPayload) error {
	if p.NativeDispatch == nil || p.NativeDispatch.SourceCommandID != p.CommandID {
		return ErrNativeObservationConflict
	}
	row, ok, err := d.state.GetInstance(p.InstanceID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrDeferred
	}
	kind := p.Kind
	if kind == "" {
		kind = "notice"
	}
	if kind == "channel" {
		kind = "user_input"
	}
	if kind == "reply" {
		kind = "notice"
	}
	var input string
	if p.EventID != "" || p.EventType != "" {
		input = d.eventTriggerInput(row, p)
		kind = "notice"
		if p.NativeDispatch.TaskSource != nil {
			kind = "task"
		}
	} else {
		network := row.NetworkID
		if network == "" {
			network = p.NetworkID
		}
		if p.Envelope != nil && p.AAD != nil {
			plain, err := d.decryptProtected(network, *p.Envelope, *p.AAD)
			if err != nil {
				return fmt.Errorf("decrypt original delivery: %w", err)
			}
			p.Body = plain
			if p.AAD.ObjectType == "task" {
				p.Body, err = d.materializeTaskContent(row, plain)
				if err != nil {
					return fmt.Errorf("decode original task: %w", err)
				}
			}
			if p.Kind == "ask" || p.Kind == "reply" || (p.AAD.ObjectType == "message" && p.MessageID != "") {
				parts, err := domain.DecodeMessageContent([]byte(plain))
				if err != nil {
					return fmt.Errorf("decode original message: %w", err)
				}
				p.Body = domain.RenderMessageParts(parts)
			}
			p.AcceptanceCriteria = nil
		} else if network != "" && deliveryHasContent(p) {
			return fmt.Errorf("original private delivery has no encrypted content")
		}
		input, err = d.compactDeliveryInput(row, p)
		if err != nil {
			return err
		}
	}
	if kind == "task" && p.NativeDispatch.TaskSource == nil {
		return ErrDeferred
	}
	if !sessionworker.ValidNativeInputKind(kind) {
		return fmt.Errorf("unsupported original delivery kind")
	}
	return d.nativeAcceptOperation(conn, p.InstanceID, p.NativeDispatch, "prompt", sessionworker.Operation{Input: input, InputKind: kind})
}
