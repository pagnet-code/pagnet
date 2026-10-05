package federation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric"
)

const controlRequestRecord = byte(4)
const controlReplyRecord = byte(5)

// ControlWireStatus deliberately excludes adapter-owned PrivateReference.
type ControlWireStatus struct {
	Attempted       bool           `json:"attempted"`
	CancelRequested bool           `json:"cancelRequested"`
	Cursor          ConsumerCursor `json:"cursor"`
}
type ControlReply struct {
	ReceiptDigest [32]byte          `json:"receiptDigest"`
	ReplayID      string            `json:"replayId"`
	RequestDigest [32]byte          `json:"requestDigest"`
	Status        ControlWireStatus `json:"status"`
	Result        *ControlResult    `json:"result,omitempty"`
}

// SendControl sends one bounded encrypted record; it is not authentication or
// an actuation ACK. The receiver must use ControlLedger.Begin before effects.
func (c *ForwardChannel) SendControl(ctx context.Context, request ControlRequest) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	r, _, e := ownedControl(request)
	if e != nil {
		return e
	}
	if _, e = controlPayload(r); e != nil {
		return e
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	defer clear(raw)
	record := append([]byte{controlRequestRecord}, raw...)
	defer clear(record)
	return c.transport.Send(ctx, record)
}
func (c *ForwardChannel) ReceiveControl(ctx context.Context) (ControlRequest, error) {
	c.receiveMu.Lock()
	defer c.receiveMu.Unlock()
	raw, e := c.transport.Receive(ctx)
	if e != nil {
		return ControlRequest{}, e
	}
	defer clear(raw)
	var request ControlRequest
	if len(raw) < 2 || raw[0] != controlRequestRecord || fabric.DecodeJSONWithLimits(raw[1:], &request, fabric.WireLimits{MaxBytes: 24 << 10, MaxDepth: 16, MaxMembers: 512}) != nil {
		c.Close()
		return request, protocolError()
	}
	owned, _, e := ownedControl(request)
	if e == nil {
		_, e = controlPayload(owned)
	}
	if e != nil {
		c.Close()
		return ControlRequest{}, e
	}
	return owned, nil
}
func replyFor(request ControlRequest, state ControlState) (ControlReply, error) {
	r, digest, e := ownedControl(request)
	if e != nil {
		return ControlReply{}, e
	}
	if _, e = controlPayload(r); e != nil {
		return ControlReply{}, e
	}
	reply := ControlReply{ReceiptDigest: r.Proof.Frame.ReceiptDigest, ReplayID: r.Proof.Frame.ReplayID, RequestDigest: digest, Status: ControlWireStatus{state.Status.Attempted, state.Status.CancelRequested, state.Status.Cursor}, Result: state.Result}
	if !cursorValid(&reply.Status.Cursor) || reply.Result != nil && !validControlResult(r, *reply.Result) {
		return ControlReply{}, protocolError()
	}
	return reply, nil
}

// SendControlReply represents a committed intent when Result==nil. Genuine
// stop ACK or original-frame result requires a separately verified checkpoint.
// Native association/credentials/history are never placed in this record.
func (c *ForwardChannel) SendControlReply(ctx context.Context, request ControlRequest, state ControlState) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	reply, e := replyFor(request, state)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(reply)
	if e != nil || len(raw) > 4096 {
		return protocolError()
	}
	defer clear(raw)
	record := append([]byte{controlReplyRecord}, raw...)
	defer clear(record)
	return c.transport.Send(ctx, record)
}
func (c *ForwardChannel) ReceiveControlReply(ctx context.Context, request ControlRequest) (ControlReply, error) {
	c.receiveMu.Lock()
	defer c.receiveMu.Unlock()
	r, _, e := ownedControl(request)
	if e != nil {
		return ControlReply{}, e
	}
	expected, _ := json.Marshal(r)
	digest := sha256.Sum256(expected)
	clear(expected)
	raw, e := c.transport.Receive(ctx)
	if e != nil {
		return ControlReply{}, e
	}
	defer clear(raw)
	var reply ControlReply
	if len(raw) < 2 || raw[0] != controlReplyRecord || fabric.DecodeJSONWithLimits(raw[1:], &reply, fabric.WireLimits{MaxBytes: 4096, MaxDepth: 8, MaxMembers: 128}) != nil || reply.RequestDigest != digest || reply.ReceiptDigest != r.Proof.Frame.ReceiptDigest || reply.ReplayID != r.Proof.Frame.ReplayID || !cursorValid(&reply.Status.Cursor) || reply.Result != nil && !validControlResult(r, *reply.Result) {
		c.Close()
		return ControlReply{}, protocolError()
	}
	return reply, nil
}
