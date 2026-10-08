// ControlChannel is the source-side client for one committed control unit
// (E1 slice-2c, D3): it opens one fresh relay connection per control unit,
// sends the signed ControlRequest (record 4), receives the committed control
// reply (record 5) and, for a pull, the retained final frames (record 6),
// then closes the connection. It performs no authentication of its own: the
// request must already carry the genuine signed source-root proof, and the
// destination's ControlLedger re-authenticates it independently.

package fabricnode

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
)

type ControlChannel struct {
	relaySocket string
	sourceCfg   federation.Config
}

func NewControlChannel(relaySocket string, sourceCfg federation.Config) *ControlChannel {
	return &ControlChannel{relaySocket: relaySocket, sourceCfg: sourceCfg}
}

// Execute runs one control unit end-to-end over a fresh relay connection. The
// returned error is the transport/reply outcome only: a destination that
// refuses the control (authentication, stale cursor, capacity, actuation)
// closes the connection without a reply. A clean close after the reply ends a
// pull's frame page (io.EOF), even when the page served no frames.
func (c *ControlChannel) Execute(ctx context.Context, request federation.ControlRequest) (federation.ControlReply, []fabric.InvocationFrame, error) {
	if c == nil || c.relaySocket == "" {
		return federation.ControlReply{}, nil, localDenied()
	}
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.relaySocket, Net: "unix"})
	if e != nil {
		return federation.ControlReply{}, nil, e
	}
	stream, e := federation.NewConnStream(conn, federationServingConnLifetime)
	if e != nil {
		return federation.ControlReply{}, nil, e
	}
	duplex, e := federation.NewDuplex(ctx, c.sourceCfg, stream, federationServingMaxBytes)
	if e != nil {
		_ = duplex.Close()
		return federation.ControlReply{}, nil, e
	}
	channel, e := federation.NewForwardChannel(duplex)
	if e != nil {
		_ = duplex.Close()
		return federation.ControlReply{}, nil, e
	}
	defer channel.Close()
	if e := channel.SendControl(ctx, request); e != nil {
		return federation.ControlReply{}, nil, e
	}
	reply, e := channel.ReceiveControlReply(ctx, request)
	if e != nil {
		return federation.ControlReply{}, nil, e
	}
	if request.Proof.Frame.Action != "pull" {
		return reply, nil, nil
	}
	page, e := federation.NewPullPage(channel, request)
	if e != nil {
		return reply, nil, e
	}
	var frames []fabric.InvocationFrame
	for {
		frame, e := page.Receive(ctx)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return reply, frames, e
		}
		frames = append(frames, frame)
	}
	return reply, frames, nil
}
