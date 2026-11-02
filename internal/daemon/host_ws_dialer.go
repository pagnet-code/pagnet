package daemon

import (
	"context"
	"errors"
	"net"

	"github.com/gorilla/websocket"
)

// hostWSDialer keeps the default WebSocket options, including proxy and TLS
// handling. Only the TCP address family changes for the opt-in experiment.
func hostWSDialer(ipv4Only bool) (*websocket.Dialer, error) {
	dialer := *websocket.DefaultDialer
	if ipv4Only {
		if dialer.NetDial != nil || dialer.NetDialContext != nil || dialer.NetDialTLSContext != nil {
			return nil, errors.New("PAGNET_HOST_WS_IPV4_ONLY cannot override custom WebSocket dial hooks")
		}
		dialer.NetDialContext = dialHostWSIPv4
	}
	return &dialer, nil
}

func dialHostWSIPv4(ctx context.Context, _ string, addr string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp4", addr)
}
