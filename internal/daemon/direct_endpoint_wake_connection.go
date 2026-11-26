package daemon

import (
	"net/url"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

// Wake is supported only for the source-v2 and target-v1 credential suites.
// The dial query has already been rebuilt from implementation readiness.
func directEndpointWakeSuiteOffered(q url.Values) bool {
	exact := func(key, protocol string) bool { values := q[key]; return len(values) == 1 && values[0] == protocol }
	source := true
	for i, key := range directManagedSourceQueryKeys {
		source = source && exact(key, directManagedSourceProtocolsV2[i])
	}
	target := exact("managed_endpoint_prepare", transport.ManagedEndpointPrepareProtocol) && exact("managed_endpoint_pop", transport.ManagedEndpointPoPProtocol) && exact("managed_direct_credential", transport.ManagedDirectCredentialProtocol)
	return source || target
}

func (c *NativeObservationConnection) captureDirectEndpointWakeOffer(q url.Values) {
	values := q[transport.DirectEndpointWakeQueryKey]
	c.offeredDirectEndpointWake = len(values) == 1 && values[0] == transport.DirectEndpointWakeProtocolV1 && directEndpointWakeSuiteOffered(q)
}

// Called after each credential suite's own offer and selection validation.
func (c *NativeObservationConnection) validDirectEndpointWakeSelection(features []string) bool {
	count, source, target := 0, false, false
	for _, feature := range features {
		switch feature {
		case transport.DirectEndpointWakeFeatureV1:
			count++
		case transport.DirectManagedSourceCredentialProtocolV2:
			source = true
		case transport.ManagedDirectCredentialProtocol:
			target = true
		}
	}
	return count == 0 || (count == 1 && c.offeredDirectEndpointWake && (source || target))
}

// directEndpointWakeConnection reserves the wake lane on one captured socket.
// Phase one deliberately has no subscriptions, writers, HTTP work or replay.
type directEndpointWakeConnection struct {
	socket *websocket.Conn
	native *NativeObservationConnection
	done   chan struct{}
	once   sync.Once
}

func newDirectEndpointWakeConnection(socket *websocket.Conn, native *NativeObservationConnection) *directEndpointWakeConnection {
	c := &directEndpointWakeConnection{socket: socket, native: native, done: make(chan struct{})}
	native.mu.Lock()
	native.directWake = c
	select {
	case <-native.closed:
		c.close()
	default:
	}
	native.mu.Unlock()
	return c
}

func (c *directEndpointWakeConnection) close() {
	if c != nil {
		c.once.Do(func() { close(c.done) })
	}
}

// No subscription can be attached in phase one. Any reserved wake message
// therefore violates this connection's protocol and must close it without ACK.
func (c *directEndpointWakeConnection) handle(env transport.Envelope) (bool, error) {
	switch env.Type {
	case transport.MsgDirectEndpointWakeSubscribe, transport.MsgDirectEndpointWakeOffer, transport.MsgDirectEndpointWakeACK, transport.MsgDirectEndpointWakeUnsubscribe, transport.MsgDirectEndpointWakeClosed:
		return true, ErrNativeObservationConflict
	default:
		return false, nil
	}
}
