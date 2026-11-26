//go:build linux || darwin

package daemon

import (
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func (d *Daemon) directManagedSourceV2HostReady() bool {
	if !d.DirectManagedSourceV2Enabled || d.nativeRegistry == nil || d.state == nil || d.serveLockFile == nil || !d.runtimeSupported(domain.RuntimeQwenCode) {
		return false
	}
	if _, err := d.serveLockFile.Stat(); err != nil {
		return false
	}
	return directManagedSourceV2ServerOrigin(d.ServerURL) != ""
}

func (d *Daemon) initDirectManagedSourceV2() {
	if !d.directManagedSourceV2HostReady() {
		return
	}
	executor, err := newLocalDirectManagedSourceCredentialV2(d)
	if err != nil || !executor.ready() {
		return
	}
	d.directManagedSourcePrepareV2 = executor.localDirectManagedSourcePrepareV2
	d.directManagedSourcePoPV2 = executor.localDirectManagedSourcePoPV2
	d.directManagedSourceCredentialV2 = executor
}

func (d *Daemon) directManagedSourceV2Ready() bool {
	return d.directManagedSourceV2HostReady() && d.directManagedSourcePrepareReadyV2() && d.directManagedSourcePoPReadyV2() && d.directManagedSourceCredentialReadyV2()
}

func (d *Daemon) directManagedSourceV2Handlers(socket *websocket.Conn, native *NativeObservationConnection) ([]func(transport.Envelope) bool, func()) {
	session, err := native.AuthenticatedNativeHostSession()
	if err != nil || !d.DirectManagedSourceV2Enabled || !native.validDirectManagedSourceSelection(session.ProtocolFeatures) {
		return nil, nil
	}
	for i, protocol := range directManagedSourceProtocolsV2 {
		if native.offeredDirectManagedSourceV2[i] != protocol {
			return nil, nil
		}
	}
	prepare := newDirectManagedSourcePrepareConnectionV2(d, socket, native, &directManagedSourcePrepareNegotiationV2{socket: socket, native: native, session: session})
	pop := newDirectManagedSourcePoPConnectionV2(d, socket, native, &directManagedSourcePoPNegotiationV2{socket: socket, native: native, session: session})
	credential := newDirectManagedSourceCredentialConnectionV2(d, socket, native, &directManagedSourceCredentialNegotiationV2{socket: socket, native: native, session: session})
	if prepare == nil || pop == nil || credential == nil {
		if prepare != nil {
			prepare.close()
		}
		if pop != nil {
			pop.close()
		}
		if credential != nil {
			credential.close()
		}
		return nil, nil
	}
	return []func(transport.Envelope) bool{prepare.handle, pop.handle, credential.handle}, func() { prepare.close(); pop.close(); credential.close() }
}

// Only reserved suite offers may be inherited in configuration. Any other
// query or malformed encoding cannot become authenticated origin authority.
func directManagedSourceV2ServerOrigin(value string) string {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.User != nil || strings.Contains(value, "#") {
		return ""
	}
	query, err := url.ParseQuery(endpoint.RawQuery)
	if err != nil {
		return ""
	}
	for _, key := range directManagedSourceQueryKeys {
		query.Del(key)
	}
	query.Del("direct_endpoint_wake")
	if len(query) != 0 {
		return ""
	}
	endpoint.RawQuery = ""
	endpoint.ForceQuery = false
	return managedPrepareServerOrigin(endpoint.String())
}
