//go:build linux || darwin

package fabricnode

// The unix domain socket transport for the federation relay listener.

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/pagnet-code/pagnet/fabric/federation"
)

// start replaces a stale relay socket, binds the listener and starts the
// accept loop. A path already held by a live listener is a startup failure.
func (r *federationRelay) start(ctx context.Context) error {
	if r == nil || ctx == nil {
		return localDenied()
	}
	if e := os.Remove(r.path); e != nil && !os.IsNotExist(e) {
		return e
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: r.path, Net: "unix"})
	if e != nil {
		return e
	}
	if e = os.Chmod(r.path, 0o600); e != nil {
		listener.Close()
		return e
	}
	r.listener = listener
	r.started = true
	go r.acceptLoop()
	return nil
}

// acceptLoop joins into CloseContext through acceptDone. A transient accept
// error keeps the listener alive unless shutdown has begun.
func (r *federationRelay) acceptLoop() {
	defer close(r.acceptDone)
	for {
		conn, e := r.listener.Accept()
		if e != nil {
			r.mu.Lock()
			stopping := r.closed
			r.mu.Unlock()
			if stopping {
				return
			}
			select {
			case <-r.lifetime.Done():
				return
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}
		r.wg.Add(1)
		go r.handle(conn)
	}
}

// handle serves one connection: first-packet link lookup, per-link runtime,
// one bounded bundle, execution through the runtime. Every failure closes the
// connection without a response; the retained result records the outcome.
func (r *federationRelay) handle(conn net.Conn) {
	defer r.wg.Done()
	defer conn.Close()
	ctx, cancel := context.WithCancel(r.lifetime)
	defer cancel()

	stream, e := federation.NewConnStream(conn, federationServingConnLifetime)
	if e != nil {
		return
	}
	first, e := stream.Read(ctx)
	if e != nil || first.Channel == ([32]byte{}) {
		return
	}

	fed := r.node.Federation
	owner, e := r.node.Installation.Operator(ctx)
	if e != nil {
		return
	}
	link, linkRevision, found, e := fed.Links.Get(ctx, owner, first.Channel)
	if e != nil || !found || link.Revoked || link.SourceRole {
		return
	}
	localCertified, e := fed.Peers.Local(ctx, owner)
	if e != nil {
		return
	}
	remoteCertified, e := fed.Peers.Remote(ctx, owner, link.RemoteNamespace, link.RemoteStoreID)
	if e != nil {
		return
	}
	serving, e := r.servingFor(ctx, first.Channel, link, linkRevision, localCertified, remoteCertified)
	if e != nil {
		return
	}

	duplex, e := federation.NewDuplex(ctx, serving.configuration, &prependStream{first: first, inner: stream}, federationServingMaxBytes)
	if e != nil {
		return
	}
	channel, e := federation.NewForwardChannel(duplex)
	if e != nil {
		_ = duplex.Close()
		return
	}
	bundle, e := channel.ReceiveBundle(ctx)
	if e != nil {
		_ = channel.Close()
		return
	}

	delivery, stop := context.WithCancel(r.lifetime)
	started, e := serving.runtime.Start(delivery, bundle)
	stop()
	if e != nil {
		started.Error = e
	}
	r.recordResult(first.Channel, started)
	_ = channel.Close()
}
