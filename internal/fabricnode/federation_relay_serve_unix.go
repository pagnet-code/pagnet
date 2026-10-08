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
// one bounded unit. The first plaintext record selects the unit type:
// record 1 (bundle start) runs the one-way bundle-forward; record 4 (control
// request) runs the destination control path. Every failure closes the
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
	kind, e := channel.DispatchFirst(ctx)
	if e != nil {
		_ = channel.Close()
		return
	}
	switch kind {
	case federation.UnitControl:
		r.handleControl(ctx, serving, channel)
		return
	case federation.UnitBundle:
	default:
		_ = channel.Close()
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

// handleControl serves one committed control unit on its own connection (D3):
// receive the signed request (record 4), serve the action through the
// per-link ControlLedger and the genuine source actuation, reply with the
// committed state (record 5) and, for a pull, the retained frames (record 6).
// Every failure closes the connection without a reply; the retained control
// result records the outcome.
func (r *federationRelay) handleControl(ctx context.Context, serving *linkServing, channel *federation.ForwardChannel) {
	fail := func(action string, state federation.ControlState, e error) {
		_ = channel.Close()
		r.recordControl(serving.channel, action, state, e)
	}
	request, e := channel.ReceiveControl(ctx)
	if e != nil {
		fail("", federation.ControlState{}, e)
		return
	}
	state, frames, e := serving.serveControl(ctx, request)
	if e != nil {
		fail(request.Proof.Frame.Action, federation.ControlState{}, e)
		return
	}
	if e := channel.SendControlReply(ctx, request, state); e != nil {
		fail(request.Proof.Frame.Action, federation.ControlState{}, e)
		return
	}
	if len(frames) > 0 {
		page, e := federation.NewPullPage(channel, request)
		if e != nil {
			fail(request.Proof.Frame.Action, state, e)
			return
		}
		for _, frame := range frames {
			if e := page.Send(ctx, frame); e != nil {
				fail(request.Proof.Frame.Action, state, e)
				return
			}
		}
	}
	_ = channel.Close()
	r.recordControl(serving.channel, request.Proof.Frame.Action, state, nil)
}
