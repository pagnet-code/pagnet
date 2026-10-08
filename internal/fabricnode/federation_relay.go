package fabricnode

// The installed federation product's blind-relay destination serving listener
// (E1 slice-2b/2c) — the platform-independent composition state.
//
// The relay identifies a link ONLY from the plaintext Packet.Channel of the
// first encrypted record; it never inspects decrypted content. Per connection
// it re-establishes the HPKE transport from that first packet and serves one
// bounded unit: a bundle-forward (records 1..3, one-way — the honest
// observation of the outcome is the relay's own retained start result) or a
// committed control unit (record 4, reply record 5, pull frames record 6 —
// the wire reply is the primary observation; the retained control result
// records outcomes the source could not receive). The actual socket transport
// is unix-only (federation_relay_serve_unix.go); other platforms fail the
// relay startup explicitly, never silently.

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

type federationRelay struct {
	node    *InstalledNode
	path    string
	started bool

	listener   net.Listener
	lifetime   context.Context
	cancel     context.CancelFunc
	acceptDone chan struct{}

	mu                sync.Mutex
	closed            bool
	serving           map[[32]byte]*linkServing
	profiles          *fabricservices.ProfileStore
	results           map[[32]byte]federationServingResult
	generation        uint64
	controlResults    map[[32]byte]federationServingControlResult
	controlGeneration uint64

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// federationServingResult is the relay's retained latest start outcome for a
// channel (private observability; bundle-forward sends no wire response).
type federationServingResult struct {
	Channel    [32]byte
	Generation uint64
	Start      FederationStart
}

// federationServingControlResult is the relay's retained latest control
// outcome for a channel (private observability): the wire reply is the
// primary observation, this records committed states and outcomes the source
// could not receive.
type federationServingControlResult struct {
	Channel    [32]byte
	Generation uint64
	Action     string
	State      federation.ControlState
	Error      error
}

// newFederationRelay composes the relay over the installed node. The default
// relay socket is <dir(settings.SocketPath)>/federation.sock; an explicit
// RelaySocket overrides it.
func newFederationRelay(ctx context.Context, n *InstalledNode, cfg *InstalledFederationConfig) (*federationRelay, error) {
	if ctx == nil || n == nil || n.Installation == nil || n.Federation == nil {
		return nil, localDenied()
	}
	path := n.Installation.Configuration().Settings.SocketPath
	if cfg != nil && cfg.RelaySocket != "" {
		// An explicit relay socket is used exactly as configured.
		path = cfg.RelaySocket
	} else {
		// The default relay socket is next to the installation admin socket.
		path = filepath.Join(filepath.Dir(path), "federation.sock")
	}
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &federationRelay{
		node:           n,
		path:           path,
		lifetime:       lifetime,
		cancel:         cancel,
		acceptDone:     make(chan struct{}),
		serving:        map[[32]byte]*linkServing{},
		results:        map[[32]byte]federationServingResult{},
		controlResults: map[[32]byte]federationServingControlResult{},
	}, nil
}

// servingFor returns the cached per-link stack, recomposing when the link
// record or either peer identity revision changed. The composition runs
// WITHOUT the relay lock (it performs real store/crypto/provider work); the
// cache is checked and installed under the lock, so concurrent compositions
// for the same channel are last-writer-wins and the loser is retired.
// Recomposition retires the previous runtime first (bounded join).
func (r *federationRelay) servingFor(ctx context.Context, channel [32]byte, link FederationLink, linkRevision uint64, local, remote registry.CertifiedPeer) (*linkServing, error) {
	upToDate := func(s *linkServing) bool {
		return s != nil && s.current(linkRevision, local.Revision, remote.Revision)
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, localDenied()
	}
	if existing := r.serving[channel]; upToDate(existing) {
		r.mu.Unlock()
		return existing, nil
	}
	r.mu.Unlock()

	profiles, e := r.servingProfiles(ctx)
	if e != nil {
		return nil, e
	}
	composed, e := r.node.composeFederationLink(ctx, r, channel, link, linkRevision, local, remote, profiles)
	if e != nil {
		return nil, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		_ = composed.Close(ctx)
		return nil, localDenied()
	}
	if existing := r.serving[channel]; upToDate(existing) {
		// A concurrent connection already installed this exact composition.
		_ = composed.Close(ctx)
		return existing, nil
	}
	if existing := r.serving[channel]; existing != nil {
		retireCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		_ = existing.Close(retireCtx)
		cancel()
	}
	r.serving[channel] = composed
	return composed, nil
}

// servingProfiles composes the node's single service profile store once; every
// per-link runtime shares it (the profile records are per-store retained state).
func (r *federationRelay) servingProfiles(ctx context.Context) (*fabricservices.ProfileStore, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.profiles != nil {
		return r.profiles, nil
	}
	installation := r.node.Installation
	profiles, e := fabricservices.NewProfileStore(ctx, installation.Store, installation.Operator, installation.Keys)
	if e != nil {
		return nil, e
	}
	r.profiles = profiles
	return profiles, nil
}

func (r *federationRelay) recordResult(channel [32]byte, start FederationStart) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.generation++
	r.results[channel] = federationServingResult{Channel: channel, Generation: r.generation, Start: start}
}

// latestResult reports the retained latest serving start for a channel and its
// monotonic generation. Private observability for the in-package acceptance
// test: bundle-forward sends no response over the wire, so the relay's own
// retained result is the only honest observation of EXECUTION_UNKNOWN outcomes.
func (r *federationRelay) latestResult(channel [32]byte) (FederationStart, uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.results[channel]
	return value.Start, value.Generation, ok
}

// servingForChannel returns the retained per-link serving stack for a channel
// (private observability for the in-package acceptance test, which
// independently recomputes committed head-state digests).
func (r *federationRelay) servingForChannel(channel [32]byte) *linkServing {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.serving[channel]
}

// recordControl retains the latest control outcome for a channel (private
// observability; the wire reply is the primary observation).
func (r *federationRelay) recordControl(channel [32]byte, action string, state federation.ControlState, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.controlGeneration++
	r.controlResults[channel] = federationServingControlResult{Channel: channel, Generation: r.controlGeneration, Action: action, State: state, Error: err}
}

// latestControlResult reports the retained latest control outcome for a
// channel and the control-generation counter. Private observability for the
// in-package acceptance test.
func (r *federationRelay) latestControlResult(channel [32]byte) (federationServingControlResult, uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.controlResults[channel]
	return value, r.controlGeneration, ok
}

// CloseContext stops the relay: cancel the lifetime, close the listener, join
// the accept loop, then join in-flight serving connections. An incomplete
// join returns the caller's context error and is retryable (idempotent).
func (r *federationRelay) CloseContext(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return localDenied()
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		r.cancel()
		if r.listener != nil {
			_ = r.listener.Close()
		}
		if r.started {
			<-r.acceptDone
		}
	})
	finish := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(finish)
	}()
	select {
	case <-finish:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// prependStream re-injects the first packet (the HPKE encapsulation record
// carrying the plaintext channel) that the relay consumed for link lookup, so
// the re-established transport observes the complete record sequence.
type prependStream struct {
	first    federation.Packet
	consumed bool
	inner    federation.PacketStream
}

func (s *prependStream) Read(ctx context.Context) (federation.Packet, error) {
	if !s.consumed {
		s.consumed = true
		return s.first, nil
	}
	return s.inner.Read(ctx)
}
func (s *prependStream) Write(ctx context.Context, p federation.Packet) error {
	return s.inner.Write(ctx, p)
}
func (s *prependStream) Close() error { return s.inner.Close() }
