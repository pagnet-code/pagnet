// Package fabricauth binds local original envelopes to real kernel peers.
// No wire field creates identity, authority, lineage or a reusable credential.
package fabricauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

// Activation comes only from trusted owner/supervisor composition, never from
// protocol JSON or a caller-selected worker/scope. Nonce alone is not authority.
type Activation struct {
	Scope                                                   nativeauthority.Scope
	RootPID                                                 int
	StartIdentity, Nonce, NativeGeneration, NativeSessionID string
}
type ManagedPeer struct {
	Process    localpeer.ProcessSnapshot
	Activation Activation
	Root       registry.AuthorityIdentity
}

// ManagedValidator must check actual current signed controller/binding and
// native ownership/session/generation/nonce against its own retained source.
// The returned principal is the exact managed endpoint, not the root owner.
// Source Admission A is separate lifecycle evidence; no task lineage is guessed.
type ManagedValidator func(context.Context, ManagedPeer) (fabric.Principal, error)

// OwnerValidator distinguishes a genuine owner process from managed native
// descendants using trusted current kernel/worker facts. Requested wire mode
// and absence of managed environment variables cannot establish owner identity.
// It is mandatory whenever this authority also admits managed processes.
type OwnerValidator func(context.Context, localpeer.ProcessSnapshot) error
type Config struct {
	Root                   registry.AuthorityIdentity
	RootOwner              fabric.Principal
	Audience, SocketPath   string
	CurrentRoot            func(context.Context) (registry.AuthorityIdentity, error)
	ManagedValidator       ManagedValidator
	ManagedFacts           ManagedFactsProvider
	HostedValidator        HostedValidator
	HostedFacts            HostedFactsProvider
	OwnerValidator         OwnerValidator
	MaxPending             int
	ProofTTL, CheckTimeout time.Duration
}
type Authority struct{ config Config }
type Session struct {
	mu             sync.Mutex
	authority      *Authority
	conn           *net.UnixConn
	process        localpeer.ProcessSnapshot
	principal      fabric.Principal
	activation     *Activation
	hosted         *HostedActivation
	pending        map[*proof]time.Time
	closed         bool
	revoked        atomic.Bool
	revocationDone chan struct{}
}
type proof struct {
	session *Session
	digest  [32]byte
	expires time.Time
}

func (*proof) MarshalJSON() ([]byte, error) { return nil, denied() }
func (*proof) UnmarshalJSON([]byte) error   { return denied() }
func denied() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Current verified local peer required")
}
func invalid() error {
	return fabric.NewError(fabric.CodeInvalidInput, "Invalid local Fabric authentication configuration or call")
}
func text(v string, n int) bool {
	return v != "" && len(v) <= n && utf8.ValidString(v) && !strings.ContainsAny(v, "\x00\r\n")
}
func sameRoot(a, b registry.AuthorityIdentity) bool {
	return a.Namespace == b.Namespace && a.StoreID == b.StoreID && a.Owner == b.Owner && a.KeyRevision == b.KeyRevision && bytes.Equal(a.PublicKey, b.PublicKey)
}
func validRoot(r registry.AuthorityIdentity) bool {
	namespace, e := fabric.DomainNamespace(r.PublicKey)
	id, e2 := hex.DecodeString(r.StoreID)
	return e == nil && e2 == nil && len(id) == 32 && hex.EncodeToString(id) == r.StoreID && namespace == r.Namespace && r.KeyRevision == 1 && text(r.Owner.Ref, 4096) && text(r.Owner.Issuer, 4096) && fabric.ValidNamespacedName(r.Owner.Kind)
}
func New(c Config) (*Authority, error) {
	if c.MaxPending == 0 {
		c.MaxPending = 128
	}
	if c.ProofTTL == 0 {
		c.ProofTTL = 30 * time.Second
	}
	if c.CheckTimeout == 0 {
		c.CheckTimeout = 3 * time.Second
	}
	if !validRoot(c.Root) || c.RootOwner != c.Root.Owner || c.Audience != c.Root.Namespace || c.CurrentRoot == nil || (c.ManagedValidator != nil || c.HostedValidator != nil) && c.OwnerValidator == nil || (c.HostedValidator == nil) != (c.HostedFacts == nil) || !text(c.SocketPath, 4096) || c.MaxPending < 1 || c.MaxPending > 1024 || c.ProofTTL < time.Millisecond || c.ProofTTL > time.Minute || c.CheckTimeout < time.Millisecond || c.CheckTimeout > 30*time.Second {
		return nil, invalid()
	}
	c.Root.PublicKey = bytes.Clone(c.Root.PublicKey)
	return &Authority{config: c}, nil
}
func (a *Authority) current(ctx context.Context) error {
	current, e := a.config.CurrentRoot(ctx)
	if e != nil || !validRoot(current) || !sameRoot(current, a.config.Root) || current.Owner != a.config.RootOwner {
		return denied()
	}
	return nil
}

// SupportsManaged reports trusted composition capabilities, never a caller's
// choice of mode. Hosts must require this before enabling managed resolution.
func (a *Authority) SupportsManaged() bool {
	return a != nil && a.config.ManagedValidator != nil && a.config.OwnerValidator != nil
}
func (a *Authority) SupportsHosted() bool {
	return a != nil && a.config.HostedValidator != nil && a.config.HostedFacts != nil && a.config.OwnerValidator != nil
}
func (a *Authority) BindOwner(ctx context.Context, conn *net.UnixConn) (*Session, error) {
	return a.bind(ctx, conn, nil)
}
func (a *Authority) BindManaged(ctx context.Context, conn *net.UnixConn, activation Activation) (*Session, error) {
	scope, ok := activation.Scope.Local()
	if !ok || scope.Validate() != nil || scope.Namespace != a.config.Root.Namespace || scope.StoreID != a.config.Root.StoreID || scope.Owner != a.config.RootOwner || scope.KeyRevision != a.config.Root.KeyRevision || !bytes.Equal(scope.PublicKey[:], a.config.Root.PublicKey) || activation.RootPID <= 0 || !text(activation.StartIdentity, 64) || !text(activation.Nonce, 512) || !text(activation.NativeGeneration, 256) || !text(activation.NativeSessionID, 4096) || a.config.ManagedValidator == nil {
		return nil, denied()
	}
	return a.bind(ctx, conn, &activation)
}
func (a *Authority) bind(ctx context.Context, conn *net.UnixConn, activation *Activation) (*Session, error) {
	if ctx == nil || conn == nil || ctx.Err() != nil {
		return nil, denied()
	}
	checked, cancel := context.WithTimeout(ctx, a.config.CheckTimeout)
	defer cancel()
	process, e := peer(checked, conn, a.config.SocketPath)
	if e != nil {
		return nil, denied()
	}
	s := &Session{authority: a, conn: conn, process: process, activation: activation, pending: map[*proof]time.Time{}}
	if activation == nil {
		s.principal = a.config.RootOwner
	}
	principal, e := s.verify(checked)
	if e != nil {
		return nil, e
	}
	s.principal = principal
	return s, nil
}
func (s *Session) verify(ctx context.Context) (fabric.Principal, error) {
	if s.closed || ctx.Err() != nil || s.authority.current(ctx) != nil {
		return fabric.Principal{}, denied()
	}
	current, e := peer(ctx, s.conn, s.authority.config.SocketPath)
	if e != nil || current != s.process {
		return fabric.Principal{}, denied()
	}
	principal := s.authority.config.RootOwner
	if s.hosted != nil {
		principal, e = s.verifyHosted(ctx, current)
		if e != nil {
			return fabric.Principal{}, e
		}
	} else if s.activation == nil {
		// Recheck on every request as ownership can change after the connection
		// was established. Configuration mistakes must not elevate a managed peer.
		if s.authority.config.ManagedValidator != nil && s.authority.config.OwnerValidator == nil {
			return fabric.Principal{}, denied()
		}
		if guard := s.authority.config.OwnerValidator; guard != nil && guard(ctx, current) != nil {
			return fabric.Principal{}, denied()
		}
	} else {
		activation := *s.activation
		if localpeer.VerifyOwned(s.conn, activation.RootPID, activation.StartIdentity) != nil {
			return fabric.Principal{}, denied()
		}
		root := s.authority.config.Root
		root.PublicKey = bytes.Clone(root.PublicKey)
		principal, e = s.authority.config.ManagedValidator(ctx, ManagedPeer{current, activation, root})
		scope, _ := activation.Scope.Local()
		if e != nil || principal.Ref != scope.Endpoint.String() || !text(principal.Issuer, 4096) || !fabric.ValidNamespacedName(principal.Kind) || principal == s.authority.config.RootOwner {
			return fabric.Principal{}, denied()
		}
		if localpeer.VerifyOwned(s.conn, activation.RootPID, activation.StartIdentity) != nil {
			return fabric.Principal{}, denied()
		}
	}
	after, e := peer(ctx, s.conn, s.authority.config.SocketPath)
	if e != nil || after != current || ctx.Err() != nil || s.authority.current(ctx) != nil {
		return fabric.Principal{}, denied()
	}
	if s.principal.Ref != "" && s.principal != principal {
		return fabric.Principal{}, denied()
	}
	return principal, nil
}
func (s *Session) Close() error {
	s.revoked.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		if s.revocationDone != nil {
			close(s.revocationDone)
		}
	}
	for p := range s.pending {
		delete(s.pending, p)
	}
	return nil
}
func (s *Session) reclaim(now time.Time) {
	for p, expires := range s.pending {
		if !now.Before(expires) {
			delete(s.pending, p)
		}
	}
}
func (s *Session) Build(ctx context.Context, call mcpbridge.Call) ([]byte, any, error) {
	if ctx == nil {
		return nil, nil, denied()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reclaim(time.Now())
	if s.closed || ctx.Err() != nil {
		return nil, nil, denied()
	}
	if len(s.pending) >= s.authority.config.MaxPending {
		return nil, nil, fabric.NewError(fabric.CodeTargetUnavailable, "Local authentication proof capacity unavailable")
	}
	// Reserve before validators/entropy/serialization; failures reclaim immediately.
	p := &proof{session: s, expires: time.Now().Add(s.authority.config.ProofTTL)}
	s.pending[p] = p.expires
	keep := false
	defer func() {
		if !keep {
			delete(s.pending, p)
		}
	}()
	checked, cancel := context.WithTimeout(ctx, s.authority.config.CheckTimeout)
	defer cancel()
	principal, e := s.verify(checked)
	if e != nil {
		return nil, nil, e
	}
	var entropy [32]byte
	if _, e = rand.Read(entropy[:]); e != nil {
		return nil, nil, denied()
	}
	envelope := fabric.Envelope{ProtocolVersion: "1.0", ID: hex.EncodeToString(entropy[:]), Operation: call.Operation, Principal: principal, Source: principal.Ref, CreatedAt: time.Now().UTC(), Context: fabric.EnvelopeContext{Origin: principal.Ref}}
	switch call.Operation {
	case fabric.OperationDiscover:
		if call.Discover == nil || call.Describe != nil || call.Invoke != nil || call.Discover.Validate() != nil {
			return nil, nil, invalid()
		}
		envelope.Payload, e = json.Marshal(call.Discover)
	case fabric.OperationDescribe:
		if call.Describe == nil || call.Discover != nil || call.Invoke != nil || call.Describe.Validate() != nil {
			return nil, nil, invalid()
		}
		envelope.Payload, e = json.Marshal(call.Describe)
	case fabric.OperationInvoke:
		if call.Invoke == nil || call.Discover != nil || call.Describe != nil || call.Invoke.InvocationID != "" {
			return nil, nil, invalid()
		}
		request := *call.Invoke
		request.InvocationID = envelope.ID
		if request.Validate() != nil {
			return nil, nil, invalid()
		}
		envelope.Target = &request.Target
		envelope.ExpectedRevision = request.ExpectedRevision
		envelope.Payload = bytes.Clone(request.Input)
		envelope.Context.IdempotencyKey = request.IdempotencyKey
		if request.Deadline != nil {
			value := *request.Deadline
			if !time.Now().Before(value) {
				return nil, nil, invalid()
			}
			envelope.Context.Deadline = &value
		}
	default:
		return nil, nil, invalid()
	}
	if e != nil || envelope.Validate() != nil {
		return nil, nil, invalid()
	}
	raw, e := json.Marshal(envelope)
	if e != nil {
		return nil, nil, invalid()
	}
	var bounded fabric.Envelope
	if fabric.DecodeJSON(raw, &bounded) != nil || bounded.Validate() != nil {
		return nil, nil, invalid()
	}
	if _, e = s.verify(checked); e != nil {
		return nil, nil, e
	}
	if !time.Now().Before(p.expires) {
		return nil, nil, denied()
	}
	p.digest = sha256.Sum256(raw)
	keep = true
	return raw, p, nil
}
func (a *Authority) Authenticate(ctx context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	p, ok := r.PeerEvidence.(*proof)
	if !ok || p == nil || p.session == nil || p.session.authority != a {
		return fabric.ExecutionContext{}, denied()
	}
	s := p.session
	s.mu.Lock()
	defer s.mu.Unlock()
	_, pending := s.pending[p]
	// Consume any attempted evidence once, including rejected/canceled requests.
	delete(s.pending, p)
	s.reclaim(time.Now())
	if !pending || ctx == nil || r.Audience != a.config.Audience || ctx.Err() != nil || !time.Now().Before(p.expires) || len(r.ExactEnvelope) == 0 || len(r.ExactEnvelope) > fabric.DefaultWireLimits.MaxBytes || p.digest != sha256.Sum256(r.ExactEnvelope) {
		return fabric.ExecutionContext{}, denied()
	}
	checked, cancel := context.WithTimeout(ctx, a.config.CheckTimeout)
	defer cancel()
	principal, e := s.verify(checked)
	if e != nil {
		return fabric.ExecutionContext{}, e
	}
	binding := &sessionBinding{authority: a, session: s, principal: principal, originalDigest: sha256.Sum256(r.ExactEnvelope)}
	trusted, e := fabric.NewAuthenticatedContextWithEvidence(principal, a.config.Audience, r.ExactEnvelope, binding)
	if e != nil {
		return fabric.ExecutionContext{}, e
	}
	if _, e = trusted.DecodeVerifiedEnvelope(r.ExactEnvelope, a.config.Audience); e != nil {
		return fabric.ExecutionContext{}, e
	}
	return trusted, nil
}

var _ mcpbridge.EnvelopeFactory = (*Session)(nil)
var _ fabric.Authenticator = (*Authority)(nil)
