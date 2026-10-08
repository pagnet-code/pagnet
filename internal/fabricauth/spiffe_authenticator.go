package fabricauth

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/spiffe"
)

// SpiffeProvider is an opt-in fabric.AuthenticatorProvider that authenticates
// callers by a SPIFFE-compatible X.509-SVID presented as transport-private
// evidence. It verifies the SVID against an operator-pinned trust bundle
// (pinned roots, CRLs, expected audience/trust domain), binds the SVID's
// verified SPIFFE subject to the asserted principal, and issues an authenticated
// execution context. It is selected by explicit configuration only; it is never
// auto-discovered, and it leaves the default local kernel authority unchanged.
type SpiffeProvider struct {
	name   fabric.ProviderName
	bundle *spiffe.TrustBundle
	// now is the clock used for expiration/revocation checks. Production uses
	// time.Now; tests may install a fixed clock to exercise time-bound states.
	now func() time.Time
}

var _ fabric.AuthenticatorProvider = (*SpiffeProvider)(nil)

// svidEvidence is the private, request-bound capability minted only after a SVID
// passes full trust-bundle validation and workload binding. It binds the caller
// to this provider, the verified principal, and the exact original bytes. It is
// never a wire value; its presence alone grants no authority.
type svidEvidence struct {
	provider       *SpiffeProvider
	principal      fabric.Principal
	originalDigest [32]byte
	audience       string
}

func (svidEvidence) MarshalJSON() ([]byte, error) { return nil, denied() }
func (*svidEvidence) UnmarshalJSON([]byte) error  { return denied() }

// NewSpiffeProvider builds a SPIFFE provider under an explicit name from an
// operator-pinned trust bundle. The name and the bundle audience must both be
// non-empty. The resulting provider uses the wall clock.
func NewSpiffeProvider(name fabric.ProviderName, bundle *spiffe.TrustBundle) (*SpiffeProvider, error) {
	if name == "" || bundle == nil {
		return nil, invalid()
	}
	return &SpiffeProvider{name: name, bundle: bundle, now: time.Now}, nil
}

// WithNow returns a copy of the provider using an explicit clock. The trust
// bundle is shared. This is a testability seam; production uses time.Now.
func (a *SpiffeProvider) WithNow(now func() time.Time) *SpiffeProvider {
	if a == nil {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &SpiffeProvider{name: a.name, bundle: a.bundle, now: now}
}

// Name is the explicit provider identity used for selection.
func (a *SpiffeProvider) Name() fabric.ProviderName { return a.name }

// Audience is the trust domain this provider authenticates.
func (a *SpiffeProvider) Audience() string { return a.bundle.Audience() }

// Authenticate is the current-status admission for NEW invocations. It requires
// the peer to present a SVID (as a *spiffe.SVID in PeerEvidence) that chains to
// a pinned root, is within its validity window, is not revoked by a trusted
// CRL, belongs to the expected audience, and whose SPIFFE subject exactly equals
// the request's asserted principal. Any failure denies the invocation.
func (a *SpiffeProvider) Authenticate(ctx context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || len(r.ExactEnvelope) == 0 || len(r.ExactEnvelope) > fabric.DefaultWireLimits.MaxBytes {
		return fabric.ExecutionContext{}, denied()
	}
	if r.Audience != a.bundle.Audience() {
		return fabric.ExecutionContext{}, denied()
	}
	svid, ok := r.PeerEvidence.(*spiffe.SVID)
	if !ok || svid == nil {
		return fabric.ExecutionContext{}, denied()
	}
	// Current-status check for NEW invocations: audience, expiration, chain, revocation.
	if err := a.bundle.Validate(svid, a.now()); err != nil {
		return fabric.ExecutionContext{}, denied()
	}
	var envelope fabric.Envelope
	if fabric.DecodeJSON(r.ExactEnvelope, &envelope) != nil {
		return fabric.ExecutionContext{}, denied()
	}
	// Workload binding: the asserted principal must match the verified SVID subject.
	binding, err := spiffe.BindWorkload(svid, envelope.Principal)
	if err != nil {
		return fabric.ExecutionContext{}, denied()
	}
	// The envelope source must be the SVID subject (re-enforced by DecodeVerifiedEnvelope).
	if envelope.Source != binding.SPIFFEID() {
		return fabric.ExecutionContext{}, denied()
	}
	principal := binding.Principal()
	evidence := &svidEvidence{
		provider:       a,
		principal:      principal,
		originalDigest: sha256.Sum256(r.ExactEnvelope),
		audience:       a.bundle.Audience(),
	}
	trusted, err := fabric.NewAuthenticatedContextWithEvidence(principal, a.bundle.Audience(), r.ExactEnvelope, evidence)
	if err != nil {
		return fabric.ExecutionContext{}, err
	}
	if _, err := trusted.DecodeVerifiedEnvelope(r.ExactEnvelope, a.bundle.Audience()); err != nil {
		return fabric.ExecutionContext{}, err
	}
	return trusted, nil
}

// RecognizesRetainedCaller checks only the private provider association for a
// historical caller. It is a selector, not current authorization: it never
// re-checks the SVID's current expiration or revocation.
func (a *SpiffeProvider) RecognizesRetainedCaller(caller fabric.ExecutionContext) bool {
	if a == nil {
		return false
	}
	ev, ok := caller.AuthenticationEvidence().(*svidEvidence)
	return ok && ev != nil && ev.provider == a && ev.principal == caller.PrincipalView() && caller.VerifyAuthenticatedDigest(ev.originalDigest, ev.audience) == nil
}

// WithRetainedCaller admits a historical read of a past invocation that this
// provider authenticated. It re-verifies the private evidence (intact and from
// this provider) and the exact original bytes, but it does NOT re-check the
// SVID's current expiration or revocation: an invocation authorized when its
// SVID was valid remains readable after the SVID is later revoked or expires.
func (a *SpiffeProvider) WithRetainedCaller(ctx context.Context, caller fabric.ExecutionContext, original []byte, next func(context.Context) error) error {
	if a == nil || ctx == nil || ctx.Err() != nil || next == nil || len(original) == 0 {
		return denied()
	}
	if !a.RecognizesRetainedCaller(caller) {
		return denied()
	}
	ev := caller.AuthenticationEvidence().(*svidEvidence)
	if sha256.Sum256(original) != ev.originalDigest {
		return denied()
	}
	if _, err := caller.DecodeVerifiedEnvelope(original, ev.audience); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return next(ctx)
}
