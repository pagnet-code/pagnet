package fabric

import (
	"context"
	"sync"
)

// ProviderName is an operator-chosen, explicitly configured issuer identity. It
// is configuration, not a discovery result: a name is never inferred from a
// certificate, an issuer string, or the environment.
type ProviderName string

// ProviderLocalKernel is the well-known name of the default local kernel
// authority. It is the selection result when no other provider is explicitly
// chosen. It is a configuration default, not an auto-discovery mechanism: the
// local kernel authority is still registered by trusted composition.
const ProviderLocalKernel ProviderName = "local-kernel"

// AuthenticatorProvider is a named issuer of authenticated execution contexts.
// A node is composed with an explicit set of providers and selects exactly one
// by name per ingress. Selection is always explicit: an unknown or unconfigured
// name is an error, never a fallback to a discovered or guessed issuer.
//
// The default local kernel authority and any opt-in issuer (for example a
// SPIFFE SVID provider) both satisfy this interface, so the node code is
// identical regardless of which issuers an operator explicitly configures.
type AuthenticatorProvider interface {
	// Name is the explicit, stable provider identity used for selection.
	Name() ProviderName
	// Authenticate verifies the request and returns an authenticated context.
	Authenticate(context.Context, AuthenticationRequest) (ExecutionContext, error)
}

// NamedProvider is an explicitly named adapter over an existing Authenticator.
// Trusted composition uses it to expose the unchanged local kernel authority
// (and any other issuer) as a selectable provider without modifying the
// underlying authenticator.
type NamedProvider struct {
	name ProviderName
	Authenticator
}

var _ AuthenticatorProvider = NamedProvider{}

func (p NamedProvider) Name() ProviderName { return p.name }

// NewNamedProvider wraps an authenticator under an explicit, non-empty name.
func NewNamedProvider(name ProviderName, a Authenticator) (NamedProvider, error) {
	if name == "" || a == nil {
		return NamedProvider{}, NewError(CodeInvalidInput, "A provider requires an explicit name and an authenticator")
	}
	return NamedProvider{name: name, Authenticator: a}, nil
}

// ProviderSet is an explicitly registered collection of named authentication
// providers. It performs no discovery: only providers registered by trusted
// composition are selectable. It is safe for concurrent use.
type ProviderSet struct {
	mu          sync.RWMutex
	defaultName ProviderName
	providers   map[ProviderName]AuthenticatorProvider
	defaultSet  bool
}

// NewProviderSet builds a set whose default (empty-name) selection is the given
// provider. The default is the explicit local kernel authority in the standard
// composition. Passing nil builds a set with no default: every selection must
// name a registered provider. The default, when non-nil, is registered under
// its own name.
func NewProviderSet(defaultProvider AuthenticatorProvider) *ProviderSet {
	s := &ProviderSet{providers: map[ProviderName]AuthenticatorProvider{}}
	if defaultProvider != nil {
		s.providers[defaultProvider.Name()] = defaultProvider
		s.defaultName = defaultProvider.Name()
		s.defaultSet = true
	}
	return s
}

// Register adds a provider by its explicit name. Registering an empty name, a
// nil provider, a provider whose Name does not match, or an already-registered
// name is an error; there is no override and no discovery.
func (s *ProviderSet) Register(p AuthenticatorProvider) error {
	if s == nil || p == nil || p.Name() == "" {
		return NewError(CodeInvalidInput, "A provider set requires a named provider")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.providers[p.Name()]; ok {
		return NewError(CodeInvalidInput, "Authentication provider is already registered")
	}
	s.providers[p.Name()] = p
	return nil
}

// Select returns the provider for the exact explicit name. An empty name
// returns the explicit default (the local kernel authority). A name that was
// never registered is an error; a provider is never discovered or inferred.
func (s *ProviderSet) Select(name ProviderName) (AuthenticatorProvider, error) {
	if s == nil {
		return nil, NewError(CodeUnauthenticated, "No authentication provider set is configured")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if name == "" {
		if !s.defaultSet {
			return nil, NewError(CodeUnauthenticated, "No default authentication provider is configured")
		}
		return s.providers[s.defaultName], nil
	}
	p, ok := s.providers[name]
	if !ok {
		return nil, NewError(CodeUnauthenticated, "Authentication provider is not explicitly configured")
	}
	return p, nil
}

// Has reports whether the exact name (or the default for an empty name) is
// explicitly configured. It is a composition-time check, not a discovery probe.
func (s *ProviderSet) Has(name ProviderName) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if name == "" {
		return s.defaultSet
	}
	_, ok := s.providers[name]
	return ok
}
