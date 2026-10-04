package registry

import (
	"bytes"
	"context"

	"github.com/pagnet-code/pagnet/fabric"
)

// CurrentAuthorityIdentity checks the currently open owner and its retained
// immutable genesis. AuthorityIdentity alone is public verification material
// and remains useful after Close; it is not a liveness/authentication check.
// Mutable endpoint/controller admission is still checked separately at dispatch.
func (s *Store) CurrentAuthorityIdentity(ctx context.Context) (AuthorityIdentity, error) {
	if ctx == nil {
		return AuthorityIdentity{}, invalid("Missing current-root context")
	}
	if err := ctx.Err(); err != nil {
		return AuthorityIdentity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	denied := func() (AuthorityIdentity, error) {
		return AuthorityIdentity{}, fabric.NewError(fabric.CodeUnauthenticated, "Retained local root is unavailable")
	}
	if s.closed {
		return denied()
	}
	var raw []byte
	if s.db.QueryRowContext(ctx, "SELECT CASE WHEN length(genesis)<=65536 THEN genesis END FROM identity WHERE singleton=1").Scan(&raw) != nil {
		return denied()
	}
	var record GenesisRecord
	if fabric.DecodeJSONWithLimits(raw, &record, fabric.WireLimits{MaxBytes: 65536, MaxDepth: 16, MaxMembers: 64}) != nil || !bytes.Equal(record.Body, s.genesis.Body) || !bytes.Equal(record.Signature, s.genesis.Signature) {
		return denied()
	}
	return AuthorityIdentity{s.identity.Namespace, s.identity.StoreID, s.identity.Owner, bytes.Clone(s.identity.PublicKey), 1}, nil
}
