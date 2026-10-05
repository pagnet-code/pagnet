package fabricauth

import "github.com/pagnet-code/pagnet/fabric/registry"

// MatchesAuthority is a cheap private capability scope/lifetime predicate for
// trusted administration composition. It performs no kernel or registry IO;
// VerifyCurrent remains mandatory before accessing operator infrastructure.
func (a *OwnerAdministration) MatchesAuthority(root registry.AuthorityIdentity) bool {
	return a != nil && a.session != nil && a.session.authority != nil && a.active.Load() && a.lifetime != nil && a.lifetime.Err() == nil && !a.session.revoked.Load() && sameRoot(a.session.authority.config.Root, root)
}
