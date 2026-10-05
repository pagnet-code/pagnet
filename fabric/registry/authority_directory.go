package registry

import (
	"context"
	"path/filepath"

	"github.com/pagnet-code/pagnet/fabric"
)

// CurrentAuthorityDirectory returns the actual retained private root directory
// for trusted host sandbox composition. It is not descriptor, discovery or
// transport metadata. A caller-selected path cannot replace this deny root.
// Directory identity is immutable for this Store; Close does not relocate it.
func (s *Store) CurrentAuthorityDirectory(ctx context.Context) (string, error) {
	if s == nil || !filepath.IsAbs(s.dir) || filepath.Clean(s.dir) != s.dir {
		return "", fabric.NewError(fabric.CodeUnauthenticated, "Retained local root is unavailable")
	}
	if _, err := s.CurrentAuthorityIdentity(ctx); err != nil {
		return "", err
	}
	return s.dir, nil
}
