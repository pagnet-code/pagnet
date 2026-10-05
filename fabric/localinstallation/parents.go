package localinstallation

import (
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/internal/privatefs"
	"path/filepath"
)

// PrepareParents prepares only owner-verified nonsecret parents for an explicit
// Bootstrap. It never creates the authority leaf or initializes identity/keys.
func PrepareParents(directory string) error { return privatefs.PrepareParents(directory) }

// PrepareBootstrapParents prepares explicit installation and direct peer socket
// parents only after verifying the configuration. The authority leaf remains
// absent until Bootstrap; an existing socket parent must already be private.
func PrepareBootstrapParents(directory string, settings Settings) error {
	if !validDirectory(directory) || !validSettings(directory, settings) {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid explicit local installation configuration")
	}
	if err := privatefs.PrepareParents(directory); err != nil {
		return err
	}
	if err := privatefs.PrepareParents(settings.SocketPath); err != nil {
		return err
	}
	return privatefs.CheckPrivateDirectory(filepath.Dir(settings.SocketPath))
}
