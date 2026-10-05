package fabricnode

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
)

// InitializeDefaultServices is called only by explicit local initialization.
// It opens no listener, launches no runtime and installs no provider software.
// Retained configuration is verified and preserved; partial state is rejected.
func InitializeDefaultServices(ctx context.Context, installation *localinstallation.Installation) error {
	retained, err := LoadInstalledServiceSettings(ctx, installation)
	if err != nil {
		return err
	}
	if retained != nil {
		return nil
	}
	owner, err := installation.Operator(ctx)
	if err != nil {
		return err
	}
	boundary, err := newLocalBoundary(ctx, installation.Store, owner, installation, 0)
	if err != nil {
		return err
	}
	return InitializeConfiguredServices(ctx, installation, boundary, DefaultInstalledServiceSettings())
}
