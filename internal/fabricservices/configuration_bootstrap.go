package fabricservices

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// InstalledServiceConfigurationKey is a closed operator-selected installation
// setting purpose. It is never an endpoint descriptor or discovery authority.
func InstalledServiceConfigurationKey() registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityLocalInstallation, ID: "services:v1"}
}

// BootstrapConfiguredServiceState is explicit initialization, not Open. All
// three records commit atomically; supplied configuration must already be
// bounded encrypted operator metadata for this actual installation.
func BootstrapConfiguredServiceState(ctx context.Context, p *ProfileStore, c InvocationConfig, policy InvocationPolicy, max int, encryptedSetting []byte) (*Invocations, *Startup, error) {
	if len(encryptedSetting) == 0 || len(encryptedSetting) > 16<<10 {
		return nil, nil, denied()
	}
	return bootstrapServiceState(ctx, p, c, policy, max, encryptedSetting)
}
