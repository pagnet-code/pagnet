// Package registry persists extension configuration in the retained domain's
// genuine signed authority ledger. It does not install programs or credentials.
package registry

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/extension"
	domain "github.com/pagnet-code/pagnet/fabric/registry"
)

type Binding struct {
	ID                     string `json:"id"`
	Protocol               string `json:"protocol"`
	Selector               string `json:"selector"`
	ProfileDigest          string `json:"profileDigest"`
	CredentialPrincipalRef string `json:"credentialPrincipalRef,omitempty"`
}
type Installation struct {
	Manifest extension.ExtensionManifest `json:"manifest"`
	Bindings []Binding                   `json:"bindings"`
}

// OwnerValidator must check the actual live owner authentication/session. A
// serialized principal or cached ExecutionContext alone is not live authority.
type OwnerValidator func(context.Context, fabric.ExecutionContext, domain.AuthorityIdentity) error

type Config struct {
	Root                                                             *domain.Store
	Protector                                                        durable.DataProtector
	OwnerValidator                                                   OwnerValidator
	MaxExtensions, MaxInterceptors, MaxEntryBytes, MaxDirectoryBytes int
}

func DefaultConfig(root *domain.Store, p durable.DataProtector, gate OwnerValidator) Config {
	return Config{root, p, gate, 64, 512, 32768, 32768}
}

type Reference struct {
	ID         string `json:"id"`
	PhysicalID string `json:"physicalId"`
	Revision   uint64 `json:"revision,string"`
	Digest     string `json:"digest"`
}
type Snapshot struct {
	Generation uint64
	Plan       *extension.Plan
}
type Page struct {
	Generation uint64
	Entries    []Reference
	NextCursor string
}
