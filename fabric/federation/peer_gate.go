package federation

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// PeerTxGate holds current actual owner-certified pair trust inside a transaction
// already created by the SAME retained registry. Implementations must perform
// bounded local checks only: no provider IO, owner lookup, recursive registry
// transaction, endpoint execution or permission inference from peer identity.
type PeerTxGate interface {
	WithCurrentTx(context.Context, *registry.AuthorityTx, PeerBinding, PeerBinding, func(context.Context) error) error
}
