// Package federation transports bounded encrypted records between explicitly
// trusted nodes. Transport authentication never grants caller or operation policy.
package federation

import (
	"context"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

const Profile = fabric.ForwardBindingProfile
const MaxRecordPlaintext = 64 << 10
const MaxRecordWire = 96 << 10
const MaxChannelRecords = 65536

// PeerBinding is trusted composition data. A resolver/gate must verify the
// actual owner's certificate/current pin; decoding these fields is not trust.
// The independent transport key is not a converted domain signing key.
type PeerBinding struct {
	Authority           registry.AuthorityIdentity
	ExchangePublicKey   [32]byte
	ExchangeKeyRevision uint64
	BindingDigest       [32]byte
	ExpiresAt           time.Time
}

// TrustGate holds actual current owner-certified peer trust across bounded
// encryption/decryption. There is no permissive default implementation.
type TrustGate interface {
	WithCurrent(context.Context, PeerBinding, PeerBinding, func(context.Context) error) error
}

// KeyProvider selects only the actual certified local private exchange key.
// Returned private bytes transfer to this package and are cleared after setup.
type KeyProvider interface {
	ExchangePrivateKey(context.Context, PeerBinding) ([]byte, error)
}

// ChannelBinding contains only independently chosen opaque routing values.
// Both directions bind the SAME channel and distinct receiver route explicitly.
type ChannelBinding struct {
	ID               [32]byte
	SourceRoute      [32]byte
	DestinationRoute [32]byte
}
type Config struct {
	Local   PeerBinding
	Remote  PeerBinding
	Keys    KeyProvider
	Trust   TrustGate
	Channel ChannelBinding
	// SourceRole determines which exact direction this object may send/receive.
	SourceRole bool
	MaxRecords uint64
}

// Packet is the complete blind-relay view. It contains no domain, principal,
// reference, operation, query, descriptor, application tracing or credential.
// Traffic volume/timing and opaque selected routes remain observable.
type Packet struct {
	Profile       string   `json:"profile"`
	Channel       [32]byte `json:"channel"`
	Route         [32]byte `json:"route"`
	Direction     uint8    `json:"direction"`
	Ordinal       uint64   `json:"ordinal,string"`
	Encapsulation []byte   `json:"encapsulation,omitempty"`
	Ciphertext    []byte   `json:"ciphertext"`
}

func authError() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Federation peer/channel authentication failed")
}
func protocolError() error {
	return fabric.NewError(fabric.CodeProtocolError, "Federation record profile, sequence or bounds invalid")
}
