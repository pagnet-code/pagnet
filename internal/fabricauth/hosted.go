package fabricauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

// HostedActivation is supplied only by trusted original-worker composition.
// CLOUD native scope survives unchanged; Endpoint is an explicit signed local
// catalog association, never a transplanted native launch/admission identity.
type HostedActivation struct {
	Scope                                                   nativeauthority.Scope
	Endpoint                                                fabric.EndpointRef
	DescriptorRevision                                      fabric.Revision
	BindingID                                               string
	RootPID                                                 int
	StartIdentity, Nonce, NativeGeneration, NativeSessionID string
}
type HostedPeer struct {
	Process    localpeer.ProcessSnapshot
	Activation HostedActivation
	Root       registry.AuthorityIdentity
}

// Private bootstrap witnesses contain original activation secrets. They must
// never become descriptors, network envelopes, events, or persisted assertions.
func (HostedActivation) MarshalJSON() ([]byte, error) { return nil, denied() }
func (*HostedActivation) UnmarshalJSON([]byte) error  { return denied() }
func (HostedPeer) MarshalJSON() ([]byte, error)       { return nil, denied() }
func (*HostedPeer) UnmarshalJSON([]byte) error        { return denied() }

type HostedValidator func(context.Context, HostedPeer) (fabric.Principal, error)
type HostedFactsProvider func(context.Context, HostedPeer) (*HostedCallerAuthority, error)

// HostedCallerAuthority is an immutable private current-root witness. It is
// not a native ownership/adoption proof, wire assertion or operator capability.
type HostedCallerAuthority struct {
	root      registry.AuthorityIdentity
	principal fabric.Principal
	scope     registry.DescriptorBatchScope
	profile   registry.AuthorityRecord
	digest    [32]byte
}

func (*HostedCallerAuthority) MarshalJSON() ([]byte, error) { return nil, denied() }
func (*HostedCallerAuthority) UnmarshalJSON([]byte) error   { return denied() }
func (a *HostedCallerAuthority) PrincipalView() fabric.Principal {
	if a == nil {
		return fabric.Principal{}
	}
	return a.principal
}
func (a *HostedCallerAuthority) Digest() [32]byte {
	if a == nil {
		return [32]byte{}
	}
	return a.digest
}

// NewHostedCallerAuthority accepts only the signed actual retained profile,
// after trusted composition has checked its original registry/private IPC.
// Binding to an actual kernel session still occurs separately in BindHosted.
func NewHostedCallerAuthority(root registry.AuthorityIdentity, principal fabric.Principal, scope registry.DescriptorBatchScope, profile registry.AuthorityRecord) (*HostedCallerAuthority, error) {
	raw, _ := json.Marshal(scope)
	h := sha256.Sum256(raw)
	expected := registry.AuthorityKey{Kind: registry.AuthorityNativeCheckpoint, ID: "hosted/profile/" + hex.EncodeToString(h[:])}
	if principal.Ref != scope.Endpoint.String() || principal.Issuer != root.Namespace || principal == root.Owner || !fabric.ValidNamespacedName(principal.Kind) || scope.Endpoint.IsOffer() || scope.Endpoint.Domain() != root.Namespace || scope.ExpectedEndpointRevision == "" || scope.BindingID == "" || scope.ExpectedProjectionRevision != 0 || profile.Key != expected || profile.Retired || registry.VerifyAuthorityRecord(root, profile) != nil {
		return nil, denied()
	}
	root.PublicKey = append([]byte(nil), root.PublicKey...)
	profile.Value = append([]byte(nil), profile.Value...)
	profile.Signature = append([]byte(nil), profile.Signature...)
	encoded, _ := json.Marshal(profile)
	return &HostedCallerAuthority{root, principal, scope, profile, sha256.Sum256(encoded)}, nil
}
func (a *HostedCallerAuthority) VerifyTx(tx *registry.AuthorityTx) error {
	if a == nil || tx == nil || a.digest == ([32]byte{}) {
		return denied()
	}
	if e := tx.VerifyCurrentActorBinding(a.scope.Endpoint, a.scope.ExpectedEndpointRevision, a.scope.BindingID); e != nil {
		return e
	}
	row, e := tx.Get(a.profile.Key)
	if e != nil || row.Retired || row.Revision != a.profile.Revision || registry.VerifyAuthorityRecord(a.root, row) != nil {
		return denied()
	}
	raw, _ := json.Marshal(row)
	if sha256.Sum256(raw) != a.digest {
		return denied()
	}
	return nil
}

func (a *Authority) BindHosted(ctx context.Context, conn *net.UnixConn, activation HostedActivation) (*Session, error) {
	cloud, ok := activation.Scope.Cloud()
	if a == nil || ctx == nil || conn == nil || ctx.Err() != nil || !ok || cloud.Validate() != nil || activation.Endpoint.IsOffer() || activation.Endpoint.Domain() != a.config.Root.Namespace || activation.DescriptorRevision == "" || activation.BindingID == "" || activation.RootPID <= 0 || !text(activation.StartIdentity, 64) || !text(activation.Nonce, 512) || !text(activation.NativeGeneration, 256) || !text(activation.NativeSessionID, 4096) || a.config.HostedValidator == nil || a.config.HostedFacts == nil || a.config.OwnerValidator == nil {
		return nil, denied()
	}
	checked, cancel := context.WithTimeout(ctx, a.config.CheckTimeout)
	defer cancel()
	process, e := peer(checked, conn, a.config.SocketPath)
	if e != nil {
		return nil, denied()
	}
	session := &Session{authority: a, conn: conn, process: process, hosted: &activation, pending: map[*proof]time.Time{}}
	principal, e := session.verify(checked)
	if e != nil {
		return nil, e
	}
	session.principal = principal
	return session, nil
}
func (s *Session) verifyHosted(ctx context.Context, current localpeer.ProcessSnapshot) (fabric.Principal, error) {
	activation := *s.hosted
	if localpeer.VerifyOwned(s.conn, activation.RootPID, activation.StartIdentity) != nil {
		return fabric.Principal{}, denied()
	}
	root := s.authority.config.Root
	root.PublicKey = append([]byte(nil), root.PublicKey...)
	principal, e := s.authority.config.HostedValidator(ctx, HostedPeer{current, activation, root})
	if e != nil || principal.Ref != activation.Endpoint.String() || principal.Issuer != root.Namespace || !fabric.ValidNamespacedName(principal.Kind) || principal == root.Owner {
		return fabric.Principal{}, denied()
	}
	if localpeer.VerifyOwned(s.conn, activation.RootPID, activation.StartIdentity) != nil {
		return fabric.Principal{}, denied()
	}
	return principal, nil
}
