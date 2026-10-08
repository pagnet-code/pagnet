// Package fabricnode (part of the installed federation product).
//
// FederationLinks is the retained, owner-guarded per-channel link registry.
// Each link is an UNSEALED plain-CAS record (decision D7): it holds only public
// values — the pinned remote authority, the remote's public exchange key and
// revision, and the opaque channel binding — plus a revocation flag. It is the
// exact set of fields a per-link runtime composes a federation.Config from. The
// secret (the local exchange private key) lives in FederationExchangeKeys, not
// here, so a link record is safe to persist unsealed.
package fabricnode

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

const linkFormat = 1

// FederationLink is the retained per-channel federation link. RemoteNamespace/
// RemoteStoreID identify the pinned peer; the remote's authority and exchange
// key come from the live pin at composition time (never a stale snapshot).
// Channel is opaque routing only.
type FederationLink struct {
	Format          int                       `json:"format"`
	RemoteNamespace string                    `json:"remoteNamespace"`
	RemoteStoreID   string                    `json:"remoteStoreId"`
	Channel         federation.ChannelBinding `json:"channel"`
	SourceRole      bool                      `json:"sourceRole"`
	CreatedAt       time.Time                 `json:"createdAt"`
	Revoked         bool                      `json:"revoked"`
}

// FederationLinks is the retained link registry over the native authority store.
type FederationLinks struct {
	store    *registry.Store
	root     registry.AuthorityIdentity
	owner    func(context.Context) (fabric.ExecutionContext, error)
	operator LocalOperator
}

// linkKey addresses one link by its 32-byte channel id (64 lowercase hex).
func linkKey(channelID [32]byte) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityFederationPeer, ID: "link." + hex.EncodeToString(channelID[:])}
}
func linkScope() registry.AuthorityScope {
	return registry.AuthorityScope{MaxOperations: 4, Timeout: time.Second}
}

// NewFederationLinks composes the link registry over the installation's actual
// store, operator and identity. A missing link is not an error: the first
// declaration creates it.
func NewFederationLinks(installation *localinstallation.Installation) (*FederationLinks, error) {
	if installation == nil || installation.Store == nil {
		return nil, localDenied()
	}
	return &FederationLinks{
		store:    installation.Store,
		root:     installation.Store.AuthorityIdentity(),
		owner:    installation.Operator,
		operator: installation,
	}, nil
}

func (l *FederationLinks) current(ctx context.Context, c fabric.ExecutionContext, next func(context.Context) error) error {
	if l == nil || ctx == nil || c.VerifyAuthenticated(l.root.Namespace) != nil || c.PrincipalView() != l.root.Owner {
		return localDenied()
	}
	root, e := l.store.CurrentAuthorityIdentity(ctx)
	if e != nil || root.Namespace != l.root.Namespace || root.StoreID != l.root.StoreID || root.Owner != l.root.Owner || root.KeyRevision != l.root.KeyRevision || !bytes.Equal(root.PublicKey, l.root.PublicKey) {
		return localDenied()
	}
	return guardedBoundary(ctx, func(ctx context.Context, n func(context.Context) error) error {
		return l.operator.WithCurrentOperator(ctx, c, n)
	}, next)
}

func (l *FederationLinks) decodeRow(row registry.AuthorityRecord, out *FederationLink) error {
	if registry.VerifyAuthorityRecord(l.root, row) != nil {
		return localDenied()
	}
	if fabric.DecodeJSONWithLimits(row.Value, out, fabric.WireLimits{MaxBytes: 64 << 10, MaxDepth: 8, MaxMembers: 512}) != nil || out.Format != linkFormat {
		return localDenied()
	}
	return nil
}

// Get returns the link for the channel id and the retained record's revision
// (the CAS base a later Retire needs). A missing or retired link is
// not-found (found=false), not an error.
func (l *FederationLinks) Get(ctx context.Context, owner fabric.ExecutionContext, channelID [32]byte) (FederationLink, uint64, bool, error) {
	var link FederationLink
	var revision uint64
	var found bool
	if l == nil {
		return link, 0, false, localDenied()
	}
	e := l.current(ctx, owner, func(ctx context.Context) error {
		return l.store.WithNativeAuthority(ctx, owner, linkScope(), func(tx *registry.AuthorityTx) error {
			row, e := tx.Get(linkKey(channelID))
			if e != nil {
				var missing *fabric.Error
				if errors.As(e, &missing) && missing.Code == fabric.CodeNotFound {
					return nil
				}
				return e
			}
			if row.Retired {
				return nil
			}
			if e := l.decodeRow(row, &link); e != nil {
				return e
			}
			revision = row.Revision
			found = true
			return nil
		})
	})
	return link, revision, found, e
}

// validate rejects a link that could never be composed: a self-target, a
// malformed remote identity (namespace/store-id), a zero channel id, or
// identical receiver routes (the serving boundary requires distinct routes).
// The remote's authority + exchange key are verified against the live pin at
// composition time, so the link itself only carries routing + peer identity.
func (l *FederationLinks) validate(link FederationLink) error {
	if link.RemoteNamespace == l.root.Namespace {
		return fabric.NewError(fabric.CodeInvalidInput, "A federation link cannot target this node")
	}
	if len(link.RemoteNamespace) != 54 || len(link.RemoteStoreID) != 64 || link.Channel.ID == ([32]byte{}) || link.Channel.SourceRoute == ([32]byte{}) || link.Channel.DestinationRoute == ([32]byte{}) || link.Channel.SourceRoute == link.Channel.DestinationRoute || link.Revoked {
		return localDenied()
	}
	return nil
}

// Put declares/updates the link with FULL CAS at the caller-supplied ledger
// base. The caller composes and validates the link (pinned remote, opaque
// channel, non-self, non-revoked); the retained record is stored unsealed.
// A re-declaration keeps the original CreatedAt. It returns the committed
// record and its ledger revision.
func (l *FederationLinks) Put(ctx context.Context, owner fabric.ExecutionContext, expectedLedgerRevision uint64, link FederationLink) (FederationLink, uint64, error) {
	if l == nil {
		return FederationLink{}, 0, localDenied()
	}
	commit := link
	commit.Format = linkFormat
	commit.Revoked = false
	if e := l.validate(commit); e != nil {
		return FederationLink{}, 0, e
	}
	var committed FederationLink
	var revision uint64
	e := l.current(ctx, owner, func(ctx context.Context) error {
		return l.store.WithNativeAuthority(ctx, owner, linkScope(), func(tx *registry.AuthorityTx) error {
			if row, e := tx.Get(linkKey(commit.Channel.ID)); e == nil {
				if !row.Retired {
					var prior FederationLink
					if e := l.decodeRow(row, &prior); e != nil {
						return e
					}
					if commit.CreatedAt.IsZero() {
						commit.CreatedAt = prior.CreatedAt
					}
				}
			} else {
				var missing *fabric.Error
				if !errors.As(e, &missing) || missing.Code != fabric.CodeNotFound {
					return e
				}
			}
			if commit.CreatedAt.IsZero() {
				commit.CreatedAt = time.Now().UTC()
			}
			raw, e := json.Marshal(commit)
			if e != nil {
				return e
			}
			defer clear(raw)
			row, e := tx.CAS(linkKey(commit.Channel.ID), expectedLedgerRevision, raw, false)
			if e != nil {
				return e
			}
			committed = commit
			revision = row.Revision
			return nil
		})
	})
	return committed, revision, e
}

// Retire revokes the link by CAS-retiring its record at the caller-supplied
// ledger base. A missing link is CodeNotFound; a stale base conflicts.
func (l *FederationLinks) Retire(ctx context.Context, owner fabric.ExecutionContext, expectedLedgerRevision uint64, channelID [32]byte) error {
	if l == nil {
		return localDenied()
	}
	return l.current(ctx, owner, func(ctx context.Context) error {
		return l.store.WithNativeAuthority(ctx, owner, linkScope(), func(tx *registry.AuthorityTx) error {
			row, e := tx.Get(linkKey(channelID))
			if e != nil {
				var missing *fabric.Error
				if errors.As(e, &missing) && missing.Code == fabric.CodeNotFound {
					return fabric.NewError(fabric.CodeNotFound, "Federation link absent")
				}
				return e
			}
			if row.Retired || row.Revision != expectedLedgerRevision {
				return fabric.NewError(fabric.CodeStaleReference, "Federation link revision conflict")
			}
			var link FederationLink
			if e := l.decodeRow(row, &link); e != nil {
				return e
			}
			link.Revoked = true
			raw, _ := json.Marshal(link)
			_, e = tx.CAS(linkKey(channelID), expectedLedgerRevision, raw, true)
			return e
		})
	})
}
