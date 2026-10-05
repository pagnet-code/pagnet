package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/node/continuations"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

// ExtensionNotifications publishes protected, recipient-specific receipts.
// The continuation SQLite commit remains the secret/revision authority; Root
// publication is a distinct phase, never a cross-store atomicity claim.
type ExtensionNotifications struct {
	installation *localinstallation.Installation
	store        *continuation.Store
	root         registry.AuthorityIdentity
	boundary     *LocalBoundary
}

func newExtensionNotifications(ctx context.Context, i *localinstallation.Installation, s *continuation.Store, b *LocalBoundary) (*ExtensionNotifications, error) {
	if ctx == nil || i == nil || i.Store == nil || i.Keys == nil || s == nil || b == nil || b.store != i.Store {
		return nil, localDenied()
	}
	root, e := i.Store.CurrentAuthorityIdentity(ctx)
	if e != nil {
		return nil, e
	}
	return &ExtensionNotifications{installation: i, store: s, root: root, boundary: b}, nil
}

type extensionNotificationPin struct {
	Format        uint32
	ID            string
	Recipient     fabric.Principal
	Revision      uint64
	Expires       string
	CapabilitySHA string
}

func notificationPinKey(id string, p fabric.Principal) registry.AuthorityKey {
	b, _ := json.Marshal(struct {
		ID        string
		Recipient fabric.Principal
	}{id, p})
	h := sha256.Sum256(append([]byte("pagnet.deferred-notification.recipient.v1\x00"), b...))
	return registry.AuthorityKey{Kind: registry.AuthorityDeferredNotification, ID: hex.EncodeToString(h[:])}
}
func (n *ExtensionNotifications) aad(k registry.AuthorityKey) []byte {
	r := n.root
	b, _ := json.Marshal(struct {
		Purpose, Domain, Store, ID string
		Key                        any
	}{"pagnet.deferred-notification.v1", r.Namespace, r.StoreID, k.ID, n.installation.Keys.Reference()})
	return b
}
func notificationPin(d continuation.PrivateDelivery) extensionNotificationPin {
	h := sha256.Sum256([]byte(d.Capability().Token()))
	return extensionNotificationPin{1, d.ID, d.Recipient, d.Revision, d.ExpiresAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), hex.EncodeToString(h[:])}
}
func (n *ExtensionNotifications) decode(k registry.AuthorityKey, r registry.AuthorityRecord) (extensionNotificationPin, error) {
	var p extensionNotificationPin
	root := n.root
	if r.Key != k || r.Retired || registry.VerifyAuthorityRecord(root, r) != nil {
		return p, localDenied()
	}
	var box extensionCipher
	if len(r.Value) > 32768 || fabric.DecodeJSONWithLimits(r.Value, &box, fabric.WireLimits{MaxBytes: 32768, MaxDepth: 4, MaxMembers: 16}) != nil {
		return p, localDenied()
	}
	b, e := n.installation.Keys.Open(n.aad(k), box.Cipher)
	if e != nil {
		return p, e
	}
	defer clear(b)
	if fabric.DecodeJSONWithLimits(b, &p, fabric.WireLimits{MaxBytes: 16384, MaxDepth: 8, MaxMembers: 32}) != nil || p.Format != 1 || notificationPinKey(p.ID, p.Recipient) != k {
		return p, localDenied()
	}
	return p, nil
}

// Publish accepts only a genuinely committed current private outbox item.
// Failure leaves its secret retrievable from SQLite for explicit recovery.
func (n *ExtensionNotifications) Publish(ctx context.Context, notice continuations.PrivateNotification) error {
	if n == nil || n.installation == nil || n.store == nil || len(notice.Recipients) == 0 || len(notice.Recipients) > 64 {
		return localDenied()
	}
	for _, recipient := range notice.Recipients {
		d, e := n.store.VerifyPrivatePublication(ctx, notice.Capability.Token(), notice.Revision, recipient)
		if e != nil || d.ID != notice.ID || !d.ExpiresAt.Equal(notice.ExpiresAt) {
			return localDenied()
		}
		p := notificationPin(d)
		k := notificationPinKey(d.ID, recipient)
		raw, _ := json.Marshal(p)
		cipher, e := n.installation.Keys.Seal(n.aad(k), raw)
		clear(raw)
		if e != nil {
			return e
		}
		value, _ := json.Marshal(extensionCipher{cipher})
		owner, e := n.installation.Operator(ctx)
		if e != nil {
			return e
		}
		e = n.installation.WithCurrentOperator(ctx, owner, func(c context.Context) error {
			return n.installation.Store.WithNativeAuthority(c, owner, registry.AuthorityScope{MaxOperations: 3}, func(tx *registry.AuthorityTx) error {
				var expected uint64
				r, e := tx.Get(k)
				if e == nil {
					old, e := n.decode(k, r)
					if e != nil {
						return e
					}
					if old == p {
						return nil
					}
					if old.Revision >= p.Revision {
						return localDenied()
					}
					expected = r.Revision
				} else {
					var f *fabric.Error
					if !errors.As(e, &f) || f.Code != fabric.CodeNotFound {
						return e
					}
				}
				_, e = tx.CAS(k, expected, value, false)
				return e
			})
		})
		if e != nil {
			return e
		}
	}
	return nil
}

// Delivery requires the actual current full recipient context and compares the
// signed Root pin to the current SQLite revision. It never lists capabilities.
func (n *ExtensionNotifications) delivery(ctx context.Context, recipient fabric.ExecutionContext, id string, facts fabricauth.CurrentCallerFacts) (continuation.PrivateDelivery, error) {
	var empty continuation.PrivateDelivery
	if n == nil {
		return empty, localDenied()
	}
	d, e := n.store.PrivateNotification(ctx, recipient, id)
	if e != nil {
		return empty, e
	}
	owner, e := n.installation.Operator(ctx)
	if e != nil {
		return empty, e
	}
	k := notificationPinKey(id, recipient.PrincipalView())
	e = n.installation.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 1}, func(tx *registry.AuthorityTx) error {
		n.boundary.mu.RLock()
		sessions := n.boundary.sessions
		n.boundary.mu.RUnlock()
		if sessions == nil || !sessions.AssociationOpen(recipient) {
			return localDenied()
		}
		if facts.Managed != nil {
			if e := tx.VerifyCurrentNativeCaller(facts.Managed.Authority); e != nil {
				return e
			}
		} else if facts.Principal != n.root.Owner {
			return localDenied()
		}
		r, e := tx.Get(k)
		if e != nil {
			return e
		}
		p, e := n.decode(k, r)
		if e != nil || p != notificationPin(d) {
			return localDenied()
		}
		return nil
	})
	if e != nil {
		return empty, e
	}
	// Revalidate after Root read, without claiming a transaction spanning stores.
	if _, e = n.store.VerifyPrivatePublication(ctx, d.Capability().Token(), d.Revision, d.Recipient); e != nil {
		return empty, e
	}
	return d, nil
}

func (n *ExtensionNotifications) Delivery(ctx context.Context, recipient fabric.ExecutionContext, id string) (continuation.PrivateDelivery, error) {
	var delivery continuation.PrivateDelivery
	if n == nil || n.boundary == nil {
		return delivery, localDenied()
	}
	e := n.boundary.callerFacts(ctx, recipient, func(c context.Context, f fabricauth.CurrentCallerFacts) error {
		var err error
		delivery, err = n.delivery(c, recipient, id, f)
		return err
	})
	if e != nil {
		return continuation.PrivateDelivery{}, e
	}
	return delivery, nil
}
