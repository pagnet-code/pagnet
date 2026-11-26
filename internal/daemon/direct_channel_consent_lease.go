//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

type directChannelConsentLeaseKey struct {
	installation string
	key          directChannelConsentKey
}

// This dormant process-local index is shared by stores using the same registry.
// It never authorizes dispatch or coordinates independent registry processes.
// registry.mu precedes the subscription leaf lock; removal has no callbacks.
type directChannelConsentLeases map[directChannelConsentLeaseKey]map[*DirectEndpointSubscription]int64

func (leases directChannelConsentLeases) revoke(key directChannelConsentLeaseKey) {
	for sub := range leases[key] {
		sub.Remove()
	}
	delete(leases, key)
}

func (leases directChannelConsentLeases) revokeAll() {
	for key := range leases {
		leases.revoke(key)
	}
}

// registerDirectChannelConsentLease has no production caller. It associates an
// exact live admission with an exact durable consent revision, without attaching
// a transport or scheduling work. The daemon and store must share the registry.
func (d *Daemon) registerDirectChannelConsentLease(ctx context.Context, store *directChannelConsentStore, key directChannelConsentKey, revision int64, sub *DirectEndpointSubscription, captured ManagedEndpointPrepareScope, evidence directEndpointReconcileBinding) error {
	if ctx == nil || d == nil || store == nil || store.registry == nil || d.nativeRegistry != store.registry || sub == nil || sub.owner != &d.directSubscriptions || !store.validKey(key) || !consentKeyValid(key) {
		return errDirectChannelConsent
	}
	// Own caller-provided slices before retaining or validating any input.
	raw, err := json.Marshal(captured.Session)
	var session transport.HostSessionPayload
	if err != nil || json.Unmarshal(raw, &session) != nil {
		return errDirectChannelConsent
	}
	captured.Session = session
	evidence.DescriptorBytes = append([]byte(nil), evidence.DescriptorBytes...)
	leaseKey := directChannelConsentLeaseKey{store.installation, key}
	registered := false
	return store.lockedCompletion(ctx, func(c *sql.Conn) error {
		rows, err := store.rows(ctx, c)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Key != key {
				continue
			}
			if err := validateDirectChannelConsentEligibility(row.directChannelConsentRecord, revision, sub, captured, store.installation, evidence, time.Now()); err != nil {
				return err
			}
			if !sub.Valid() {
				return errDirectChannelConsent
			}
			leases := store.registry.directConsentLeases
			if leases == nil {
				leases = make(directChannelConsentLeases)
				store.registry.directConsentLeases = leases
			}
			// Retired handles need no registry callback from their leaf lock.
			for k, entries := range leases {
				for old := range entries {
					select {
					case <-old.Done():
						delete(entries, old)
					default:
					}
				}
				if len(entries) == 0 {
					delete(leases, k)
				}
			}
			if leases[leaseKey] == nil {
				leases[leaseKey] = make(map[*DirectEndpointSubscription]int64)
			}
			leases[leaseKey][sub] = revision
			registered = true
			return nil
		}
		return errDirectChannelConsent
	}, func(err error) {
		if err != nil && registered {
			sub.Remove()
			delete(store.registry.directConsentLeases[leaseKey], sub)
		}
	})
}
