//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

// directChannelConsentPreview is an explicit owner read of one retained public
// issue. It is deliberately disconnected from automatic attachment and exposes
// neither credential material nor a consent mutation or dispatch capability.
type directChannelConsentPreview struct {
	captured ManagedEndpointPrepareScope
	store    *directChannelConsentStore
	key      directChannelConsentKey
	issue    [sha256.Size]byte
	admit    func(context.Context) (*DirectEndpointSubscription, error)
	observe  func(*DirectEndpointSubscription) (directEndpointReconcileObserver, error)
}

// Revision and Enabled report persisted selector state. Eligibility for the
// observed terms requires separate exact-binding validation.
type directChannelConsentPreviewSummary struct {
	Selector                               directChannelConsentKey
	LocalPrincipal, PeerPrincipal, GrantID string
	GrantGeneration                        int64
	AuthorizationDigest, ExpiresAt         string
	Budget                                 transport.DirectChannelBudgetV2
	Limits                                 transport.DirectChannelLimitsV2
	Revision                               int64
	Enabled                                bool
	Fingerprint                            string
}

func newDirectSourceChannelConsentPreview(d *Daemon, captured ManagedEndpointPrepareScope, store *directChannelConsentStore, issue transport.DirectManagedSourceCredentialIssueV2) (*directChannelConsentPreview, error) {
	return newDirectSourceChannelConsentPreviewWithReader(d, captured, store, issue, nil)
}

func newDirectSourceChannelConsentPreviewWithReader(d *Daemon, captured ManagedEndpointPrepareScope, store *directChannelConsentStore, issue transport.DirectManagedSourceCredentialIssueV2, reader directEndpointReconcileReader) (*directChannelConsentPreview, error) {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectChannelConsent
	}
	owned, err := transport.DecodeDirectManagedSourceCredentialIssueV2(raw)
	if err != nil {
		return nil, errDirectChannelConsent
	}
	subject := owned.PoP.Prepare.Subject
	p, err := newDirectChannelConsentPreview(d, captured, store, owned.PoP.ACK.Reservation.ServerURL, "S", string(subject.DirectIntentID), string(subject.PrincipalID), raw)
	if err != nil {
		return nil, err
	}
	p.admit = func(ctx context.Context) (*DirectEndpointSubscription, error) {
		return d.admitDirectManagedSourceEndpointV2(ctx, p.captured, owned)
	}
	p.observe = func(s *DirectEndpointSubscription) (directEndpointReconcileObserver, error) {
		return newDirectSourceReconcileObserverWithReader(d, p.captured, s, owned, reader, time.Now)
	}
	return p, nil
}

func newDirectTargetChannelConsentPreview(d *Daemon, captured ManagedEndpointPrepareScope, store *directChannelConsentStore, issue transport.ManagedDirectCredentialIssue) (*directChannelConsentPreview, error) {
	return newDirectTargetChannelConsentPreviewWithReader(d, captured, store, issue, nil)
}

func newDirectTargetChannelConsentPreviewWithReader(d *Daemon, captured ManagedEndpointPrepareScope, store *directChannelConsentStore, issue transport.ManagedDirectCredentialIssue, reader directEndpointReconcileReader) (*directChannelConsentPreview, error) {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectChannelConsent
	}
	owned, err := transport.DecodeManagedDirectCredentialIssue(raw)
	if err != nil {
		return nil, errDirectChannelConsent
	}
	subject := owned.PoP.Prepare.Subject
	p, err := newDirectChannelConsentPreview(d, captured, store, owned.PoP.ACK.Reservation.ServerURL, "P", string(subject.DirectIntentID), string(subject.PrincipalID), raw)
	if err != nil {
		return nil, err
	}
	p.admit = func(ctx context.Context) (*DirectEndpointSubscription, error) {
		return d.admitManagedTargetEndpoint(ctx, p.captured, owned)
	}
	p.observe = func(s *DirectEndpointSubscription) (directEndpointReconcileObserver, error) {
		return newDirectTargetReconcileObserverWithReader(d, p.captured, s, owned, reader, time.Now)
	}
	return p, nil
}

func newDirectChannelConsentPreview(d *Daemon, captured ManagedEndpointPrepareScope, store *directChannelConsentStore, server, role, intent, principal string, issue []byte) (*directChannelConsentPreview, error) {
	if d == nil || store == nil || store.registry == nil || d.nativeRegistry != store.registry || captured.Socket == nil || captured.Connection == nil {
		return nil, errDirectChannelConsent
	}
	raw, err := json.Marshal(captured.Session)
	var session transport.HostSessionPayload
	if err != nil || json.Unmarshal(raw, &session) != nil {
		return nil, errDirectChannelConsent
	}
	captured.Session = session
	key := directChannelConsentKey{Server: server, Tenant: session.TenantID, Account: session.AccountID, Host: session.HostID, Intent: intent, Role: role, Principal: principal}
	if !store.validKey(key) || !consentKeyValid(key) {
		return nil, errDirectChannelConsent
	}
	return &directChannelConsentPreview{captured: captured, store: store, key: key, issue: sha256.Sum256(issue)}, nil
}

// Preview works with missing or disabled consent: the explicit owner action is
// allowed to inspect terms before opting in. Every admission is temporary, even
// on success. The automatic controller retains its enabled-revision HTTP gate.
func (p *directChannelConsentPreview) Preview(ctx context.Context) (result directChannelConsentPreviewSummary, err error) {
	var sub *DirectEndpointSubscription
	defer func() {
		if recover() != nil {
			err = errDirectChannelConsent
		}
		if sub != nil {
			sub.Remove()
		}
		if err != nil {
			result, err = directChannelConsentPreviewSummary{}, errDirectChannelConsent
		}
	}()
	if p == nil || ctx == nil || ctx.Err() != nil {
		return result, errDirectChannelConsent
	}
	sub, err = p.admit(ctx)
	if err != nil || sub == nil {
		return result, errDirectChannelConsent
	}
	observe, err := p.observe(sub)
	if err != nil {
		return result, err
	}
	observed, err := observe(ctx)
	if err != nil {
		return result, err
	}
	record, err := p.store.Get(ctx, p.key)
	if err != nil || ctx.Err() != nil || directReconcileBindingCurrentContext(ctx, sub) != nil {
		return result, errDirectChannelConsent
	}
	binding, err := deriveDirectChannelConsentBinding(sub, p.captured, p.store.installation, observed.Binding, time.Now())
	if err != nil || binding.Key != p.key {
		return result, errDirectChannelConsent
	}
	// A fixed, map-free JSON representation binds the complete exact terms to
	// the authenticated descriptor, owned scope, installation and retained issue.
	// Revisions are informational and do not change a terms fingerprint.
	fingerprint, err := p.fingerprint(binding, observed.Binding.DescriptorHash)
	if err != nil {
		return result, err
	}
	return directChannelConsentPreviewSummary{Selector: binding.Key, LocalPrincipal: binding.Key.Principal, PeerPrincipal: binding.PeerPrincipal, GrantID: binding.GrantID, GrantGeneration: binding.GrantGeneration, AuthorizationDigest: binding.AuthorizationSnapshotDigest, ExpiresAt: binding.ExpiresAt, Budget: observed.Binding.Descriptor.Budget, Limits: observed.Binding.Descriptor.Limits, Revision: record.Revision, Enabled: record.Enabled, Fingerprint: fingerprint}, nil
}

func (p *directChannelConsentPreview) fingerprint(binding directChannelConsentBinding, descriptorHash [sha256.Size]byte) (string, error) {
	raw, err := json.Marshal(struct {
		Binding        directChannelConsentBinding
		DescriptorHash [sha256.Size]byte
		Session        transport.HostSessionPayload
		Installation   string
		Issue          [sha256.Size]byte
	}{binding, descriptorHash, p.captured.Session, p.store.installation, p.issue})
	if err != nil {
		return "", errDirectChannelConsent
	}
	fingerprint := sha256.Sum256(append([]byte("pagnet/direct-channel-consent-preview/v1\x00"), raw...))
	return hex.EncodeToString(fingerprint[:]), nil
}
